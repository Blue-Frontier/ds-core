const { LRUCache } = require('lru-cache')
const log = require('../../../../utils/util.log.server')
const dnsUtil = require('../../../dns/index')
const echUtil = require('./ech')
const { toHostMap, createEchDomainMap, isEchDomain } = require('./domain')
const { connectTls } = require('./tlsSocket')
const ProxyHttpsAgent = require('../ProxyHttpsAgent')

/** ECH被服务器拒绝（含public_name认证失败）后，该域名多久内不再尝试ECH */
const ECH_REJECT_TTL = 10 * 60 * 1000
/** 其它ECH失败（DNS查询失败、握手失败等）后，该域名多久内不再尝试ECH */
const ECH_FAILURE_TTL = 60 * 1000
/** 负缓存大小 */
const FALLBACK_CACHE_SIZE = 512
/** Node的https客户端只支持HTTP/1.1 */
const DEFAULT_ALPN_PROTOCOLS = ['http/1.1']
/** ECH握手超时时间 */
const ECH_HANDSHAKE_TIMEOUT = 15 * 1000

function makeError (code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

/**
 * 上游使用 ECH（RFC 9849）的 https.Agent
 *
 * 仅对配置中 `server.dns.ech.domains` 指定的域名生效：
 * 通过DNS的HTTPS(65)记录获取 ech 参数，然后用纯JS实现的 TLS 1.3 + ECH 客户端完成握手，
 * 握手成功后把连接包装成 net.Socket 风格的 Duplex 交给 Node 的 http 客户端收发 HTTP/1.1 报文。
 *
 * 任何一步失败（DNS未下发ech、握手失败、服务器拒绝ECH）都会自动回退到原生 TLS，保证请求不受影响。
 */
class EchHttpsAgent extends ProxyHttpsAgent {
  constructor (options = {}) {
    super(options)
    this.dnsConfig = options.dnsConfig || null
    this.echOptions = options.ech || {}
    this.echDomains = createEchDomainMap({ domains: options.hostMap })
    this.alpnProtocols = options.alpnProtocols || DEFAULT_ALPN_PROTOCOLS
    this.unusableCache = new LRUCache({ max: FALLBACK_CACHE_SIZE })
    this.stat = options.stat || { request: 0, ech: 0, reject: 0, error: 0, fallback: 0 }
    // 原生agent：ECH不可用时完全交给它建立连接，保证与开启ECH之前的TLS行为一致
    this.nativeAgent = options.nativeAgent || null
  }

  /**
   * 建立原生TLS连接（交给被包装的原生agent，保持TLS版本/证书校验等原有逻辑）
   */
  createNativeConnection (options, callback) {
    if (this.nativeAgent != null && this.nativeAgent !== this) {
      return this.nativeAgent.createConnection(options, callback)
    }
    return super.createConnection(options, callback)
  }

  /**
   * 该域名是否需要使用ECH
   */
  match (hostname) {
    return isEchDomain(this.echDomains, hostname)
  }

  /**
   * 该域名的ECH是否可用（是否处于负缓存有效期内）
   */
  isUsable (hostname) {
    const item = this.unusableCache.get(hostname)
    if (item == null) {
      return true
    }
    if (item.expireAt > Date.now()) {
      return false
    }
    this.unusableCache.delete(hostname)
    return true
  }

  markUnusable (hostname, ttl, reason) {
    this.unusableCache.set(hostname, {
      expireAt: Date.now() + ttl,
      reason,
    })
  }

  /**
   * 覆写 createConnection：
   * - 非目标域名 / ECH不可用：走原生TLS（同步返回socket）
   * - 目标域名：异步完成 ECH 握手后通过 callback 返回 socket；失败则回退原生TLS
   */
  createConnection (options, callback) {
    const hostname = options.servername || options.host
    if (!this.match(hostname) || !this.isUsable(hostname)) {
      return this.createNativeConnection(options, callback)
    }

    this.connectWithEch(options, hostname, Number.parseInt(options.port, 10) || 443)
      .then((socket) => {
        callback(null, socket)
      })
      .catch((error) => {
        log.warn(`[ECH] 使用ECH连接失败，回退原生TLS: ${hostname}, error: ${error.message}`)
        this.stat.fallback++
        let socket = null
        try {
          socket = this.createNativeConnection(options, callback)
        } catch (e) {
          callback(e)
          return
        }
        if (socket != null) {
          callback(null, socket)
        } else if (callback == null) {
          // 没有回调时无法异步返回socket，只能抛出
          throw error
        }
      })

    // 异步返回socket
    return undefined
  }

  /**
   * 获取该域名的ECH配置（由DNS的HTTPS记录下发）
   */
  async lookupEch (hostname) {
    return dnsUtil.lookupEch(this.dnsConfig, hostname)
  }

  /**
   * ECH握手：服务器返回 retry_configs 时，用新配置再试一次（RFC 9849 §6.1.6）
   */
  async connectWithEch (options, hostname, port) {
    let retryConfig = null
    let lastError = null
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        return await this.createEchSocket(options, hostname, port, retryConfig)
      } catch (e) {
        lastError = e
        retryConfig = null
        if (e.code === 'ECH_REJECTED' && e.retryConfigs != null) {
          retryConfig = echUtil.selectEchConfig(e.retryConfigs)
          if (retryConfig != null) {
            log.info(`[ECH] ${hostname} 服务器返回 retry_configs，使用新下发的ECH配置重试，public_name: ${retryConfig.publicName}`)
            continue
          }
        }
        break
      }
    }

    if (lastError != null) {
      if (lastError.code === 'ECH_REJECTED') {
        this.stat.reject++
        this.markUnusable(hostname, ECH_REJECT_TTL, 'rejected')
      } else if (lastError.code !== 'ECH_NO_CONFIG') {
        this.stat.error++
        this.markUnusable(hostname, ECH_FAILURE_TTL, lastError.message)
      }
    }
    throw lastError
  }

  async createEchSocket (options, hostname, port, retryConfig) {
    let echConfig = retryConfig
    let publicName = retryConfig == null ? null : retryConfig.publicName
    let dnsCost = 0

    if (echConfig == null) {
      const dnsStart = Date.now()
      const ech = await this.lookupEch(hostname)
      dnsCost = Date.now() - dnsStart
      if (ech == null || ech.config == null) {
        throw makeError('ECH_NO_CONFIG', `该域名未获取到可用的ECH配置: ${hostname}`)
      }
      echConfig = ech.config
      publicName = ech.publicName
    }

    this.stat.request++
    const start = Date.now()
    const { socket, info } = await connectTls({
      host: options.host || options.hostname || hostname,
      port,
      servername: hostname,
      alpnProtocols: this.alpnProtocols,
      echConfig,
      rejectUnauthorized: options.rejectUnauthorized !== false && this.echOptions.rejectUnauthorized !== false,
      ca: options.ca,
      lookup: options.lookup,
      family: options.family,
      localAddress: options.localAddress,
      timeout: this.echOptions.timeout || ECH_HANDSHAKE_TIMEOUT,
      connectTimeout: this.echOptions.connectTimeout,
    })

    this.stat.ech++
    const cost = Date.now() - start
    const dnsCostLabel = dnsCost > 0 ? `DNS: ${dnsCost} ms, 建连: ${cost} ms` : `建连: ${cost} ms`
    log.info(`[ECH] 上游TLS已使用ECH: ${hostname}:${port} ➜ public_name: ${publicName}, 版本: ${info.protocol}, 套件: ${info.cipherSuite}, ALPN: ${info.alpnProtocol}, 证书校验: ${info.authorized ? '通过' : info.authorizationError}, ${dnsCostLabel}`)
    return socket
  }
}

/**
 * 创建上游ECH agent工厂（配置未启用或未指定域名时返回null）
 *
 * 不自己维护agent选项，而是包装 mitmproxy 已有的 https agent：
 * 这样 keepAlive、超时、TLS版本、证书校验等全部沿用原有逻辑，ECH只接管目标域名的建连过程。
 *
 * @param {{dnsConfig: object, ech: object}} options
 */
function createEchAgentPair ({ dnsConfig, ech }) {
  const echOptions = ech || {}
  if (dnsConfig == null || echOptions.enabled === false || echOptions.use === false) {
    return null
  }

  const hostMap = toHostMap(echOptions.domains)
  if (Object.keys(hostMap).length === 0) {
    return null
  }

  const stat = { request: 0, ech: 0, reject: 0, error: 0, fallback: 0 }
  const wrappedAgents = new WeakMap()
  const echDomains = createEchDomainMap(echOptions)

  function wrap (baseAgent) {
    if (baseAgent == null || baseAgent === false) {
      return baseAgent
    }
    let agent = wrappedAgents.get(baseAgent)
    if (agent == null) {
      agent = new EchHttpsAgent({
        ...baseAgent.options,
        dnsConfig,
        ech: echOptions,
        hostMap,
        stat,
        nativeAgent: baseAgent,
      })
      if (baseAgent.unVerifySslAgent != null) {
        agent.unVerifySslAgent = wrap(baseAgent.unVerifySslAgent)
      }
      wrappedAgents.set(baseAgent, agent)
    }
    return agent
  }

  log.info(`[ECH] 已开启上游ECH: 指定域名 ${JSON.stringify(Object.keys(hostMap))}`)

  return {
    stat,
    isEnabled: true,
    wrap,
    match (hostname) {
      return isEchDomain(echDomains, hostname)
    },
  }
}

module.exports = {
  EchHttpsAgent,
  createEchAgentPair,
  ECH_REJECT_TTL,
  ECH_FAILURE_TTL,
}

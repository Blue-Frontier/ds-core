const { LRUCache } = require('lru-cache')
const log = require('../../../../utils/util.log.server')
const dnsUtil = require('../../../dns/index')
const echUtil = require('./ech')
const { toHostMap, createEchDomainMap, isEchDomain } = require('./domain')
const { connectTls } = require('./tlsSocket')
const { INIT_SOCKET } = require('agentkeepalive/lib/constants')
const ProxyHttpsAgent = require('../ProxyHttpsAgent')

/** ECH被服务器拒绝（含public_name认证失败）后，该域名多久内不再尝试ECH */
const ECH_REJECT_TTL = 10 * 60 * 1000
/**
 * 其它ECH失败（DNS查询失败、握手失败等）后，该「域名|IP」多久内不再尝试ECH
 *
 * 只按IP拉黑：同一个域名的其它IP依旧会尝试ECH（以前是按域名拉黑，一次握手失败就让整个域名
 * 60秒内完全不使用ECH，导致同一个域名的请求时而走ECH、时而不走）。
 */
const ECH_FAILURE_TTL = 60 * 1000
/** 负缓存大小 */
const FALLBACK_CACHE_SIZE = 512
/** Node的https客户端只支持HTTP/1.1 */
const DEFAULT_ALPN_PROTOCOLS = ['http/1.1']
/**
 * ECH握手超时时间
 *
 * 线上成功的ECH建连耗时（964次采样）：P50=0.7s、P90=6.7s、P95=9s。
 * 被丢弃的ECH握手（本网络会间歇性丢弃带ECH扩展的ClientHello）永远不会有响应，
 * 所以超时值就是一次丢包的代价：取8秒覆盖90%的正常握手，同时把失败代价比15秒减半。
 */
/** ECH握手超时时间 */
const ECH_HANDSHAKE_TIMEOUT = 15 * 1000
/** ECH建连（TCP）超时时间，默认与握手超时一致 */
const ECH_CONNECT_TIMEOUT = 8 * 1000
/**
 * ECH上游连接池的并发上限
 *
 * 一次并发几十个请求时，几十个ECH握手会同瞬间发往同一个anycast IP，本网络实测约有一半会被丢弃
 * （8秒握手超时）；这些超时又会被记成「该IP的ECH不可用」，负缓存很快覆盖全部IP，
 * 于是后续请求全部退化成原生TLS——而这些域名的原生TLS又被按SNI阻断，直接30秒超时（浏览器看到500）。
 * 限到浏览器同级别的并发（6-8）后，每批握手明显更容易成功，空闲连接也能被后面的请求复用。
 */
const DEFAULT_MAX_SOCKETS = 8
/**
 * ECH连接在连接池里的空闲回收时间
 *
 * 原agent用的是30秒（ds的 keepAliveTimeout），但ECH连接更容易被网络中间设备静默掐断：
 * 线上日志里出现过复用一个空闲连接时请求卡12秒、36秒才成功，并在日志里留下
 * 「代理请求成功但太慢, cost: 12148 ms > 8000 ms」的IP优选反馈。
 * 连接池里留得越久，复用到已失效连接的概率越大，所以ECH连接单独收短到5秒
 * （同一批并发请求依旧能复用，跨批次则重新握手，一次ECH握手P50只要0.7秒）。
 */
const ECH_FREE_SOCKET_TIMEOUT = 5 * 1000
/**
 * 每个域名记住多少个「解析到过的IP」
 *
 * 预设IP池/DNS轮换会给出多个候选IP，但下游lookup每次只给一个；一旦DNS缓存的当前IP是个
 * 在本域名上根本握不上手的坏IP（例如 104.16.100.215 在 cdn.ldstatic.com 上 0/8），
 * 重新解析也会一直把它拿回来，于是每个请求都要白等一次8秒握手超时，最后耗尽30秒建连预算返回500。
 * 记住解析到过的IP后，就能直接换到另一个已知可用IP继续尝试ECH。
 */
const MAX_IP_HISTORY = 8

function makeError (code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

/**
 * 去掉IPv6映射前缀（`::ffff:104.26.2.74` ➜ `104.26.2.74`），保证与DNS缓存中的IP写法一致
 */
function normalizeIp (ip) {
  if (typeof ip !== 'string') {
    return null
  }
  return ip.replace(/^::ffff:/i, '')
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
    // 域名 ➜ 解析到过的IP列表（最近使用的在前），用于坏IP时直接换一个已知IP
    this.hostIpHistory = new LRUCache({ max: FALLBACK_CACHE_SIZE })
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
   * 「域名|IP」形式的负缓存键（按IP拉黑时使用）
   */
  echPairKey (hostname, ip) {
    return ip == null ? hostname : `${hostname}|${ip}`
  }

  /**
   * 该域名（或该域名的指定IP）的ECH是否可用（是否处于负缓存有效期内）
   *
   * - 不带IP：只判断域名级负缓存（服务器拒绝ECH，通常是配置问题，换IP也没用）
   * - 带IP：域名级 + 该(域名,IP)级
   */
  isUsable (hostname, ip) {
    if (!this.isKeyUsable(hostname)) {
      return false
    }
    return ip == null || this.isKeyUsable(this.echPairKey(hostname, ip))
  }

  isKeyUsable (key) {
    const item = this.unusableCache.get(key)
    if (item == null) {
      return true
    }
    if (item.expireAt > Date.now()) {
      return false
    }
    this.unusableCache.delete(key)
    return true
  }

  markUnusable (hostname, ttl, reason) {
    this.unusableCache.set(hostname, {
      expireAt: Date.now() + ttl,
      reason,
    })
  }

  markUnusablePair (hostname, ip, ttl, reason) {
    this.markUnusable(this.echPairKey(hostname, ip), ttl, reason)
  }

  clearPair (hostname, ip) {
    this.unusableCache.delete(this.echPairKey(hostname, ip))
  }

  /**
   * 记住该域名解析到过的IP（最近使用的排在前面，最多 MAX_IP_HISTORY 个）
   */
  rememberIp (hostname, ip) {
    if (ip == null) {
      return
    }
    let list = this.hostIpHistory.get(hostname)
    if (list == null) {
      list = []
      this.hostIpHistory.set(hostname, list)
    }
    const index = list.indexOf(ip)
    if (index >= 0) {
      list.splice(index, 1)
    }
    list.unshift(ip)
    if (list.length > MAX_IP_HISTORY) {
      list.length = MAX_IP_HISTORY
    }
  }

  /**
   * 该域名解析到过的IP里，当前不在负缓存里的一个（没有则返回null）
   */
  pickUsableKnownIp (hostname) {
    const list = this.hostIpHistory.get(hostname)
    if (list == null) {
      return null
    }
    for (const ip of list) {
      if (this.isUsable(hostname, ip)) {
        return ip
      }
    }
    return null
  }

  /**
   * 把某个IP包装成lookup的回调参数（family按字面判断，IPv6才有冒号）
   */
  respondWithIp (callback, ip) {
    callback(null, ip, ip.includes(':') ? 6 : 4)
  }

  /**
   * 包装传给connectTls的lookup
   *
   * 目的：
   * 1. 捕获本次连接真实使用的IP（失败时用来只拉黑这个IP，并反馈给DNS做IP优选）
   * 2. 该(域名,IP)已知ECH不可用时，记一次失败让DNS缓存换一个IP、再重新解析一次继续尝试ECH
   *    （以前的实现直接放弃ECH改走原生TLS，于是同一个域名时而走ECH、时而不走）
   */
  createEchLookup (hostname, targetLookup) {
    const capture = { ip: null, allUnusable: false }
    if (typeof targetLookup !== 'function') {
      return { lookup: targetLookup, capture }
    }

    const pickIp = (address) => {
      if (Array.isArray(address)) {
        return address.length > 0 && address[0] != null ? normalizeIp(address[0].address) : null
      }
      return normalizeIp(address)
    }

    const lookup = (host, lookupOptions, callback) => {
      targetLookup(host, lookupOptions, (err, address, family) => {
        if (err != null) {
          callback(err)
          return
        }

        const ip = pickIp(address)
        if (ip != null) {
          this.rememberIp(hostname, ip)
        }
        if (ip == null || this.isUsable(hostname, ip)) {
          capture.ip = ip
          callback(null, address, family)
          return
        }

        // 该(域名,IP)已知ECH不可用：记为失败（DNS缓存会切换下一个IP）
        dnsUtil.countEchIp(this.dnsConfig, hostname, ip, true, 'ECH在该IP上不可用，切换IP重试')

        // 之前解析到过别的IP时直接换过去：DNS缓存有可能一直把同一个坏IP还回来
        const knownIp = this.pickUsableKnownIp(hostname)
        if (knownIp != null && knownIp !== ip) {
          log.info(`[ECH] ${hostname} 的IP ${ip} 已知ECH不可用，改用其它已知IP重试ECH: ${knownIp}`)
          capture.ip = knownIp
          this.respondWithIp(callback, knownIp)
          return
        }

        log.info(`[ECH] ${hostname} 的IP ${ip} 已知ECH不可用，重新解析以切换IP`)
        targetLookup(host, lookupOptions, (err2, address2, family2) => {
          if (err2 != null) {
            capture.ip = ip
            callback(null, address, family)
            return
          }
          const ip2 = pickIp(address2)
          this.rememberIp(hostname, ip2)
          if (ip2 == null) {
            capture.ip = ip
            callback(null, address, family)
            return
          }
          if (this.isUsable(hostname, ip2)) {
            capture.ip = ip2
            callback(null, address2, family2)
            return
          }

          // 能解析到的IP全都处于负缓存里：原生TLS在这些域名上通常更糟（按SNI阻断，必挂30秒），
          // 所以这里仍旧尝试ECH——挑「失败得最早」的那个IP（最可能已经恢复）并清掉它的负缓存，
          // 给它一次机会。绝不因为负缓存就把整个请求降级成原生TLS。
          const candidates = []
          const pushCandidate = (candidateIp, candidateAddress, candidateFamily) => {
            if (candidateIp == null || candidates.some(item => item.ip === candidateIp)) {
              return
            }
            candidates.push({ ip: candidateIp, address: candidateAddress, family: candidateFamily })
          }
          pushCandidate(ip2, address2, family2)
          pushCandidate(ip, address, family)
          for (const historyIp of this.hostIpHistory.get(hostname) || []) {
            pushCandidate(historyIp, historyIp, historyIp.includes(':') ? 6 : 4)
          }

          let index = 0
          let earliest = Number.MAX_SAFE_INTEGER
          for (let i = 0; i < candidates.length; i++) {
            const item = this.unusableCache.get(this.echPairKey(hostname, candidates[i].ip))
            const expireAt = item == null ? -1 : item.expireAt
            if (expireAt >= 0 && expireAt < earliest) {
              earliest = expireAt
              index = i
            }
          }
          const chosen = candidates[index >= 0 ? index : 0]
          this.clearPair(hostname, chosen.ip)
          capture.ip = chosen.ip
          capture.reusedFromCache = true
          log.info(`[ECH] ${hostname} 可解析到的IP都在负缓存里，仍沿用ECH重试（原生TLS在该域名上同样被阻断）: ${chosen.ip}`)
          callback(null, chosen.address, chosen.family)
        })
      })
    }

    return { lookup, capture }
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
        this.initEchSocket(socket, options)
        callback(null, socket)
      })
      .catch((error) => {
        log.warn(`[ECH] 使用ECH连接失败，回退原生TLS: ${hostname}, error: ${error.message}`)
        this.stat.fallback++
        // 原生回退也失败时，把该(域名,IP)喂给 ECH DNS 的 IP 优选（countEchIp），
        // 让 ECH 专用 DNS / 预设 IP / NAT64 把该 IP 降权，下次切到下一个 IP。
        // 否则 ECH 不可用退化到原生时，原生撞死 IP 不会反馈给 ECH DNS 优选，
        // 优选会一直把同一个坏 IP 排第一 → 间歇超时，需重启 DS 才清掉。
        if (error && error.resolvedIp) {
          dnsUtil.countEchIp(this.dnsConfig, hostname, error.resolvedIp, true, '原生TLS回退失败，切换IP')
        }
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
   * 给新建的ECH socket补上 agentkeepalive 的 socket 初始化
   *
   * agentkeepalive 是在它自己的 createConnection 里调用 [INIT_SOCKET] 的，而这里整个覆写了 createConnection，
   * 所以必须手动补上：INIT_SOCKET 会设置socket超时并安装 close/error/free/timeout 监听，
   * 其中 timeout 监听（onTimeout）负责回收空闲连接与中断卡死的请求。
   * 不补的话 socket 上没有 timeout 监听器，agentkeepalive 的 onTimeout 永远不会执行，
   * 空闲连接一直留在连接池里，一旦被网络/中间设备掐断，复用时请求要挂十几秒甚至几十秒才报 ECONNRESET。
   */
  initEchSocket (socket, options) {
    const initSocket = this[INIT_SOCKET]
    if (typeof initSocket === 'function') {
      initSocket.call(this, socket, options)
    }
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
    // 已经反馈过的失败IP，避免重试路径与循环尾部把它记两次
    let recordedIp = null
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
        // 本网络上带ECH扩展的ClientHello会被间歇性丢弃（同一个IP时而成功时而超时），
        // 所以握手失败后立刻把这个IP记为失败、换一个IP再试一次ECH，命中率远高于直接回退原生TLS
        if (attempt === 0 && this.canRetryWithAnotherIp(e)) {
          this.recordEchFailure(hostname, e.resolvedIp, e.message)
          recordedIp = e.resolvedIp
          log.warn(`[ECH] ${hostname} 的IP ${e.resolvedIp} ECH失败(${e.message})，换一个IP重试ECH`)
          continue
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
        const ip = lastError.resolvedIp
        if (ip == null) {
          this.markUnusable(hostname, ECH_FAILURE_TTL, lastError.message)
        } else if (ip !== recordedIp) {
          // 只拉黑该(域名,IP)：换个IP依旧会尝试ECH；同时把该IP记为失败，让DNS优选换一个ECH可用的IP
          this.recordEchFailure(hostname, ip, lastError.message)
        }
      }
    }
    throw lastError
  }

  /**
   * 记录一次ECH失败：只拉黑该(域名,IP)，并反馈给「ECH专用DNS」与「预设IP」做IP优选
   */
  recordEchFailure (hostname, ip, reason) {
    this.markUnusablePair(hostname, ip, ECH_FAILURE_TTL, reason)
    dnsUtil.countEchIp(this.dnsConfig, hostname, ip, true, reason)
  }

  /**
   * 这次失败是否值得换一个IP重试ECH
   *
   * ECH被服务器拒绝（要按域名拉黑）、拿不到ECH配置时，重试没有意义。
   */
  canRetryWithAnotherIp (error) {
    if (error == null || error.resolvedIp == null) {
      return false
    }
    return error.code !== 'ECH_REJECTED' && error.code !== 'ECH_NO_CONFIG'
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
    // 包装lookup：捕获本次连接真实使用的IP；该IP已知ECH不可用时先换一个IP再继续尝试ECH
    const { lookup, capture } = this.createEchLookup(hostname, options.lookup)
    let socket = null
    let info = null
    try {
      ({ socket, info } = await connectTls({
        host: options.host || options.hostname || hostname,
        port,
        servername: hostname,
        alpnProtocols: this.alpnProtocols,
        echConfig,
        rejectUnauthorized: options.rejectUnauthorized !== false && this.echOptions.rejectUnauthorized !== false,
        ca: options.ca,
        lookup,
        family: options.family,
        localAddress: options.localAddress,
        timeout: this.echOptions.timeout || ECH_HANDSHAKE_TIMEOUT,
        connectTimeout: this.echOptions.connectTimeout || ECH_CONNECT_TIMEOUT,
      }))
    } catch (e) {
      if (e != null && capture.ip != null) {
        // 失败时用来只拉黑这个IP（其它IP依旧尝试ECH），并反馈给DNS做IP优选
        e.resolvedIp = capture.ip
      }
      throw e
    }

    this.stat.ech++
    if (capture.ip != null) {
      // 这个IP上的ECH可用：清掉负缓存并记一次成功，避免DNS优选把它当成坏IP换走
      this.clearPair(hostname, capture.ip)
      dnsUtil.countEchIp(this.dnsConfig, hostname, capture.ip, false, 'ECH握手成功')
    }
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
        // 限制并发连接数：一次几十个请求同时做ECH握手时，本网络会丢掉其中约一半的ClientHello，
        // 超时又会被记成「IP的ECH不可用」，最终把整个域名推向原生TLS（而被按SNI阻断）
        maxSockets: echOptions.maxSockets || DEFAULT_MAX_SOCKETS,
        // ECH连接的空闲回收时间单独设置：keepAliveTimeout 是 agentkeepalive 的旧名字，
        // 传 undefined 避免它覆盖 freeSocketTimeout（见 agentkeepalive/lib/agent.js:39-47）
        freeSocketTimeout: echOptions.freeSocketTimeout || ECH_FREE_SOCKET_TIMEOUT,
        keepAliveTimeout: undefined,
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

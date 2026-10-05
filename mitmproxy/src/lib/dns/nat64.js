const https = require('node:https')
const { Buffer } = require('node:buffer')
const { LRUCache } = require('lru-cache')
const BaseDNS = require('./base')
const svcbUtil = require('./util.svcb')
const log = require('../../utils/util.log.server')

// NAT64（RFC 6146）：把 IPv4 地址嵌入一个 IPv6 前缀的最末 32 位，通过 IPv6 网络访问 IPv4 站点。
// 前缀由使用者配置（`server.dns.nat64.prefix`）：这里不内置任何公共 NAT64 网关——
// 流量会经该网关转发，属于第三方中转，必须由使用者自行选择与信任。
// 未配置前缀时 NAT64 不会启用（见 options.js 与下方的 toNat64Address）。
// 默认的DoH列表（按顺序尝试，前一个不可用时会自动用后面的）：
// 其中 dns.alidns.com 在国内网络下通常可以直连（SNI 不被阻断），另外两个更权威但可能被阻断
const DEFAULT_DOH = [
  'https://dns.alidns.com/resolve',
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
]
// DoH 服务域名对应的真实 IPv4：域名本身在本网络可能被投毒，必须先知道地址才能建立 NAT64 连接
// （这些是各 DoH 服务公开且固定的地址）
const DEFAULT_BOOTSTRAP = {
  'dns.alidns.com': ['223.5.5.5', '223.6.6.6'],
  'doh.pub': ['1.12.12.12', '120.53.53.53'],
  'cloudflare-dns.com': ['1.1.1.1', '1.0.0.1'],
  'dns.google': ['8.8.8.8', '8.8.4.4'],
}
const QUERY_TIMEOUT = 5000
// 多个DoH并发尝试时的错峰间隔
const PARALLEL_DELAY = 300
const DEFAULT_CACHE_TTL = 5 * 60 * 1000
// 查询失败时的短暂缓存，避免NAT64不可用时每个请求都等一次超时
const FAILED_CACHE_TTL = 30 * 1000
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
// 必须显式指定agent：Node 在 NODE_USE_ENV_PROXY=1 时会用 http_proxy/HTTPS_PROXY 环境变量里的代理，
// 而NAT64地址是IPv6直连地址，走代理会一直失败
const NAT64_AGENT = new https.Agent({ keepAlive: false, maxSockets: 8 })

/**
 * 把配置里的DoH配置（字符串或数组，字符串支持逗号分隔）规整成数组
 *
 * @param {string|string[]} doh 配置值
 * @returns {string[]} DoH地址列表
 */
function toDohList (doh) {
  const list = Array.isArray(doh) ? doh : String(doh == null ? '' : doh).split(',')
  return list.map(item => String(item).trim()).filter(item => item !== '')
}

/**
 * 判断某个DNS服务是不是DoH（NAT64通道上只能使用DoH）
 *
 * @param {object} conf DNS服务配置
 * @param {string} server DNS服务地址
 * @returns {boolean} 是否为DoH
 */
function isDohServer (conf, server) {
  const type = conf.type == null ? null : String(conf.type).replace(/\s+/g, '').toLowerCase()
  if (type == null) {
    return server.startsWith('http://') || server.startsWith('https://')
  }
  return type === 'https' || type === 'doh' || type === 'dns-over-https'
}

/**
 * 规整DoH地址（与 `initDNS` 的处理保持一致：没有路径时补 `/dns-query`）
 *
 * @param {string} server DNS服务地址
 * @returns {string} DoH地址
 */
function normalizeDohServer (server) {
  return server.includes('/') ? server : `https://${server}/dns-query`
}

/**
 * 解析「解析用DNS」，得到要使用的DoH地址列表（按优先级排序）
 *
 * 设置方式与「ECH专用DNS」保持一致：从「DNS服务管理」里选一个DNS服务名。
 * 区别是NAT64通道上只能走DoH（`https://`），选了非DoH类型的DNS（如 `tls://`、`udp://`）时会忽略并给出提示。
 * 列表末尾始终带上内置的公共DoH作为兜底，避免选中的DNS不可用时完全解析不出IP。
 *
 * @param {object} config NAT64配置，`config.dns` 为DNS服务名，`config.doh` 为直接指定的DoH地址（高级用法）
 * @param {object} providers 「DNS服务管理」里的DNS服务列表
 * @returns {Array<{url: string, sni: string}>} DoH地址列表（`sni` 为DNS服务里配置的SNI改写，可为空）
 */
function resolveDohList (config = {}, providers = {}) {
  const list = []
  const dnsName = config.dns == null ? '' : String(config.dns).trim()
  if (dnsName !== '') {
    const conf = providers[dnsName]
    const server = conf == null ? '' : String(conf.server || conf.host || '').replace(/\s+/g, '')
    if (server === '') {
      log.warn(`[DNS-over-NAT64] 未找到DNS服务 '${dnsName}'（请在「DNS服务管理」中配置），已改用默认DoH`)
    } else if (isDohServer(conf, server)) {
      // sni：与普通DNS服务一致，可取 conf.sni 或 conf.servername（用于绕过对DoH域名的SNI阻断）
      list.push({ url: normalizeDohServer(server), sni: conf.sni || conf.servername || '' })
    } else {
      log.warn(`[DNS-over-NAT64] DNS服务 '${dnsName}' 的地址 '${server}' 不是DoH类型（需为 https:// 开头），无法通过NAT64通道查询，已改用默认DoH`)
    }
  }
  for (const item of toDohList(config.doh)) {
    list.push({ url: item, sni: '' })
  }
  for (const item of DEFAULT_DOH) {
    list.push({ url: item, sni: '' })
  }
  // 同一个DoH地址只保留一次
  const map = new Map()
  for (const item of list) {
    if (!map.has(item.url)) {
      map.set(item.url, item)
    }
  }
  return [...map.values()]
}

/**
 * 把 IPv6 地址展开成 8 组（例如 `2a01:4f8:c2c:123f:64:5::` ➜ `['2a01','4f8','c2c','123f','64','5','0','0']`）
 *
 * @param {string} address IPv6地址或前缀
 * @returns {string[]} 8 组十六进制字符串
 */
function expandGroups (address) {
  const text = String(address == null ? '' : address).trim()
  const index = text.indexOf('::')
  const headText = index >= 0 ? text.substring(0, index) : text
  const tailText = index >= 0 ? text.substring(index + 2) : ''
  const groups = headText.split(':').filter(v => v !== '')
  const tailGroups = tailText.split(':').filter(v => v !== '')
  while (groups.length + tailGroups.length < 8) {
    groups.push('0')
  }
  return groups.concat(tailGroups).slice(0, 8)
}

/**
 * 把 IPv4 地址嵌入 NAT64 前缀，得到可直连的 IPv6 地址
 *
 * @param {string} prefix NAT64前缀，形如 `2a01:4f8:c2c:123f:64:5::`
 * @param {string} ipv4 IPv4地址
 * @returns {string|null} NAT64地址（IPv4不合法时返回null）
 */
function toNat64Address (prefix, ipv4) {
  const matched = IPV4_RE.exec(String(ipv4 == null ? '' : ipv4).trim())
  if (matched == null) {
    return null
  }
  const value = matched.slice(1).map(v => Number.parseInt(v, 10))
  if (value.some(v => Number.isNaN(v) || v > 255)) {
    return null
  }
  const groups = expandGroups(prefix)
  // 空前缀（或 `::`）会被补成全零地址，得到一个看似合法实则无效的 IPv6，必须显式拒绝
  if (groups.every(g => g === '0')) {
    return null
  }
  groups[6] = ((value[0] << 8) | value[1]).toString(16)
  groups[7] = ((value[2] << 8) | value[3]).toString(16)
  return groups.join(':')
}

/**
 * 基于 NAT64 的DNS解析（`dnsType: 'Nat64'`）
 *
 * 与其它DNS的区别：不做常规的 A/AAAA 查询，而是**通过 NAT64 通道**查询域名的真实 A 记录
 * （本网络的常规DNS被投毒、直连的DoH也被阻断），再把每个 IPv4 嵌进 NAT64 前缀返回。
 * 返回的地址是普通的 IPv6 地址，后续的 ECH 握手、IP优选、失败计数等逻辑全部复用。
 *
 * 走 NAT64 的域名会被当作 ECH 域名（在 `options.js` 中并入ECH名单），因此：
 * 自动被拦截（MITM）、跳过增强模式、忽略SNI改写与预设IP、并在上游TLS握手时使用ECH。
 */
module.exports = class DNSOverNat64 extends BaseDNS {
  constructor (config = {}, preSetIpList) {
    super(null, 6, 'NAT64', 'Nat64', config.cacheSize, preSetIpList)
    this.prefix = String(config.prefix || '').trim()
    // 「解析用DNS」（与 ECH 的设置方式一致，见 resolveDohList）：选中的DoH优先，末尾带上内置公共DoH兜底
    const dohEntries = resolveDohList(config, config.providers || {})
    this.dohList = dohEntries.map(item => item.url)
    // DoH地址 ➜ SNI改写（DNS服务里配置了 sni 时使用，与普通DNS服务的处理一致）
    this.dohSni = {}
    for (const item of dohEntries) {
      if (item.sni) {
        this.dohSni[item.url] = item.sni
      }
    }
    // 最近一次成功的DoH（优先使用，避免每次都回退一遍不可用的DoH）
    this.doh = this.dohList[0]
    this.bootstrap = { ...DEFAULT_BOOTSTRAP, ...(config.bootstrap || {}) }
    this.verifySsl = config.verifySsl === true
    // 正在进行的DoH请求（有一个成功后可立即中止其余的，避免占用连接）
    this.activeRequests = new Set()
    // 真实A记录的缓存：IP级缓存由基类的 lookup 维护，这里避免每次重建缓存都查询一次DoH
    const cacheTtl = Number.parseInt(config.cacheTtl, 10)
    this.recordCache = new LRUCache({
      max: 256,
      ttl: cacheTtl > 0 ? cacheTtl : DEFAULT_CACHE_TTL,
    })
  }

  /**
   * 解析域名的真实A记录，并转换成 NAT64 地址（IPv6）
   *
   * @param {string} hostname 域名
   * @returns {Promise<string[]>} NAT64 地址列表
   */
  async _lookup (hostname) {
    const start = Date.now()
    let ipv4List
    try {
      ipv4List = await this._queryIpv4(hostname)
    } catch (e) {
      log.error(`[DNS-over-NAT64 '${this.dnsName}'] 查询真实A记录失败: ${hostname}, doh: ${this.doh}, error: ${e.message}`)
      return []
    }
    if (ipv4List.length === 0) {
      log.warn(`[DNS-over-NAT64 '${this.dnsName}'] 没有查询到该域名的A记录: ${hostname}, doh: ${this.doh}`)
      return []
    }

    const ipList = ipv4List.map(ip => toNat64Address(this.prefix, ip)).filter(ip => ip != null)
    log.info(`[DNS-over-NAT64 '${this.dnsName}'] ${hostname} ➜ ${JSON.stringify(ipList)} (真实IP: ${ipv4List.join(', ')}, 前缀: ${this.prefix}, ${Date.now() - start} ms)`)
    return ipList
  }

  /**
   * 查询HTTPS(65)/SVCB(64)记录（获取ECH参数用），走同一条 NAT64 通道
   *
   * @param {string} hostname 域名
   * @param {string} type 记录类型
   * @returns {Promise<object>} 与 wire format 一致的结构
   */
  async _svcbQueryPromise (hostname, type = 'HTTPS') {
    const json = await this._dohQuery(hostname, type === 'SVCB' ? 'SVCB' : 'HTTPS')
    const answers = []
    for (const answer of json.Answer || []) {
      if (answer.type !== svcbUtil.TYPE_HTTPS && answer.type !== svcbUtil.TYPE_SVCB) {
        continue
      }
      answers.push({
        name: answer.name,
        type: svcbUtil.typeName(answer.type),
        typeCode: answer.type,
        ttl: answer.TTL,
        data: svcbUtil.parsePresentation(answer.data),
      })
    }
    return {
      rcode: 0,
      truncated: json.TC === true,
      questions: [{ name: hostname, type: 'HTTPS' }],
      answers,
    }
  }

  /**
   * 查询域名的真实A记录（带缓存）
   *
   * @param {string} hostname 域名
   * @returns {Promise<string[]>} IPv4地址列表
   */
  async _queryIpv4 (hostname) {
    const cached = this.recordCache.get(hostname)
    if (cached != null) {
      return cached
    }

    let json
    try {
      json = await this._dohQuery(hostname, 'A')
    } catch (e) {
      // NAT64网关不可用时不缓存（每次请求都会重试太慢），只做一个短时间的空结果缓存
      this.recordCache.set(hostname, [], { ttl: FAILED_CACHE_TTL })
      throw e
    }

    const ipv4List = []
    for (const answer of json.Answer || []) {
      const ip = String(answer.data == null ? '' : answer.data).trim()
      if (answer.type === 1 && IPV4_RE.test(ip) && !ipv4List.includes(ip)) {
        ipv4List.push(ip)
      }
    }
    this.recordCache.set(hostname, ipv4List)
    return ipv4List
  }

  /**
   * 通过 NAT64 通道查询DoH（JSON接口，RFC 8427）
   *
   * 连接的是 DoH 域名对应真实IPv4的 NAT64 地址，SNI/Host 仍是 DoH 域名本身；
   * 这样即使本网络的DNS被投毒、或直连DoH被阻断，也能拿到真实解析结果。
   * 配置了多个DoH时并发错峰尝试（最近成功的优先），先返回者胜。
   *
   * @param {string} hostname 要查询的域名
   * @param {string} type 记录类型（A/AAAA/HTTPS/...）
   * @returns {Promise<object>} DoH返回的JSON
   */
  _dohQuery (hostname, type) {
    const dohList = this.dohList.filter((doh) => {
      const dohHost = new URL(doh).hostname
      const bootstrapList = this.bootstrap[dohHost]
      return bootstrapList != null && bootstrapList.length > 0
    }).sort((a, b) => {
      // 最近成功的DoH排最前
      return (a === this.doh ? 0 : 1) - (b === this.doh ? 0 : 1)
    })

    if (dohList.length === 0) {
      return Promise.reject(new Error(`未配置DoH域名(${this.dohList.join(', ')})的真实IPv4地址（server.dns.nat64.bootstrap），无法通过NAT64查询DNS`))
    }

    return new Promise((resolve, reject) => {
      let isOver = false
      let pending = dohList.length
      let lastError = null
      const finish = (err, value, doh) => {
        if (isOver) {
          return
        }
        if (err != null) {
          lastError = err
          pending--
          if (pending > 0) {
            return
          }
          isOver = true
          reject(lastError)
          return
        }
        isOver = true
        this.doh = doh
        // 已经有一个DoH返回结果，中止其余的尝试
        this.abortActiveRequests()
        resolve(value)
      }

      dohList.forEach((doh, index) => {
        setTimeout(() => {
          if (isOver) {
            return
          }
          this._queryOneDoh(doh, hostname, type).then((json) => {
            if (json != null && this.doh !== doh) {
              log.info(`[DNS-over-NAT64 '${this.dnsName}'] 使用DoH: ${doh}`)
            }
            finish(null, json, doh)
          }).catch((e) => {
            log.debug(`[DNS-over-NAT64 '${this.dnsName}'] DoH不可用: ${doh}, error: ${e.message}`)
            finish(e)
          })
        }, index * PARALLEL_DELAY)
      })
    })
  }

  /**
   * 中止所有正在进行的DoH请求
   */
  abortActiveRequests () {
    for (const req of this.activeRequests) {
      req.destroy()
    }
    this.activeRequests.clear()
  }

  /**
   * 向单个DoH地址发起一次查询
   *
   * @param {string} doh DoH地址
   * @param {string} hostname 要查询的域名
   * @param {string} type 记录类型
   * @returns {Promise<object>} DoH返回的JSON
   */
  _queryOneDoh (doh, hostname, type) {
    const url = new URL(doh)
    url.searchParams.set('name', hostname)
    url.searchParams.set('type', type)
    if (!url.searchParams.has('ct')) {
      // 部分DoH（如 cloudflare-dns.com）需要该参数才返回JSON
      url.searchParams.set('ct', 'application/dns-json')
    }

    const dohHost = url.hostname
    // 地址本身就是IPv4时（如 https://1.1.1.1/dns-query）直接用它，否则从 bootstrap 里取它的真实IPv4
    const isIpHost = IPV4_RE.test(dohHost)
    const bootstrapList = isIpHost ? [dohHost] : this.bootstrap[dohHost]
    if (bootstrapList == null || bootstrapList.length === 0) {
      return Promise.reject(new Error(`未配置DoH域名 ${dohHost} 的真实IPv4地址（server.dns.nat64.bootstrap），无法通过NAT64查询DNS`))
    }

    const target = toNat64Address(this.prefix, bootstrapList[0])
    if (target == null) {
      return Promise.reject(new Error(`NAT64前缀不合法: ${this.prefix}`))
    }

    return new Promise((resolve, reject) => {
      let isOver = false
      let req = null
      let timer = null
      const finish = (err, value) => {
        if (isOver) {
          return
        }
        isOver = true
        clearTimeout(timer)
        if (req != null) {
          this.activeRequests.delete(req)
        }
        if (err) {
          reject(err)
        } else {
          resolve(value)
        }
      }

      req = https.request({
        host: target,
        family: 6,
        port: Number.parseInt(url.port, 10) || 443,
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        // SNI：优先用DNS服务里配置的SNI改写；地址是IPv4字面量时不发SNI（证书直接覆盖该IP）
        servername: this.dohSni[doh] || (isIpHost ? undefined : dohHost),
        rejectUnauthorized: this.verifySsl,
        timeout: QUERY_TIMEOUT,
        agent: NAT64_AGENT,
        headers: {
          // Host 始终用DoH地址里的域名（与普通DNS服务一致：SNI改写只影响TLS的servername，不影响Host）
          host: dohHost,
          accept: 'application/dns-json',
        },
      }, (res) => {
        const chunks = []
        res.on('data', chunk => chunks.push(chunk))
        res.on('end', () => {
          if (res.statusCode !== 200) {
            finish(new Error(`DoH服务返回状态码 ${res.statusCode}`))
            return
          }
          try {
            const json = JSON.parse(Buffer.concat(chunks).toString('utf8'))
            const status = json.Status == null ? 0 : Number(json.Status)
            // 3 = NXDOMAIN（域名不存在），不是错误，只是没有记录
            if (status !== 0 && status !== 3) {
              finish(new Error(`DoH服务返回错误状态: ${status}`))
              return
            }
            finish(null, json)
          } catch (e) {
            finish(new Error(`DoH服务返回的内容不是合法的JSON: ${e.message}`))
          }
        })
        res.on('error', finish)
      })

      // 硬超时兜底（timeout 事件在连接阶段不一定触发）
      timer = setTimeout(() => {
        req.destroy(new Error(`DoH查询超时(${QUERY_TIMEOUT}ms)`))
      }, QUERY_TIMEOUT)

      req.on('error', finish)
      req.on('timeout', () => {
        req.destroy(new Error(`DoH查询超时(${QUERY_TIMEOUT}ms)`))
      })
      this.activeRequests.add(req)
      req.end()
    })
  }
}

module.exports.expandGroups = expandGroups
module.exports.toNat64Address = toNat64Address
module.exports.toDohList = toDohList
module.exports.resolveDohList = resolveDohList

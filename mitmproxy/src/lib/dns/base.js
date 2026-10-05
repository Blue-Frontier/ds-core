const { LRUCache } = require('lru-cache')
const log = require('../../utils/util.log.server')
const matchUtil = require('../../utils/util.match')
const { isIPv6 } = require('./util.ip')
const svcbUtil = require('./util.svcb')
const { DynamicChoice } = require('../choice/index')
const os = require('node:os')

// 启动时检测系统是否有 IPv6 网络能力（遍历本机网卡），无则过滤所有 IPv6 DNS 结果
// 注意：忽略 fe80::/10 本地链路地址，它们不代表实际上游 IPv6 连通性
let ipv6Unavailable = (() => {
  const nets = os.networkInterfaces()
  for (const name of Object.keys(nets)) {
    for (const info of nets[name]) {
      if (!info.internal && info.family === 'IPv6' && !info.address.startsWith('fe80:')) {
        return false
      }
    }
  }
  log.info('未检测到可用的 IPv6 网络接口，将过滤所有 IPv6 DNS 解析结果')
  return true
})()

// 运行时兜底：累计 3 次 IPv6 ENETUNREACH 后，认为上游 IPv6 不可达
let ipv6ErrCount = 0
function reportIPv6Error (ip) {
  if (!isIPv6(ip) || ipv6Unavailable) return
  ipv6ErrCount++
  if (ipv6ErrCount >= 3) {
    ipv6Unavailable = true
    log.warn(`IPv6 地址 ${ip} 多次不可达（ENETUNREACH），已自动禁用 IPv6 DNS 解析`)
  }
}
module.exports.reportIPv6Error = reportIPv6Error

function mapToList (ipMap) {
  const ipList = []
  for (const key in ipMap) {
    const value = ipMap[key]
    // 真值即生效：true、非空字符串、对象（常用于顺带写 desc）都算启用；
    // false / null / 0 / 'false' / '0' 视为未启用
    if (value && value !== 'false' && value !== '0') {
      ipList.push(key)
    }
  }
  return ipList
}

const defaultCacheSize = 1024

// ECH（Encrypted Client Hello）相关默认值
const defaultEchCacheSize = 512 // ECH配置缓存的最大条数
const defaultEchEmptyTtl = 10 * 60 * 1000 // DNS未下发ech参数时的缓存时间(ms)
const defaultEchMinTtl = 60 * 1000 // DNS未给出TTL时的默认缓存时间(ms)
const defaultEchMaxTtl = 60 * 60 * 1000 // 最大缓存时间(ms)
const ECH_QUERY_TIMEOUT = 8000 // 查询HTTPS记录的超时时间(ms)
const ECH_MAX_ALIAS_DEPTH = 3 // HTTPS记录中 AliasMode(priority=0) 的最大跟随层数

class IpCache extends DynamicChoice {
  constructor (hostname) {
    super(hostname)
    this.lookupCount = 0
  }

  /**
   * 设置新的ipList
   *
   * @param newBackupList
   */
  setBackupList (newBackupList) {
    super.setBackupList(newBackupList)
    this.lookupCount++
  }
}

module.exports = class BaseDNS {
  constructor (dnsServer, dnsFamily, dnsName, dnsType, cacheSize, preSetIpList) {
    this.dnsName = dnsName
    this.dnsType = dnsType
    this.preSetIpList = preSetIpList

    this.cache = new LRUCache({
      maxSize: (cacheSize > 0 ? cacheSize : defaultCacheSize),
      sizeCalculation: () => {
        return 1
      },
    })

    // ECH 相关（RFC 9848：通过DNS的HTTPS(65)记录中的 ech 参数来启用ECH）
    this.echConfig = null
    this.echCache = null
    this.echPendingMap = new Map()
    this.echStat = {
      query: 0,
      hit: 0,
      error: 0,
    }

    if (!dnsServer) {
      return
    }
    this.dnsServer = dnsServer
    this.dnsFamily = Number.parseInt(dnsFamily) || (isIPv6(dnsServer) ? 6 : 4)
    this.dnsFamily = this.dnsFamily === 6 ? 6 : 4 // 避免值错误
  }

  count (hostname, ip, isError = true) {
    const ipCache = this.cache.get(hostname)
    if (ipCache) {
      ipCache.doCount(ip, isError)
    }
  }

  /**
   * 初始化ECH支持，由 `dns/index.js` 在创建DNS实例后调用
   *
   * @param options.enabled 是否启用ECH（查询DNS的HTTPS记录）
   * @param options.cacheSize ECH配置缓存的最大条数
   * @param options.emptyTtl DNS未下发ech参数时的缓存时间(ms)
   * @param options.minTtl DNS未给出TTL时的默认缓存时间(ms)
   * @param options.maxTtl 最大缓存时间(ms)
   */
  initEch (options = {}) {
    this.echConfig = {
      enabled: options.enabled !== false,
      emptyTtl: options.emptyTtl > 0 ? options.emptyTtl : defaultEchEmptyTtl,
      minTtl: options.minTtl > 0 ? options.minTtl : defaultEchMinTtl,
      maxTtl: options.maxTtl > 0 ? options.maxTtl : defaultEchMaxTtl,
    }
    if (this.echCache == null) {
      this.echCache = new LRUCache({
        max: options.cacheSize > 0 ? options.cacheSize : defaultEchCacheSize,
      })
    }
  }

  /**
   * 该DNS服务是否支持获取ECH参数（需要支持 HTTPS(65) 记录的查询，且已启用ECH）
   */
  get echEnabled () {
    return this.echConfig != null && this.echConfig.enabled && typeof this._svcbQueryPromise === 'function'
  }

  /**
   * 获取该域名由DNS下发的 ECH 参数（RFC 9848）
   *
   * @returns {Promise<null|object>} 形如 `{ echConfigList, publicName, config, configs, ttl, dnsName, dnsType }`
   */
  async lookupEch (hostname, options = {}) {
    if (!this.echEnabled) {
      return null
    }

    const cached = this.echCache.get(hostname)
    if (cached !== undefined) {
      this.echStat.hit++
      if (cached === false) {
        log.debug(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 命中缓存（该域名未下发ech参数）: ${hostname}`)
        return null
      }
      log.debug(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 命中缓存: ${hostname} ➜ public_name: ${cached.publicName}`)
      return cached
    }

    // 同一个域名的并发查询合并为一次
    const pending = this.echPendingMap.get(hostname)
    if (pending != null) {
      return await pending
    }

    const promise = this._lookupEch(hostname, 0, options).finally(() => {
      this.echPendingMap.delete(hostname)
    })
    this.echPendingMap.set(hostname, promise)
    return await promise
  }

  async _lookupEch (hostname, depth, options = {}) {
    const start = Date.now()
    this.echStat.query++

    let response
    try {
      response = await this._doSvcbQuery(hostname, 'HTTPS', start)
    } catch (e) {
      this.echStat.error++
      log.warn(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 查询HTTPS记录失败: ${hostname}, error: ${e.message}`)
      return null
    }

    const parsed = this._parseEchResponse(hostname, response, start)

    // 处理 AliasMode（priority=0）：继续查询其指向的域名
    if (parsed != null && parsed.alias != null && depth < ECH_MAX_ALIAS_DEPTH) {
      log.info(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] ${hostname} 的HTTPS记录为AliasMode，跟随查询: ${parsed.alias}`)
      return await this._lookupEch(parsed.alias, depth + 1, options)
    }

    if (parsed == null || parsed.echConfigList == null) {
      // 缓存「该域名未下发ech参数」，避免每次请求都查询一次
      this.echCache.set(hostname, false, { ttl: this.echConfig.emptyTtl })
      return null
    }

    const ttl = Math.min(Math.max((parsed.recordTtl || 0) * 1000, this.echConfig.minTtl), this.echConfig.maxTtl)
    const result = {
      echConfigList: parsed.echConfigList,
      configs: parsed.configs,
      config: parsed.config,
      publicName: parsed.config.publicName,
      priority: parsed.priority,
      target: parsed.target,
      ipv4hint: parsed.ipv4hint,
      ipv6hint: parsed.ipv6hint,
      alpn: parsed.alpn,
      ttl,
      expireAt: Date.now() + ttl,
      dnsName: this.dnsName,
      dnsType: this.dnsType,
    }

    this.echCache.set(hostname, result, { ttl })
    log.info(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 获取到该域名的ECH参数： ${hostname} ➜ public_name: ${result.publicName}, kem: ${result.config.kem}, ech: ${result.echConfigList.length} bytes, ttl: ${parsed.recordTtl}s`)

    return result
  }

  /**
   * 从 HTTPS(65) 记录的响应中解析出 ech 参数
   */
  _parseEchResponse (hostname, response, start) {
    const cost = Date.now() - (start == null ? Date.now() : start)

    if (response == null || response.answers == null || response.answers.length === 0) {
      log.info(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 该域名未下发HTTPS记录: ${hostname}, cost: ${cost} ms`)
      return null
    }

    const records = response.answers.filter(item => item.data != null && svcbUtil.isSvcType(item.type))
    if (records.length === 0) {
      log.info(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 该域名未下发HTTPS记录: ${hostname}, cost: ${cost} ms`)
      return null
    }

    // AliasMode：priority=0 且 target 不是根域名，需要继续查询target
    const aliasRecord = records.find(item => item.data.priority === 0 && item.data.target && item.data.target !== '.')
    if (aliasRecord != null) {
      return {
        alias: aliasRecord.data.target,
      }
    }

    // ServiceMode：按priority升序，取第一个下发了ech参数的记录（RFC 9460 §3.1）
    const serviceRecords = records
      .filter(item => item.data.priority > 0)
      .sort((a, b) => a.data.priority - b.data.priority)

    const record = serviceRecords.find(item => item.data.ech != null && item.data.ech.length > 0)
    if (record == null) {
      log.info(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 该域名的HTTPS记录未下发ech参数: ${hostname}, cost: ${cost} ms`)
      return null
    }

    const echConfigList = record.data.ech
    const config = svcbUtil.pickEchConfig(echConfigList)
    if (config == null) {
      log.warn(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] 该域名的ECH参数无法使用: ${hostname}, ech: ${echConfigList.toString('base64')}`)
      return null
    }

    return {
      echConfigList,
      configs: svcbUtil.parseEchConfigList(echConfigList),
      config,
      priority: record.data.priority,
      target: record.data.target,
      ipv4hint: record.data.paramMap.ipv4hint,
      ipv6hint: record.data.paramMap.ipv6hint,
      alpn: record.data.paramMap.alpn,
      recordTtl: record.ttl,
      cost,
    }
  }

  /**
   * 查询 HTTPS(65) 记录，带超时控制
   */
  _doSvcbQuery (hostname, type = 'HTTPS', start) {
    if (start == null) {
      start = Date.now()
    }

    return new Promise((resolve, reject) => {
      let isOver = false
      const timeoutId = setTimeout(() => {
        if (!isOver) {
          isOver = true
          log.error(`[ECH][DNS-over-${this.dnsType} '${this.dnsName}'] DNS查询超时, hostname: ${hostname}, type: ${type}, dnsServer: ${this.dnsServer}${this.dnsServerPort ? `:${this.dnsServerPort}` : ''}, cost: ${Date.now() - start} ms`)
          reject(new Error('DNS查询超时'))
        }
      }, ECH_QUERY_TIMEOUT)

      try {
        this._svcbQueryPromise(hostname, type)
          .then((response) => {
            isOver = true
            clearTimeout(timeoutId)
            resolve(response)
          })
          .catch((e) => {
            isOver = true
            clearTimeout(timeoutId)
            reject(e)
          })
      } catch (e) {
        isOver = true
        clearTimeout(timeoutId)
        reject(e)
      }
    })
  }

  async lookup (hostname, options = {}) {
    try {
      let ipCache = this.cache.get(hostname)
      // ECH域名：IP地址缓存退化成「域名兜底项」时（此前解析出的真实IP都被判定失败），先重置失败计数重新使用真实IP；
      // 缓存里从未解析出真实IP时，清除缓存重新解析一次。
      // 否则下游会把域名交给系统DNS解析（可能被投毒或阻断），表现为一直连接超时（ECH域名尤其致命：必须用真实IP才能完成ECH握手）
      if (ipCache != null && options.resetOnHostnameFallback === true && ipCache.value === hostname) {
        const reset = ipCache.resetChoice(hostname)
        log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] IP地址缓存已退化为域名兜底项${reset ? `，重置失败计数后重新使用真实IP: ${ipCache.value}` : '，缓存中没有真实IP，清除缓存重新解析'}: ${hostname}`)
        if (!reset) {
          this.cache.delete(hostname)
          ipCache = null
        }
      }

      if (ipCache) {
        const ip = ipCache.value
        if (ip != null) {
          if (options.ipChecker) {
            if (options.ipChecker(ip)) {
              ipCache.doCount(ip, false)
              log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] 获取IP地址缓存: ${hostname} -> ${ip}（测试通过）`)
              return ip
            } else {
              log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] 获取IP地址缓存: ${hostname} -> ${ip}（测试不通过）-> ${hostname}`)
              return hostname
            }
          } else {
            log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] 获取IP地址缓存: ${hostname} -> ${ip}`)
            return ip
          }
        } else {
          log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] 未获取到IP地址缓存: ${hostname}`)
        }
      } else {
        ipCache = new IpCache(hostname)
        this.cache.set(hostname, ipCache)
        log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] 首次创建IP地址缓存区: ${hostname}`)
      }

      const t = Date.now()
      let ipList = await this._lookupWithPreSetIpList(hostname, options)
      if (ipList == null) {
        // 没有获取到ip
        ipList = []
      }
      // 本机无 IPv6 网络能力时过滤 IPv6 地址，避免 ENETUNREACH
      if (ipv6Unavailable) {
        ipList = ipList.filter(ip => !isIPv6(ip))
      }
      ipList.push(hostname) // 把原域名加入到统计里去

      ipCache.setBackupList(ipList)

      const ip = ipCache.value
      log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] ${hostname} ➜ ${ip} (${Date.now() - t} ms), ipList: ${JSON.stringify(ipList)}, ipCache:`, JSON.stringify(ipCache))

      if (options.ipChecker) {
        if (ip != null && ip !== hostname && options.ipChecker(ip)) {
          return ip
        }

        for (const ip of ipList) {
          if (ip !== hostname && options.ipChecker(ip)) {
            return ip
          }
        }
      }

      return ip != null ? ip : hostname
    } catch (error) {
      log.error(`[DNS-over-${this.dnsType} '${this.dnsName}'] cannot resolve hostname ${hostname}, error:`, error)
      return hostname
    }
  }

  async _lookupWithPreSetIpList (hostname, options = {}) {
    // ECH域名强制忽略预设IP：预设IP往往是域名自身的源站IP，不支持ECH，会导致ECH握手失败
    if (this.preSetIpList && options.ignorePreSetIpList !== true) {
      // 获取当前域名的预设IP列表
      let hostnamePreSetIpList = matchUtil.matchHostname(this.preSetIpList, hostname, `matched preSetIpList(${this.dnsName})`)
      if (hostnamePreSetIpList && (hostnamePreSetIpList.length > 0 || hostnamePreSetIpList.length === undefined)) {
        if (hostnamePreSetIpList.length > 0) {
          hostnamePreSetIpList = hostnamePreSetIpList.slice() // 复制一份列表数据，避免配置数据被覆盖
        } else {
          hostnamePreSetIpList = mapToList(hostnamePreSetIpList)
        }

        if (hostnamePreSetIpList.length > 0) {
          hostnamePreSetIpList.isPreSet = true
          log.info(`[DNS-over-PreSet '${this.dnsName}'] 获取到该域名的预设IP列表： ${hostname} - ${JSON.stringify(hostnamePreSetIpList)}`)
          return hostnamePreSetIpList
        }
      }
    }

    return await this._lookup(hostname, options)
  }

  async _lookup (hostname, options = {}) {
    const start = Date.now()

    options.family = Number.parseInt(options.family) === 6 ? 6 : 4
    const type = options.family === 6 ? 'AAAA' : 'A'

    let response
    try {
      // 执行DNS查询
      log.debug(`[DNS-over-${this.dnsType} '${this.dnsName}'] query start: ${hostname}`)
      response = await this._doDnsQuery(hostname, type, start)
    } catch {
      // 异常日志在 _doDnsQuery已经打印过，这里就不再打印了
      return []
    }

    try {
      const cost = Date.now() - start
      log.debug(`[DNS-over-${this.dnsType} '${this.dnsName}'] query end: ${hostname}, cost: ${cost} ms, response:`, response)

      if (response == null || response.answers == null || response.answers.length == null || response.answers.length === 0) {
        log.warn(`[DNS-over-${this.dnsType} '${this.dnsName}'] 没有该域名的IPv${options.family}地址: ${hostname}, cost: ${cost} ms, response:`, response)
        return []
      }

      const ret = response.answers.filter(item => item.type === type).map(item => item.data)
      if (ret.length === 0) {
        log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] 没有该域名的IPv${options.family}地址: ${hostname}, cost: ${cost} ms`)
      } else {
        log.info(`[DNS-over-${this.dnsType} '${this.dnsName}'] 获取到该域名的IPv${options.family}地址： ${hostname} - ${JSON.stringify(ret)}, cost: ${cost} ms`)
      }

      return ret
    } catch (e) {
      log.error(`[DNS-over-${this.dnsType} '${this.dnsName}'] 解读响应失败，response:`, response, ', error:', e)
      return []
    }
  }

  _doDnsQuery (hostname, type = 'A', start) {
    if (start == null) {
      start = Date.now()
    }

    return new Promise((resolve, reject) => {
      // 设置超时任务
      let isOver = false
      const timeout = 8000
      const timeoutId = setTimeout(() => {
        if (!isOver) {
          isOver = true
          log.error(`[DNS-over-${this.dnsType} '${this.dnsName}'] DNS查询超时, hostname: ${hostname}, sni: ${this.dnsServerName || '无'}, type: ${type}${this.dnsServer ? `, dnsServer: ${this.dnsServer}` : ''}${this.dnsServerPort ? `:${this.dnsServerPort}` : ''}, cost: ${Date.now() - start} ms`)
          reject(new Error('DNS查询超时'))
        }
      }, timeout)

      try {
        this._dnsQueryPromise(hostname, type)
          .then((response) => {
            isOver = true
            clearTimeout(timeoutId)
            resolve(response)
          })
          .catch((e) => {
            isOver = true
            clearTimeout(timeoutId)
            if (e.message === 'DNS查询超时') {
              log.error(`[DNS-over-${this.dnsType} '${this.dnsName}'] DNS查询超时. hostname: ${hostname}, sni: ${this.dnsServerName || '无'}, type: ${type}${this.dnsServer ? `, dnsServer: ${this.dnsServer}` : ''}${this.dnsServerPort ? `:${this.dnsServerPort}` : ''}, cost: ${Date.now() - start} ms`)
            } else {
              log.error(`[DNS-over-${this.dnsType} '${this.dnsName}'] DNS查询错误, hostname: ${hostname}, sni: ${this.dnsServerName || '无'}, type: ${type}${this.dnsServer ? `, dnsServer: ${this.dnsServer}` : ''}${this.dnsServerPort ? `:${this.dnsServerPort}` : ''}, cost: ${Date.now() - start} ms, error:`, e)
            }
            reject(e)
          })
      } catch (e) {
        isOver = true
        clearTimeout(timeoutId)
        log.error(`[DNS-over-${this.dnsType} '${this.dnsName}'] DNS查询异常, hostname: ${hostname}, type: ${type}${this.dnsServer ? `, dnsServer: ${this.dnsServer}` : ''}${this.dnsServerPort ? `:${this.dnsServerPort}` : ''}, cost: ${Date.now() - start} ms, error:`, e)
        reject(e)
      }
    })
  }
}

const matchUtil = require('../../utils/util.match')
const echDomainUtil = require('../proxy/common/ech/domain')
const ipUtil = require('./util.ip')
const log = require('../../utils/util.log.server')
const DNSOverPreSetIpList = require('./preset.js')
const DNSOverHTTPS = require('./https.js')
const DNSOverTLS = require('./tls.js')
const DNSOverTCP = require('./tcp.js')
const DNSOverUDP = require('./udp.js')

module.exports = {
  /**
   * @param dnsProviders DNS服务列表
   * @param preSetIpList 预设IP列表
   * @param options 选项，其中 `options.ech` 为 ECH配置（RFC 9848），形如 `{ enabled, cacheSize, emptyTtl, minTtl, maxTtl }`
   */
  initDNS (dnsProviders, preSetIpList, options = {}) {
    const dnsMap = {}
    const echOptions = options.ech || {}

    // 创建普通的DNS
    for (const provider in dnsProviders) {
      const conf = dnsProviders[provider]

      // 获取DNS服务器
      let server = conf.server || conf.host
      if (server != null) {
        server = server.replace(/\s+/, '')
      }
      if (!server) {
        continue
      }

      // 获取DNS类型
      let type = conf.type
      if (type == null) {
        if (server.startsWith('https://') || server.startsWith('http://')) {
          type = 'https'
        } else if (server.startsWith('tls://') || server.startsWith('dot://')) {
          type = 'tls'
        } else if (server.startsWith('tcp://')) {
          type = 'tcp'
        } else if (server.includes('://') && !server.startsWith('udp://')) {
          throw new Error(`Unknown type DNS: ${server}, provider: ${provider}`)
        } else {
          type = 'udp'
        }
      } else {
        type = type.replace(/\s+/, '').toLowerCase()
      }

      // 获取DNS的Family值
      const family = conf.family

      // 创建DNS对象
      if (type === 'https' || type === 'doh' || type === 'dns-over-https') {
        if (!server.includes('/')) {
          server = `https://${server}/dns-query`
        }

        // 基于 https
        dnsMap[provider] = new DNSOverHTTPS(provider, conf.cacheSize, preSetIpList, server, family, conf.sni || conf.servername)
      } else {
        // 获取DNS端口
        let port = conf.port

        // 处理带协议的DNS服务地址
        if (server.includes('://')) {
          server = server.split('://')[1]
        }
        // 处理带端口的DNS服务地址
        if (port == null && server.includes(':')) {
          // 判断是否为IPv6并带端口号
          if (server.includes(']:')) {
            [server, port] = server.split(']:')
            server = server.substring(1) // 移除第一个字符 `[`
          } else if (!ipUtil.isIPv6(server)) {
            [server, port] = server.split(':')
          }
        }

        // 去除host两边的中括号，因为可能是IPv6配置
        server = server.replace(/[[\]]/g, '')

        if (type === 'tls' || type === 'dot' || type === 'dns-over-tls') {
          // 基于 tls
          dnsMap[provider] = new DNSOverTLS(provider, conf.cacheSize, preSetIpList, server, port, family, conf.sni || conf.servername)
        } else if (type === 'tcp') {
          // 基于 tcp
          dnsMap[provider] = new DNSOverTCP(provider, conf.cacheSize, preSetIpList, server, port, family)
        } else {
          // 基于 udp
          dnsMap[provider] = new DNSOverUDP(provider, conf.cacheSize, preSetIpList, server, port, family)
        }
      }

      if (conf.forSNI || conf.forSni) {
        dnsMap.ForSNI = dnsMap[provider]
      }

      // 初始化ECH支持：provider 级配置 `ech: false` 可单独关闭某个DNS的ECH查询
      const echEnabled = echOptions.enabled !== false && conf.ech !== false
      if (dnsMap[provider].initEch != null) {
        dnsMap[provider].initEch({ ...echOptions, enabled: echEnabled })
      }
    }

    // 创建预设IP的DNS
    dnsMap.PreSet = new DNSOverPreSetIpList(preSetIpList)
    if (dnsMap.ForSNI == null) {
      dnsMap.ForSNI = dnsMap.PreSet
    }

    log.info(`设置SNI默认使用的DNS为 '${dnsMap.ForSNI.dnsName}'（注：当某个域名配置了SNI但未配置DNS时，将默认使用该DNS）`)

    return dnsMap
  },
  /**
   * 该域名是否启用了ECH（域名在 `server.dns.ech.domains` 名单中，且ECH已启用并使用）
   *
   * ECH域名会强制忽略常规的SNI改写、预设IP等配置：ECH握手必须使用真实SNI，
   * 且必须拿到真实可用的IP，否则握手会失败（表现为回退原生TLS或连接被重置）。
   */
  isEchDomain (dnsConfig, hostname) {
    if (dnsConfig == null || dnsConfig.ech == null) {
      return false
    }
    if (dnsConfig.ech.enabled === false || dnsConfig.ech.use === false) {
      return false
    }
    return echDomainUtil.isEchDomain(dnsConfig.echDomains, hostname)
  },

  /**
   * 获取ECH域名指定的DNS（`server.dns.ech.dns`，取值来自「DNS服务管理」中的DNS名称）
   *
   * 未指定或指定的DNS不存在时返回null
   */
  getEchDNS (dnsConfig) {
    if (dnsConfig == null || dnsConfig.ech == null || dnsConfig.dnsMap == null) {
      return null
    }
    const dnsName = dnsConfig.ech.dns
    if (dnsName == null || dnsName === '') {
      return null
    }
    return dnsConfig.dnsMap[dnsName] || null
  },

  /**
   * ECH域名是否忽略「预设IP」与「IP测速」结果（默认忽略）
   *
   * 预设IP通常是域名自己的源站IP，可能不支持ECH（此时ECH握手会失败，只能回退到原生TLS）；
   * 但 Cloudflare 站点在默认解析出的IP被阻断时，也可以用它指定一组可用的 Cloudflare IP，
   * 因此 `server.dns.ech.preSetIpDomains` 里的域名例外：允许使用预设IP与IP测速结果。
   */
  isEchIgnorePreSetIp (dnsConfig, hostname) {
    if (dnsConfig == null || dnsConfig.ech == null) {
      return true
    }
    return !echDomainUtil.isEchDomain(dnsConfig.echPreSetIpDomains, hostname)
  },

  getDNSAndFamily (dnsConfig, hostname) {
    const isEchDomain = this.isEchDomain(dnsConfig, hostname)

    // ECH域名优先使用ECH指定的DNS
    if (isEchDomain) {
      const echDns = this.getEchDNS(dnsConfig)
      if (echDns != null) {
        return {
          dns: echDns,
        }
      }
    }

    // 1. 匹配 预设IP配置（ECH域名默认强制忽略预设IP，避免ECH握手打到不支持ECH的IP上）
    const ignorePreSetIp = isEchDomain && this.isEchIgnorePreSetIp(dnsConfig, hostname)
    if (!ignorePreSetIp) {
      const hostnamePreSetIpList = matchUtil.matchHostname(dnsConfig.preSetIpList, hostname, 'matched preSetIpList(getDNSAndFamily)')
      if (hostnamePreSetIpList) {
        return {
          dns: dnsConfig.dnsMap.PreSet,
        }
      }
    }

    // 2. 读取域名对应的DNS配置
    const dnsData = matchUtil.matchHostname(dnsConfig.mapping, hostname, 'get dns data')
    if (!dnsData) {
      return null
    }

    // 由于DNS中的usa已重命名为cloudflare，所以做以下处理，为了向下兼容
    let dns
    if (dnsData.dnsName === 'usa' && dnsConfig.dnsMap.usa == null && dnsConfig.dnsMap.cloudflare != null) {
      dns = dnsConfig.dnsMap.cloudflare
    } else {
      dns = dnsConfig.dnsMap[dnsData.dnsName]
      if (!dns) {
        return null
      }
    }

    return {
      dns,
      family: dnsData.family,
    }
  },

  /**
   * 获取该域名上游TLS握手使用的ECH参数（RFC 9848）
   *
   * 先查该域名自己下发的ECH记录；查不到时使用共享的ECH配置（`server.dns.ech.publicName`，
   * 默认为 Cloudflare 的 `cloudflare-ech.com`，它对所有 Cloudflare 站点通用：
   * Cloudflare 边缘节点解密后按内层SNI路由到真实站点，所以站点自身没下发ECH记录也能用）。
   *
   * @returns {Promise<null|object>} 形如 `{ echConfigList, publicName, config, ttl, dnsName, dnsType }`
   */
  async lookupEch (dnsConfig, hostname) {
    if (dnsConfig == null || dnsConfig.dnsMap == null || dnsConfig.ech == null || dnsConfig.ech.enabled === false) {
      return null
    }

    const ech = await this.lookupDomainEch(dnsConfig, hostname)
    if (ech != null) {
      return ech
    }

    const publicName = dnsConfig.ech.publicName
    if (publicName == null || publicName === '' || publicName === hostname) {
      return null
    }

    const shared = await this.lookupDomainEch(dnsConfig, publicName)
    if (shared != null) {
      log.info(`[ECH] ${hostname} 未下发ECH记录，改用共享ECH配置: public_name: ${shared.publicName}`)
    }
    return shared
  },

  /**
   * 只获取该域名由DNS下发的ECH参数（不含共享ECH配置的兜底逻辑）
   *
   * 配置了ECH专用DNS（`server.dns.ech.dns`）时，只从该DNS获取；
   * 否则优先使用该域名映射到的DNS，若该DNS未下发ech参数，则依次尝试其它支持ECH的DNS
   *
   * @returns {Promise<null|object>} 形如 `{ echConfigList, publicName, config, ttl, dnsName, dnsType }`
   */
  async lookupDomainEch (dnsConfig, hostname) {
    // 指定了ECH专用DNS：只查询该DNS，避免其它DNS的超时阶梯拖慢建连过程
    const echDns = this.getEchDNS(dnsConfig)
    if (echDns != null) {
      if (!echDns.echEnabled) {
        log.warn(`[ECH] ECH专用DNS '${echDns.dnsName}' 未启用ECH查询，无法获取ECH参数: ${hostname}`)
        return null
      }
      return await echDns.lookupEch(hostname).catch((e) => {
        log.warn(`[ECH][DNS-over-${echDns.dnsType} '${echDns.dnsName}'] 获取ECH参数失败: ${hostname}, error: ${e.message}`)
        return null
      })
    }

    const candidates = []

    // 1. 该域名映射到的DNS
    const dnsData = this.getDNSAndFamily(dnsConfig, hostname)
    if (dnsData != null && dnsData.dns != null) {
      candidates.push(dnsData.dns)
    }

    if (dnsConfig.ech.tryAllProviders !== false) {
      // 2. 默认用于SNI的DNS
      if (dnsConfig.dnsMap.ForSNI != null) {
        candidates.push(dnsConfig.dnsMap.ForSNI)
      }

      // 3. 其它DNS
      for (const dnsName of Object.keys(dnsConfig.dnsMap)) {
        candidates.push(dnsConfig.dnsMap[dnsName])
      }
    }

    const dnsList = []
    const tried = new Set()
    for (const dns of candidates) {
      if (dns == null || tried.has(dns) || !dns.echEnabled) {
        continue
      }
      tried.add(dns)
      dnsList.push(dns)
    }

    if (dnsList.length === 0) {
      return null
    }

    // 并发查询：映射的DNS优先查询，其余DNS延迟一小段时间后并发查询，取最先返回的结果。
    // 原因：串行查询时，前面DNS的超时（如DoT 4秒、本机DNS 5秒）会拖慢整个建连过程，导致代理请求超时。
    const parallelDelay = Number.parseInt(dnsConfig.ech.parallelDelay, 10)
    const delay = Number.isNaN(parallelDelay) || parallelDelay < 0 ? 200 : parallelDelay

    return await new Promise((resolve) => {
      let pending = dnsList.length
      const done = (ech) => {
        if (ech != null) {
          resolve(ech)
        } else if (--pending === 0) {
          resolve(null)
        }
      }
      dnsList.forEach((dns, index) => {
        const query = () => {
          dns.lookupEch(hostname)
            .then(done)
            .catch((e) => {
              log.warn(`[ECH][DNS-over-${dns.dnsType} '${dns.dnsName}'] 获取ECH参数失败: ${hostname}, error: ${e.message}`)
              done(null)
            })
        }
        if (index === 0 || delay === 0) {
          query()
        } else {
          setTimeout(query, delay)
        }
      })
    })
  },
}

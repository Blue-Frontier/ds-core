const matchUtil = require('../../utils/util.match')
const echDomainUtil = require('../proxy/common/ech/domain')
const ipUtil = require('./util.ip')
const log = require('../../utils/util.log.server')
const DNSOverPreSetIpList = require('./preset.js')
const DNSOverNat64 = require('./nat64.js')
const DNSOverHTTPS = require('./https.js')
const DNSOverTLS = require('./tls.js')
const DNSOverTCP = require('./tcp.js')
const DNSOverUDP = require('./udp.js')

module.exports = {
  /**
   * @param dnsProviders DNS服务列表
   * @param preSetIpList 预设IP列表
   * @param options 选项，其中 `options.ech` 为 ECH配置（RFC 9848），形如 `{ enabled, cacheSize, emptyTtl, minTtl, maxTtl }`；
   *                `options.nat64` 为 NAT64配置，形如 `{ enabled, prefix, domains, doh, bootstrap }`
   */
  initDNS (dnsProviders, preSetIpList, options = {}) {
    const dnsMap = {}
    const echOptions = options.ech || {}
    const nat64Options = options.nat64 || {}

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

    // 创建 NAT64 的DNS：把域名解析出的真实IPv4嵌入NAT64前缀，得到可直连的IPv6地址
    if (nat64Options.enabled === true) {
      // providers 传入供「解析用DNS」使用（与「ECH专用DNS」的设置方式一致）
      const nat64Dns = new DNSOverNat64({ ...nat64Options, providers: dnsProviders }, preSetIpList)
      dnsMap.Nat64 = nat64Dns
      if (nat64Dns.initEch != null) {
        // NAT64通道同样可以查询HTTPS记录，作为ECH参数的来源之一
        nat64Dns.initEch({
          ...echOptions,
          enabled: echOptions.enabled !== false && nat64Options.ech !== false,
        })
      }
      log.info(`已启用NAT64：域名 ${JSON.stringify(nat64Options.domains)}, 前缀: ${nat64Dns.prefix}, 解析用DNS: ${nat64Options.dns || '默认'}, DoH: ${nat64Dns.dohList.join(' | ')}`)
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
    if (this.isNat64Domain(dnsConfig, hostname)) {
      // NAT64域名（把真实IPv4嵌进NAT64前缀直连）一律按ECH域名处理：
      // 必须用真实SNI完成ECH握手，否则明文SNI会被中间网络重置
      return true
    }
    if (dnsConfig == null || dnsConfig.ech == null) {
      return false
    }
    if (dnsConfig.ech.enabled === false || dnsConfig.ech.use === false) {
      return false
    }
    return echDomainUtil.isEchDomain(dnsConfig.echDomains, hostname)
  },

  /**
   * 该域名是否走 NAT64 直连（域名在 `server.dns.nat64.domains` 名单中，且NAT64已启用）
   *
   * 走NAT64的域名一律用NAT64通道解析IP（本网络的常规DNS可能被投毒、直连DoH被阻断），
   * 且会被当作ECH域名（在 `options.js` 中并入ECH名单）：自动拦截、跳过增强模式、上游TLS使用ECH。
   */
  isNat64Domain (dnsConfig, hostname) {
    if (dnsConfig == null || dnsConfig.dnsMap == null || dnsConfig.dnsMap.Nat64 == null) {
      return false
    }
    return echDomainUtil.isEchDomain(dnsConfig.nat64Domains, hostname)
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
   *
   * 注：忽略预设IP不等于完全不用——ECH专用DNS解析不出可用IP时会回退到预设IP
   * （回退逻辑在 `proxy/mitmproxy/dnsLookup.js`）。
   */
  isEchIgnorePreSetIp (dnsConfig, hostname) {
    if (this.isNat64Domain(dnsConfig, hostname)) {
      // NAT64域名：优先用NAT64通道动态解析，「预设IP」只在解析失败时作为回退
      // （回退逻辑在 dnsLookup.js，需要 ignorePreSetIpList=true 才会启用 preSetDns 回退）
      return true
    }
    if (dnsConfig == null || dnsConfig.ech == null) {
      return true
    }
    return !echDomainUtil.isEchDomain(dnsConfig.echPreSetIpDomains, hostname)
  },

  getDNSAndFamily (dnsConfig, hostname) {
    const isEchDomain = this.isEchDomain(dnsConfig, hostname)
    // ECH域名的「预设IP」例外：强制优先使用预设IP
    const echForcePreSetIp = isEchDomain && !this.isEchIgnorePreSetIp(dnsConfig, hostname)

    // 0. NAT64域名：用NAT64通道解析（域名在本网络可能被投毒或阻断，只有NAT64通道能拿到真实IP）
    if (this.isNat64Domain(dnsConfig, hostname)) {
      return {
        dns: dnsConfig.dnsMap.Nat64,
      }
    }

    // 1. 匹配 预设IP配置
    // ECH域名默认强制忽略预设IP（改用ECH指定的DNS解析，解析不出可用IP时由 dnsLookup 回退到预设IP），
    // 例外名单（`server.dns.ech.preSetIpDomains`）里的域名则强制优先使用预设IP
    if (!isEchDomain || echForcePreSetIp) {
      const hostnamePreSetIpList = matchUtil.matchHostname(dnsConfig.preSetIpList, hostname, 'matched preSetIpList(getDNSAndFamily)')
      if (hostnamePreSetIpList) {
        return {
          dns: dnsConfig.dnsMap.PreSet,
        }
      }
    }

    // 2. ECH域名优先使用ECH指定的DNS
    if (isEchDomain) {
      const echDns = this.getEchDNS(dnsConfig)
      if (echDns != null) {
        return {
          dns: echDns,
        }
      }
    }

    // 3. 读取域名对应的DNS配置
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

  /**
   * ECH握手成功/失败后，把该IP计入相关DNS的优选统计（用于把域名切换到ECH可用的IP）
   *
   * 同一个域名的不同IP上ECH的可用性可能不同（边缘节点不支持ECH、或该IP被针对性干扰），
   * 而ECH握手失败以前不会反馈给DNS，导致IP优选结果只能按「慢/超时」调整，ECH命中率不稳定。
   *
   * ECH域名只会用「ECH专用DNS」或「预设IP」的解析结果，所以只反馈给这两个DNS，
   * 不波及 local/aliyun 等其它DNS的IP优选结果；没有该域名缓存的DNS会自动忽略这次计数。
   *
   * @param dnsConfig DNS配置
   * @param hostname 域名
   * @param ip 本次ECH连接使用的IP
   * @param isError true=记失败（连续失败后会切换到下一个IP），false=记成功（重置连续失败计数）
   * @param reason 计入失败的原因（仅用于日志）
   */
  countEchIp (dnsConfig, hostname, ip, isError, reason) {
    if (dnsConfig == null || hostname == null || ip == null || ip === hostname) {
      return
    }

    const dnsList = [this.getEchDNS(dnsConfig)]
    if (dnsConfig.dnsMap != null && dnsConfig.dnsMap.PreSet != null) {
      dnsList.push(dnsConfig.dnsMap.PreSet)
    }
    if (dnsConfig.dnsMap != null && dnsConfig.dnsMap.Nat64 != null) {
      // NAT64域名用的IP来自NAT64通道，失败反馈要记到它自己的IP缓存里，才能切换到下一个IP
      dnsList.push(dnsConfig.dnsMap.Nat64)
    }

    let counted = false
    for (const dns of dnsList) {
      if (dns == null) {
        continue
      }
      dns.count(hostname, ip, isError)
      counted = true
    }

    if (!counted) {
      return
    }
    if (isError) {
      log.error(`记录ip失败次数，用于优选ip！ hostname: ${hostname}, ip: ${ip}, reason: ${reason}, dns: ECH`)
    } else {
      log.debug(`记录ip成功次数，用于优选ip！ hostname: ${hostname}, ip: ${ip}, dns: ECH`)
    }
  },
}

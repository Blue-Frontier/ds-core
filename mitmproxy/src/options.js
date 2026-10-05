const fs = require('node:fs')
const path = require('node:path')
const lodash = require('lodash')
const { LRUCache } = require('lru-cache')
const dnsUtil = require('./lib/dns')
const echDomainUtil = require('./lib/proxy/common/ech/domain')
const interceptorImpls = require('./lib/interceptor')
const scriptInterceptor = require('./lib/interceptor/impl/res/script')
const { getTmpPacFilePath, downloadPacAsync, createOverwallMiddleware } = require('./lib/proxy/middleware/overwall')
const log = require('./utils/util.log.server')
const matchUtil = require('./utils/util.match')

// 每个域名的路径级拦截器缓存的最大条数。
// 对于使用 .* 路径模式的域名（如 api.github.com），每个唯一 URL（含不同 query string）都会生成独立的缓存条目。
// 设置上限，超出后清空最久未使用的缓存，防止长期运行时因 API 分页/唯一 token 等导致内存无界增长。
const PATH_CACHE_MAX_SIZE = 512

// ECH域名需要强制忽略的拦截器：
// ECH握手必须使用真实SNI，因此 `sni` 拦截器（改写/禁用SNI）对ECH域名一律不生效
const ECH_IGNORED_INTERCEPTORS = new Set(['sni'])

// 处理拦截配置
function buildIntercepts (intercepts) {
  // 自动生成script拦截器所需的辅助配置，降低使用`script拦截器`配置绝对地址和相对地址时的门槛
  scriptInterceptor.handleScriptInterceptConfig(intercepts)

  return intercepts
}

// 从拦截器配置中，获取exclusions字段，返回数组类型
function getExclusionArray (exclusions) {
  let ret = null
  if (Array.isArray(exclusions)) {
    if (exclusions.length > 0) {
      ret = exclusions
    }
  } else if (lodash.isObject(exclusions)) {
    ret = []
    for (const exclusion in exclusions) {
      ret.push(exclusion)
    }
    if (ret.length === 0) {
      return null
    }
  }
  return ret
}

function handleDnsMapping (dnsMapping, familyMapping) {
  // 循环读取所有key value
  for (const hostname in dnsMapping) {
    const value = dnsMapping[hostname]
    if (value == null) {
      delete dnsMapping[hostname]
      continue
    }

    if (typeof value === 'string') {
      dnsMapping[hostname] = {
        dnsName: value,
        family: Number.parseInt(familyMapping[hostname]) === 6 ? 6 : 4,
      }
    } else if (value.dnsName == null) {
      log.warn(`域名 ${hostname} 的DNS配置有误，未配置dnsName，配置值：`, value)
      delete dnsMapping[hostname]
    }
  }

  return dnsMapping
}

module.exports = (serverConfig) => {
  const intercepts = matchUtil.domainMapRegexply(buildIntercepts(serverConfig.intercepts))
  const whiteList = matchUtil.domainMapRegexply(serverConfig.whiteList)
  const timeoutMapping = matchUtil.domainMapRegexply(serverConfig.setting.timeoutMapping)

  const dnsMapping = handleDnsMapping(serverConfig.dns.mapping, serverConfig.dns.familyMapping || {})
  const setting = serverConfig.setting

  if (!setting.script.dirAbsolutePath) {
    setting.script.dirAbsolutePath = path.join(setting.rootDir, setting.script.defaultDir)
  }
  if (setting.verifySsl !== false) {
    setting.verifySsl = true
  }
  setting.timeoutMapping = timeoutMapping

  const overWallConfig = serverConfig.plugin.overwall
  if (overWallConfig.pac && overWallConfig.pac.enabled) {
    const pacConfig = overWallConfig.pac

    // 自动更新 pac.txt
    if (!pacConfig.pacFileAbsolutePath && pacConfig.autoUpdate) {
      // 异步下载远程 pac.txt 文件，并保存到本地；下载成功后，需要重启代理服务才会生效
      downloadPacAsync(pacConfig)
    }

    // 优先使用本地已下载的 pac.txt 文件
    if (!pacConfig.pacFileAbsolutePath && fs.existsSync(getTmpPacFilePath())) {
      pacConfig.pacFileAbsolutePath = getTmpPacFilePath()
      log.info('读取已下载的 pac.txt 文件:', pacConfig.pacFileAbsolutePath)
    }

    if (!pacConfig.pacFileAbsolutePath) {
      log.info('setting.rootDir:', setting.rootDir)
      pacConfig.pacFileAbsolutePath = path.join(setting.rootDir, pacConfig.pacFilePath)
      log.info('读取内置的 pac.txt 文件:', pacConfig.pacFileAbsolutePath)
      if (pacConfig.autoUpdate) {
        log.warn('远程 pac.txt 文件下载失败或还在下载中，现使用内置 pac.txt 文件:', pacConfig.pacFileAbsolutePath)
      }
    }
  }

  // 插件列表
  const middlewares = []

  const preSetIpList = matchUtil.domainMapRegexply(serverConfig.preSetIpList)

  // ECH配置（RFC 9848）：通过DNS的HTTPS(65)记录获取 ech 参数，用于上游TLS握手
  const dnsEchConfig = serverConfig.dns.ech || {}

  // NAT64配置：把（可能被投毒/阻断的）域名解析成真实IPv4后嵌入NAT64前缀，走IPv6直连
  const nat64Config = serverConfig.dns.nat64 || {}
  // NAT64 前缀必须由使用者配置：不内置任何公共 NAT64 网关（流量经该网关转发，属第三方中转）
  const nat64Prefix = String(nat64Config.prefix || '').trim()
  const nat64Declared = nat64Config.enabled === true
    && Array.isArray(nat64Config.domains) && nat64Config.domains.length > 0
  if (nat64Declared && nat64Prefix === '') {
    log.warn('已启用 NAT64 但未配置「NAT64前缀」（server.dns.nat64.prefix），NAT64 不会生效；请填写所使用的 NAT64 服务提供的前缀')
  }
  const isNat64Enabled = nat64Declared && nat64Prefix !== ''
  const nat64DomainMap = isNat64Enabled ? echDomainUtil.createEchDomainMap(nat64Config) : null
  // NAT64域名必须使用ECH（SNI被加密才不会被中间网络重置），因此并入ECH域名名单：
  // 这样它们会自动被拦截（MITM）、跳过增强模式、忽略SNI改写与预设IP
  const echConfig = isNat64Enabled
    ? { ...dnsEchConfig, domains: { ...echDomainUtil.toHostMap(dnsEchConfig.domains), ...echDomainUtil.toHostMap(nat64Config.domains) } }
    : dnsEchConfig

  // ECH域名匹配表：ECH域名会强制忽略预设IP、SNI改写等常规配置，这里先解析一次
  const echDomainMap = echDomainUtil.createEchDomainMap(echConfig)
  // ECH域名中允许使用预设IP与IP测速的例外名单（默认全部忽略预设IP）
  const echPreSetIpDomainMap = echDomainUtil.createEchDomainMap({ domains: echConfig.preSetIpDomains })
  const isEchEnabled = echConfig.enabled !== false && echConfig.use !== false
  // NAT64域名必须被拦截（MITM）才能走NAT64直连并使用ECH，与ECH开关无关
  const checkNat64Domain = hostname => isNat64Enabled && echDomainUtil.isEchDomain(nat64DomainMap, hostname)
  const checkEchDomain = hostname => checkNat64Domain(hostname) || (isEchEnabled && echDomainUtil.isEchDomain(echDomainMap, hostname))

  // 增强功能插件：如果启用了，则添加到插件列表中
  // 注：ECH域名不会进入增强模式的反代路径（由 checkEchDomain 判断），必须直连才能使用ECH
  const overwallMiddleware = createOverwallMiddleware(overWallConfig, { checkEchDomain })
  if (overwallMiddleware) {
    middlewares.push(overwallMiddleware)
  }

  const options = {
    host: serverConfig.host,
    port: serverConfig.port,
    maxLength: serverConfig.fakeServerMaxLength,
    dnsConfig: {
      preSetIpList,
      dnsMap: dnsUtil.initDNS(serverConfig.dns.providers, preSetIpList, {
        ech: echConfig,
        nat64: { ...nat64Config, enabled: isNat64Enabled },
      }),
      mapping: matchUtil.domainMapRegexply(dnsMapping),
      speedTest: serverConfig.dns.speedTest,
      ech: echConfig,
      echDomains: echDomainMap,
      echPreSetIpDomains: echPreSetIpDomainMap,
      nat64Domains: nat64DomainMap,
    },
    setting,
    compatibleConfig: {
      connect: serverConfig.compatible ? matchUtil.domainMapRegexply(serverConfig.compatible.connect) : {},
      request: serverConfig.compatible ? matchUtil.domainMapRegexply(serverConfig.compatible.request) : {},
    },
    middlewares,
    sslConnectInterceptor: (req, cltSocket, head) => {
      const hostname = req.url.split(':')[0]

      // 配置了白名单的域名，将跳过代理
      const inWhiteList = !!matchUtil.matchHostname(whiteList, hostname, 'in whiteList')
      if (inWhiteList) {
        log.info(`为白名单域名，不拦截: ${hostname}`)
        return false // 不拦截
      }

      // 配置了拦截的域名，将会被代理
      const matched = matchUtil.matchHostname(intercepts, hostname, 'matched intercepts')
      if ((!!matched) === true) {
        log.debug(`拦截器拦截：${req.url}, matched:`, matched)
        return matched // 拦截
      }

      // ECH域名：必须被拦截（MITM）才能在上游TLS握手中使用ECH，即使没有配置拦截器
      if (checkEchDomain(hostname)) {
        log.info(`为ECH域名，拦截: ${hostname}`)
        return true // 拦截
      }

      return null // 不在白名单中，也未配置在拦截功能中，跳过当前拦截器，由下一个拦截器判断
    },
    createIntercepts: (context) => {
      const rOptions = context.rOptions
      const interceptOpts = matchUtil.matchHostnameAll(intercepts, rOptions.hostname, 'get interceptOpts')
      if (!interceptOpts) { // 该域名没有配置拦截器，直接过
        return
      }

      // 获取缓存：同一 hostname+path 的拦截器列表是固定的，不必每次重新构建
      // 注：缓存 key 使用完整路径（含 query string），以保证正则捕获组（matched）的正确性
      // 注：采用 LRU 淘汰策略，上限为 PATH_CACHE_MAX_SIZE 条；利用 Map 按插入顺序迭代的特性，命中时删除后重新插入以更新位置
      if (!interceptOpts._pathCache) {
        const cache = new LRUCache({
          maxSize: PATH_CACHE_MAX_SIZE,
          sizeCalculation: () => {
            return 1
          },
        })
        Object.defineProperty(interceptOpts, '_pathCache', { value: cache, enumerable: false, configurable: true })
      } else {
        const cached = interceptOpts._pathCache.get(rOptions.path)
        if (cached) {
          return cached
        }
      }

      const matchIntercepts = []
      const matchInterceptsOpts = {}
      // ECH域名：强制忽略会破坏ECH握手的拦截器（如 sni 改写）
      const isEchDomain = checkEchDomain(rOptions.hostname)
      for (const regexp in interceptOpts) { // 遍历拦截配置
        // 跳过hostname匹配结果，它不是路径正则
        if (regexp === 'matched') {
          continue
        }
        // 判断是否匹配拦截器
        const matched = matchUtil.isMatched(rOptions.path, regexp)
        if (matched == null) { // 拦截器匹配失败
          continue
        }

        // 获取拦截器
        const interceptOpt = interceptOpts[regexp]
        interceptOpt.key = regexp

        // 添加exclusions字段，用于排除某些路径
        // @since 1.8.5
        if (interceptOpt.exclusions) {
          let isExcluded = false
          try {
            const exclusions = getExclusionArray(interceptOpt.exclusions)
            if (exclusions) {
              for (const exclusion of exclusions) {
                if (matchUtil.isMatched(rOptions.path, exclusion)) {
                  log.debug(`拦截器配置排除了path：${rOptions.protocol}//${rOptions.hostname}:${rOptions.port}${rOptions.path}, exclusion: '${exclusion}', interceptOpt:`, interceptOpt)
                  isExcluded = true
                }
              }
            }
          } catch (e) {
            log.error(`判断拦截器是否排除当前path时出现异常, path: ${rOptions.path}, interceptOpt:`, interceptOpt, ', error:', e)
          }
          if (isExcluded) {
            continue
          }
        }

        log.debug(`拦截器匹配path成功：${rOptions.protocol}//${rOptions.hostname}:${rOptions.port}${rOptions.path}, regexp: ${regexp}, interceptOpt:`, interceptOpt)

        // log.info(`interceptor matched, regexp: '${regexp}' =>`, JSON.stringify(interceptOpt), ', url:', url)
        for (const impl of interceptorImpls) {
          // ECH域名：ECH握手必须使用真实SNI，忽略 sni 等会与ECH冲突的拦截器
          if (isEchDomain && ECH_IGNORED_INTERCEPTORS.has(impl.name)) {
            log.info(`ECH域名忽略拦截器 '${impl.name}': ${rOptions.hostname}`)
            continue
          }

          // 根据拦截配置挑选合适的拦截器来处理
          if (impl.is && impl.is(interceptOpt)) {
            let action = 'add'

            // 如果存在同名拦截器，则order值越大，优先级越高
            const matchedInterceptOpt = matchInterceptsOpts[impl.name]
            if (matchedInterceptOpt) {
              if (matchedInterceptOpt.order >= (interceptOpt.order || 0)) {
                log.warn(`duplicate interceptor: ${impl.name}, hostname: ${rOptions.hostname}`)
                continue
              }
              action = 'replace'
            }

            const interceptor = { name: impl.name, priority: impl.priority }
            if (impl.requestIntercept) {
              // req拦截器
              interceptor.requestIntercept = (context, req, res, ssl, next) => {
                return impl.requestIntercept(context, interceptOpt, req, res, ssl, next, matched, interceptOpts.matched)
              }
            } else if (impl.responseIntercept) {
              // res拦截器
              interceptor.responseIntercept = (context, req, res, proxyReq, proxyRes, ssl, next) => {
                return impl.responseIntercept(context, interceptOpt, req, res, proxyReq, proxyRes, ssl, next, matched, interceptOpts.matched)
              }
            }

            // log.info(`${action} interceptor: ${impl.name}, hostname: ${rOptions.hostname}, regexp: ${regexp}`)
            if (action === 'add') {
              matchIntercepts.push(interceptor)
            } else {
              matchIntercepts[matchedInterceptOpt.index] = interceptor
            }
            matchInterceptsOpts[impl.name] = {
              order: interceptOpt.order || 0,
              index: action === 'replace' ? matchedInterceptOpt.index : matchIntercepts.length - 1,
            }
          }
        }
      }

      matchIntercepts.sort((a, b) => {
        return a.priority - b.priority
      })
      // for (const interceptor of matchIntercepts) {
      //   log.info('interceptor:', interceptor.name, 'priority:', interceptor.priority)
      // }

      // 设置缓存
      interceptOpts._pathCache.set(rOptions.path, matchIntercepts)

      return matchIntercepts
    },
  }

  if (setting.rootCaFile) {
    options.caCertPath = setting.rootCaFile.certPath
    options.caKeyPath = setting.rootCaFile.keyPath
  }
  return options
}

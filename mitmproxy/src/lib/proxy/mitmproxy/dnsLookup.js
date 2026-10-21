const defaultDns = require('node:dns')
const net = require('node:net')
const log = require('../../../utils/util.log.server')
const speedTest = require('../../speed')
const cloudflareRoute = require('../../cloudflareRoute')
const trafficMonitor = require('../../traffic/TrafficMonitor')
const { isZeroIp } = require('../../dns/util.ip')

// HTTP/2 头值只允许 ASCII 可见字符，需过滤中文等非 ASCII 字符
function safeHeaderValue (value) {
  return String(value).replace(/[^\x20-\x7E]/g, '')
}

function isValidIpAddress (ip) {
  return typeof ip === 'string' && net.isIP(ip) !== 0
}

function getAddressFamily (ip) {
  return net.isIP(ip) === 6 ? 6 : 4
}

// DNS 返回的全部地址都是零 IP（0.0.0.0 / ::）时，判定为 Adblock 拦截，通知流量统计忽略该域名
function markBlockedIfAllZero (hostname, address) {
  const list = Array.isArray(address) ? address : [address]
  if (list.length === 0) {
    return
  }
  const allZero = list.every((item) => {
    const ip = item && item.address ? item.address : item
    return isZeroIp(ip)
  })
  if (allZero) {
    trafficMonitor.markBlocked(hostname)
  }
}

function rewriteCloudflareIp (hostname, ip, isPreSet) {
  if (!isValidIpAddress(ip)) {
    return ip
  }
  // 预设 IP 优先级最高，不参与 Cloudflare 路由重定向
  if (isPreSet) {
    return ip
  }
  const rewritten = cloudflareRoute.rewriteIp(ip, hostname)
  if (rewritten !== ip) {
    log.info(`[cloudflare-route] 命中 Cloudflare IP 段，重写: ${hostname}: ${ip} -> ${rewritten}`)
  }
  return rewritten
}

function respondLookup (callback, ip, family, all) {
  if (all) {
    callback(null, [{ address: ip, family }])
    return
  }

  callback(null, ip, family)
}

function createIpChecker (tester) {
  if (!tester || tester.backupList == null || tester.backupList.length === 0) {
    return null
  }

  return (ip) => {
    for (let i = 0; i < tester.backupList.length; i++) {
      const item = tester.backupList[i]
      if (item.host === ip) {
        // 先判断失败标记：失败 IP 在重新测速成功前不再被回退 DNS 选用
        if (item.status === 'failed') {
          return false // IP测速失败
        }
        if (item.time > 0) {
          return true // IP测速成功
        }
        break
      }
    }

    return true // IP测速未知
  }
}

module.exports = {
  // options.ignorePreSetIpList: ECH域名强制忽略预设IP（预设IP通常是域名自身的源站IP，不支持ECH）
  // options.ignoreSpeedTest: ECH域名强制忽略IP测速结果（测速池同样可能来自预设IP或其它DNS）
  // options.preSetDns: ECH域名在「ECH专用DNS解析不出可用IP」时用于回退的预设IP的DNS实例（null 表示不回退）
  // options.resetOnHostnameFallback: ECH域名在IP地址缓存退化为「域名兜底项」时，重置失败计数重新使用真实IP
  createLookupFunc (res, dnsAndFamily, action, target, port, isDnsIntercept, options = {}) {
    target = target ? (`, target: ${target}`) : ''

    const dns = dnsAndFamily.dns
    const family = Number.parseInt(dnsAndFamily.family) === 6 ? 6 : 4
    const ignorePreSetIpList = options.ignorePreSetIpList === true
    const ignoreSpeedTest = options.ignoreSpeedTest === true
    const preSetDns = options.preSetDns || null
    const resetOnHostnameFallback = options.resetOnHostnameFallback === true
    // 主 DNS（可能是「预设IP」）解析不出结果时的兜底提供方，见 dns/index.js 的 getFallbackDnsList
    const fallbackDnsList = Array.isArray(options.fallbackDnsList) ? options.fallbackDnsList : []

    return (hostname, options, callback) => {
      const all = options && options.all === true
      const defaultLookup = (options, callback) => {
        defaultDns.lookup(hostname, options, (err, address, family) => {
          if (!err) {
            markBlockedIfAllZero(hostname, address)
            if (Array.isArray(address)) {
              address = address.map((item) => {
                const newIp = rewriteCloudflareIp(hostname, item.address)
                return { address: newIp, family: getAddressFamily(newIp) }
              })
            } else {
              address = rewriteCloudflareIp(hostname, address)
              family = getAddressFamily(address)
            }
            if (res) {
              const first = Array.isArray(address) ? address[0] : { address, family }
              if (first && isValidIpAddress(first.address)) {
                res.setHeader('DS-DNS', `default: ${first.address} (IPv${first.family})`)
              }
            }
          }
          callback(err, address, family)
        })
      }
      const tester = ignoreSpeedTest ? null : speedTest.getSpeedTester(hostname, port)
      if (tester) {
        const aliveIpObj = tester.pickFastAliveIpObj()
        if (aliveIpObj && isValidIpAddress(aliveIpObj.host) && !isZeroIp(aliveIpObj.host)) {
          const addressFamily = getAddressFamily(aliveIpObj.host)
          log.info(`----- ${action}: ${hostname}, use alive ip from dns '${aliveIpObj.dns}': ${aliveIpObj.host}${target} -----`)
          if (isDnsIntercept) {
            isDnsIntercept.dns = dns
            isDnsIntercept.hostname = hostname
            isDnsIntercept.ip = aliveIpObj.host
            isDnsIntercept.tester = tester
          }
          if (res) {
            const dnsLabel = aliveIpObj.dns === '预设IP' ? 'PreSet' : safeHeaderValue(aliveIpObj.dns)
            res.setHeader('DS-DNS', `${dnsLabel}: ${aliveIpObj.host} (IPv${addressFamily})`)
          }
          respondLookup(callback, aliveIpObj.host, addressFamily, all)
          return
        } else {
          log.info(`----- ${action}: ${hostname}, no valid alive ip${target}, tester: { "ready": ${tester.ready}, "backupList": ${JSON.stringify(tester.backupList)} }`)
        }
      }

      const ipChecker = createIpChecker(tester)

      // 无已测速的存活 IP，轮转分配未失败 IP 逐个探测，并发请求自动分散
      if (tester && tester.backupList.length > 0) {
        const probe = tester.pickNextForProbing()
        if (probe && isValidIpAddress(probe.host) && !isZeroIp(probe.host)) {
          const addressFamily = getAddressFamily(probe.host)
          log.info(`----- ${action}: ${hostname}, use probing ip: ${probe.host} (family: ${addressFamily})${target} -----`)
          if (isDnsIntercept) {
            isDnsIntercept.dns = dns
            isDnsIntercept.hostname = hostname
            isDnsIntercept.ip = probe.host
            isDnsIntercept.tester = tester
          }
          if (res) {
            const dnsLabel = probe.dns === '预设IP' ? 'PreSet' : safeHeaderValue(probe.dns)
            res.setHeader('DS-DNS', `${dnsLabel}: ${probe.host} (IPv${addressFamily})`)
          }
          respondLookup(callback, probe.host, addressFamily, all)
          return
        }
      }

      // ECH域名：ECH专用DNS解析不出可用IP时（DNS查询失败、没查到地址、缓存里的真实IP都失败了），回退到「预设IP」
      const resolvePreSetIp = async () => {
        if (preSetDns == null) {
          return null
        }
        try {
          // 预设IP的缓存同样会退化为域名兜底项（预设IP失败后），这里一并重置，否则回退拿不到可用IP
          const preSetIp = await preSetDns.lookup(hostname, { family, resetOnHostnameFallback })
          if (preSetIp != null && preSetIp !== hostname && isValidIpAddress(preSetIp)) {
            log.info(`----- ${action}: ${hostname}, ECH专用DNS未解析出可用IP，回退预设IP: ${preSetIp}${target} -----`)
            return preSetIp
          }
        } catch (e) {
          log.warn(`----- ${action}: ${hostname}, ECH专用DNS未解析出可用IP，回退预设IP失败${target}, error:`, e)
        }
        return null
      }

      // 主 DNS 解析不出结果时，先用其它已配置的 DNS 提供方做一次真实解析，再决定是否交给系统 DNS。
      // 预设IP 这类只在表里查的实例解析不出境外域名时会把请求推给系统 DNS，而国内系统 DNS 常返回
      // EAI_AGAIN，自动重试又会重复同一条链，因此在这里给出一条能真正解析的退路。
      const resolveByFallbackDns = async () => {
        for (const fallbackDns of fallbackDnsList) {
          if (fallbackDns == null || fallbackDns === dns) {
            continue
          }
          try {
            const fallbackIp = await fallbackDns.lookup(hostname, { family, resetOnHostnameFallback })
            if (fallbackIp != null && fallbackIp !== hostname && isValidIpAddress(fallbackIp)) {
              return { ip: fallbackIp, dnsName: fallbackDns.dnsName }
            }
          } catch (e) {
            log.warn(`----- ${action}: ${hostname}, 兜底 DNS '${fallbackDns.dnsName}' 解析失败${target}, error:`, e)
          }
        }
        return null
      }

      const useDefaultDns = async () => {
        const fallback = await resolveByFallbackDns()
        if (fallback != null) {
          markBlockedIfAllZero(hostname, fallback.ip)
          const fallbackFamily = getAddressFamily(fallback.ip)
          log.info(`----- ${action}: ${hostname}, 主 DNS 未解析出结果，改用 '${fallback.dnsName}': ${fallback.ip}(family: ${fallbackFamily})${target} -----`)
          if (res) {
            res.setHeader('DS-DNS', `${safeHeaderValue(fallback.dnsName)}: ${fallback.ip} (IPv${fallbackFamily})`)
          }
          respondLookup(callback, fallback.ip, fallbackFamily, all)
          return
        }
        // 不继承原 family 选项：强制 IPv6 时若系统 DNS 无 AAAA，会误报 ENOTFOUND，此时应允许系统 DNS 返回 IPv4
        const defaultOptions = { ...options }
        delete defaultOptions.family
        defaultLookup(defaultOptions, callback)
      }

      dns.lookup(hostname, { ipChecker, family, ignorePreSetIpList, resetOnHostnameFallback }).then(async (ip) => {
        let usedDns = dns
        if (preSetDns != null && (ip == null || ip === hostname || !isValidIpAddress(ip))) {
          const preSetIp = await resolvePreSetIp()
          if (preSetIp != null) {
            ip = preSetIp
            usedDns = preSetDns
          }
        }
        if (ip !== hostname && isValidIpAddress(ip)) {
          markBlockedIfAllZero(hostname, ip)
          ip = rewriteCloudflareIp(hostname, ip, usedDns && usedDns.dnsName === 'PreSet')
          const addressFamily = getAddressFamily(ip)
          if (isDnsIntercept) {
            isDnsIntercept.dns = usedDns
            isDnsIntercept.hostname = hostname
            isDnsIntercept.ip = ip
            if (tester) {
              isDnsIntercept.tester = tester
            }
          }
          log.info(`----- ${action}: ${hostname}, use ip from dns '${usedDns.dnsName}': ${ip}(family: ${addressFamily})${target} -----`)
          if (res) {
            const dnsLabel = usedDns.dnsName === '预设IP' ? 'PreSet' : safeHeaderValue(usedDns.dnsName)
            res.setHeader('DS-DNS', `${dnsLabel}: ${ip} (IPv${addressFamily})`)
          }
          respondLookup(callback, ip, addressFamily, all)
        } else {
          // 主 DNS 没给出可用 IP：先兜底到其它 DNS 提供方，再退回系统 DNS
          if (ip != null && ip !== hostname && !isValidIpAddress(ip)) {
            log.warn(`----- ${action}: ${hostname}, dns returned invalid ip '${ip}'${target}, fallback to default DNS`)
          }
          await useDefaultDns()
        }
      }).catch(async (err) => {
        log.error(`----- ${action}: ${hostname}, dns lookup error${target}, options:`, options, `, error:`, err)
        await useDefaultDns()
      })
    }
  },

  // 未配置自定义 DNS 时，使用系统默认 DNS 解析，并捕获 IP 写入响应头。
  // fallbackDnsList 非空时，系统 DNS 失败（如国内解析境外域名的 EAI_AGAIN）会先用这些提供方兜底一次。
  createDefaultLookupFunc (res, action, target, fallbackDnsList) {
    target = target ? `, target: ${target}` : ''
    const dnsList = Array.isArray(fallbackDnsList) ? fallbackDnsList : []

    return (hostname, options, callback) => {
      const useFallbackDns = async (err) => {
        for (const fallbackDns of dnsList) {
          try {
            const fallbackIp = await fallbackDns.lookup(hostname, {})
            if (fallbackIp != null && fallbackIp !== hostname && isValidIpAddress(fallbackIp)) {
              const fallbackFamily = getAddressFamily(fallbackIp)
              markBlockedIfAllZero(hostname, fallbackIp)
              log.info(`----- ${action}: ${hostname}, 系统 DNS 解析失败（${err.code || err.message}），改用 '${fallbackDns.dnsName}': ${fallbackIp}(family: ${fallbackFamily})${target} -----`)
              if (res) {
                res.setHeader('DS-DNS', `${safeHeaderValue(fallbackDns.dnsName)}: ${fallbackIp} (IPv${fallbackFamily})`)
              }
              respondLookup(callback, fallbackIp, fallbackFamily, options && options.all === true)
              return true
            }
          } catch (e) {
            log.warn(`----- ${action}: ${hostname}, 兜底 DNS '${fallbackDns.dnsName}' 解析失败${target}, error:`, e)
          }
        }
        return false
      }

      defaultDns.lookup(hostname, options, (err, address, family) => {
        if (err) {
          log.error(`----- ${action}: ${hostname}, default dns lookup error${target}, error:`, err)
          useFallbackDns(err).then((handled) => {
            if (!handled) {
              callback(err, address, family)
            }
          })
          return
        }
        markBlockedIfAllZero(hostname, address)
        if (Array.isArray(address)) {
          address = address.map((item) => {
            const newIp = rewriteCloudflareIp(hostname, item.address)
            return { address: newIp, family: getAddressFamily(newIp) }
          })
        } else {
          address = rewriteCloudflareIp(hostname, address)
          family = getAddressFamily(address)
        }
        const first = Array.isArray(address) ? address[0] : { address, family }
        const ip = first && first.address
        const fam = first && first.family
        if (ip && isValidIpAddress(ip)) {
          log.info(`----- ${action}: ${hostname}, use default DNS: ${ip}(family: ${fam})${target} -----`)
          if (res) {
            res.setHeader('DS-DNS', `default: ${ip} (IPv${fam})`)
          }
        }
        // Node 20+ 默认开启 autoSelectFamily，会以 { all: true } 调用自定义 lookup，
        // 此时必须回传完整的地址数组；只回传单个 IP 会被 Node 当作数组解析，
        // 导致 ERR_INVALID_IP_ADDRESS: Invalid IP address: undefined
        if (Array.isArray(address) && address.length === 0) {
          // 防御：all 模式下解析结果为空时，按 ENOTFOUND 处理，避免回传空数组
          const notFound = new Error(`getaddrinfo ENOTFOUND ${hostname}`)
          notFound.code = 'ENOTFOUND'
          callback(notFound)
          return
        }
        callback(null, Array.isArray(address) ? address : ip, family)
      })
    }
  },
}

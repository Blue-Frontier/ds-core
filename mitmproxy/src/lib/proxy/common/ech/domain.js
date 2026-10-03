const matchUtil = require('../../../../utils/util.match')

/**
 * 把 ECH 域名配置转换成域名匹配表（同时兼容数组与对象两种写法）
 *
 * @param {string[]|object|null} domains 形如 `['crypto.cloudflare.com', '*.cloudflare.com']` 或 `{ 'x.com': true }`
 */
function toHostMap (domains) {
  const hostMap = {}
  if (Array.isArray(domains)) {
    for (const domain of domains) {
      if (typeof domain === 'string' && domain.length > 0) {
        hostMap[domain] = true
      }
    }
  } else if (domains != null && typeof domains === 'object') {
    for (const domain of Object.keys(domains)) {
      if (domains[domain] !== false && domains[domain] != null) {
        hostMap[domain] = true
      }
    }
  }
  return hostMap
}

/**
 * 生成 ECH 域名的匹配表（支持通配符与正则，只解析一次，供 isEchDomain 反复匹配使用）
 */
function createEchDomainMap (echOptions) {
  return matchUtil.domainMapRegexply(toHostMap(echOptions == null ? null : echOptions.domains))
}

/**
 * 判断该域名是否在 ECH 域名名单中
 *
 * ECH 域名会强制忽略常规的 SNI 改写与预设IP等配置，因此该判断在多处复用。
 */
function isEchDomain (echDomainMap, hostname) {
  if (echDomainMap == null || hostname == null || hostname.length === 0) {
    return false
  }
  return matchUtil.matchHostname(echDomainMap, hostname, 'ECH') != null
}

module.exports = {
  toHostMap,
  createEchDomainMap,
  isEchDomain,
}

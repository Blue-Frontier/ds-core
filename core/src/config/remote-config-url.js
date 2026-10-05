const logOrConsole = require('../utils/util.log-or-console')

/**
 * 远程配置地址的协议约束：不再支持裸 HTTP。
 *
 * 远程配置可以改写拦截/重定向规则、DNS 服务商与预设 IP、ECH 域名，明文 http 下载会被中间人直接篡改，
 * 等同于接管被代理流量。因此 http:// 开头的地址统一改写为 https://，并写回用户配置文件（见 config-api.js）。
 * 非 http:// 开头（https://、空串、非字符串）原样返回，用户自建的其它协议地址不受影响。
 */

/** 需要强制 https 的远程配置地址字段（共享配置 + 个人配置） */
const REMOTE_CONFIG_URL_KEYS = ['url', 'personalUrl']

const PLAIN_HTTP_PREFIX_REG = /^\s*http:\/\//i

/** 是否为裸 HTTP 地址 */
function isPlainHttpUrl (url) {
  return typeof url === 'string' && PLAIN_HTTP_PREFIX_REG.test(url)
}

/**
 * 裸 HTTP 地址改写为 HTTPS。
 * @param {unknown} url
 * @returns {unknown} 非 http:// 开头时原样返回
 */
function toHttpsUrl (url) {
  if (!isPlainHttpUrl(url)) {
    return url
  }
  return `https://${url.trim().slice('http://'.length)}`
}

/**
 * 就地修正 config.app.remoteConfig 的地址协议。
 * 对合并后的最终配置调用，因此远程配置里写 http 地址也会被改写。
 * @param {object} config
 * @returns {object} 原 config（就地修改）
 */
function applyRemoteConfigUrlHttps (config) {
  const remoteConfig = config?.app?.remoteConfig
  if (remoteConfig == null) {
    return config
  }

  for (const key of REMOTE_CONFIG_URL_KEYS) {
    if (!isPlainHttpUrl(remoteConfig[key])) {
      continue
    }
    const fixed = toHttpsUrl(remoteConfig[key])
    logOrConsole.info(`远程配置地址不再支持裸HTTP，已自动改写为HTTPS: ${remoteConfig[key]} -> ${fixed}`)
    remoteConfig[key] = fixed
  }

  return config
}

module.exports = {
  REMOTE_CONFIG_URL_KEYS,
  isPlainHttpUrl,
  toHttpsUrl,
  applyRemoteConfigUrlHttps,
}

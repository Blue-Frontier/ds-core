const tls = require('node:tls')

/**
 * 决定上游 TLS 的 SNI 与证书校验域名（常规请求与 WebSocket 升级路径共用）。
 *
 * 规则：
 * - SNI：拦截器（sni / proxy）按规则写入 `rOptions.servername`；未写入时用真实域名。
 * - 证书校验：**默认校验真实域名**，不能用伪装 SNI（会变成 Host: none 或对不上证书）；
 *   规则显式配置 `verifyHost` 时改用它 —— 用于「换 SNI 敲门」类规则
 *   （如 huggingface.co 用 huggingface.cn 的 SNI 连，服务器返回的就是 huggingface.cn 的证书）。
 * - 免校验必须由规则显式声明 `unVerifySsl: true`（或 `ssl: false`），
 *   由 unVerifySsl / proxy 拦截器换成免校验 agent；sni 只负责改 SNI，不改校验策略。
 *
 * @param {object} rOptions 请求参数（就地修改 servername / checkServerIdentity）
 * @param {object} [log]    日志对象，用于 verifyHost 偏离真实域名时的安全告警
 */
function applyTlsVerifyPolicy (rOptions, log) {
  if (rOptions.protocol !== 'https:' || !rOptions.hostname) {
    return
  }

  const realHost = rOptions.hostname
  if (rOptions.servername == null) {
    rOptions.servername = realHost
  }
  const verifyHost = (rOptions.verifyHost != null && rOptions.verifyHost !== '') ? rOptions.verifyHost : realHost
  if (rOptions.servername !== realHost || verifyHost !== realHost) {
    rOptions.checkServerIdentity = (_host, cert) => tls.checkServerIdentity(verifyHost, cert)
  }
  if (verifyHost !== realHost && log) {
    log.warn(`[安全风险] 证书校验域名 verifyHost='${verifyHost}' 与真实域名 '${realHost}' 不一致：`
      + '任何持有该证书的中间人都可能冒充真实域名；不需要比对证书时请改用 unVerifySsl，而不是随意指定 verifyHost')
  }
}

module.exports = {
  applyTlsVerifyPolicy,
}

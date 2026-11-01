/**
 * 请求拦截器的公共工具。
 *
 * 修改型拦截器（sni / unVerifySsl 等）只改 rOptions，**不返回值**（undefined），
 * 调用方据此继续执行下一个拦截器，因此它们可以叠加；这里集中放「改 rOptions」和「留痕」的小函数，
 * 避免 sni.js / proxy.js 各写一份。
 */

/**
 * 追加 DS-Interceptor 响应头。
 *
 * 叠加执行时后一个拦截器不能覆盖前一个的标记，否则客户端与日志里看不到完整的命中规则
 * （例如 sni: (disabled) + unVerifySsl）。
 *
 * @param {object} res  响应对象（升级路径传入的是只吸收 setHeader 的 stub）
 * @param {string} label 本次拦截器的标记
 */
function appendInterceptorLabel (res, label) {
  if (res == null || typeof res.setHeader !== 'function' || !label) {
    return
  }
  const prev = typeof res.getHeader === 'function' ? res.getHeader('DS-Interceptor') : null
  res.setHeader('DS-Interceptor', prev ? `${prev}, ${label}` : label)
}

/**
 * 把 DS-Interceptor 标记片段拼成一个响应头值。
 */
function joinLabels (labels) {
  return labels.filter(Boolean).join(', ')
}

/**
 * 把 rOptions.agent 换成免校验的 agent。
 *
 * 只有规则**显式**配置 `unVerifySsl: true` 或 `ssl: false` 时才允许调用 ——
 * 改写 SNI 本身不代表放弃上游身份校验，两者是独立配置。
 *
 * @returns {boolean} 本次是否真的切换（false 表示当前 agent 本来就不校验）
 */
function applyUnVerifySslAgent (rOptions) {
  const agent = rOptions.agent
  if (agent && agent.options && agent.options.rejectUnauthorized && agent.unVerifySslAgent) {
    // 不能直接改 agent.options.rejectUnauthorized：agent 是单例，所有请求共用同一个对象
    rOptions.agent = agent.unVerifySslAgent
    return true
  }
  return false
}

/**
 * 把 rOptions.agent 恢复成校验版。
 *
 * 用于「请求目标被改写到别处」的场景（overwall）：原规则里的 unVerifySsl 是为原域名声明的，
 * 不能跟着请求作用到新目标的连接上。
 *
 * @returns {boolean} 是否恢复了（false 表示当前 agent 本来就是校验版/没有绑定关系）
 */
function restoreVerifySslAgent (rOptions) {
  const agent = rOptions.agent
  if (agent && agent.verifySslAgent) {
    rOptions.agent = agent.verifySslAgent
    return true
  }
  return false
}

/**
 * 把规则里的 verifyHost 写到 rOptions 上，供证书校验使用。
 *
 * 用途：默认情况下 DS 用「真实域名」校验证书。但有一类规则是**故意换成另一个真实域名的 SNI**
 * （例如 huggingface.co 用 huggingface.cn 的 SNI 连，以绕过对 huggingface.co 的 SNI 阻断），
 * 这类场景服务器返回的是 **SNI 那个域名**的证书，用真实域名校验必然失败。
 * 此时可在规则里显式指定 `verifyHost`，声明「请用这个域名校验证书」。
 *
 * 例：{ "sni": "huggingface.cn", "verifyHost": "huggingface.cn" }
 *
 * @returns 用于日志/响应头的说明串（未配置时返回空串）
 */
function applyVerifyHost (rOptions, interceptOpt) {
  if (interceptOpt.verifyHost == null || interceptOpt.verifyHost === '') {
    return ''
  }
  rOptions.verifyHost = interceptOpt.verifyHost
  return `verifyHost: ${interceptOpt.verifyHost}`
}

module.exports = {
  appendInterceptorLabel,
  joinLabels,
  applyUnVerifySslAgent,
  restoreVerifySslAgent,
  applyVerifyHost,
}

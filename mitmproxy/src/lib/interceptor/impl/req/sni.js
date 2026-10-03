module.exports = {
  name: 'sni',
  priority: 123,
  requestIntercept (context, interceptOpt, req, res, _ssl, _next) {
    const { rOptions, log } = context

    // 配置 sni: "" 时，不发送 SNI（Node 在 servername 为空字符串时不会发送 SNI 扩展）。
    // 实测 production.cloudflare.docker.com / character.ai 等 Cloudflare 域名在 TLS1.2 下可用。
    if (interceptOpt.sni === '') {
      rOptions.servername = ''
      applyVerifyHost(rOptions, interceptOpt)
      res.setHeader('DS-Interceptor', 'sni: (disabled)')
      log.info(`sni intercept: SNI 已禁用: ${rOptions.hostname}`)
      return true
    }

    let unVerifySsl = rOptions.agent && rOptions.agent.options.rejectUnauthorized === false

    if (interceptOpt.sni != null) {
      rOptions.servername = interceptOpt.sni
    }
    const verifyHostStr = applyVerifyHost(rOptions, interceptOpt)
    if (rOptions.agent && rOptions.agent.options.rejectUnauthorized && rOptions.agent.unVerifySslAgent) {
      // rOptions.agent.options.rejectUnauthorized = false // 不能直接在agent上进行修改属性值，因为它采用了单例模式，所有请求共用这个对象的
      rOptions.agent = rOptions.agent.unVerifySslAgent
      unVerifySsl = true
    }

    const unVerifySslStr = unVerifySsl ? ', unVerifySsl' : ''
    res.setHeader('DS-Interceptor', `sni: ${interceptOpt.sni}${verifyHostStr}${unVerifySslStr}`)

    log.info(`sni intercept: sni replace servername: ${rOptions.hostname} ➜ ${rOptions.servername}${verifyHostStr}${unVerifySslStr}`)
    return true
  },
  is (interceptOpt) {
    // 注意：sni 为空字符串时也要生效，用于显式禁用 SNI
    // proxy生效时，sni不需要生效，因为proxy中也会使用sni覆盖 rOptions.servername
    if (interceptOpt.proxy) {
      return false
    }
    return (interceptOpt.sni !== undefined && interceptOpt.sni !== null) || interceptOpt.verifyHost != null
  },
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
  return `, verifyHost: ${interceptOpt.verifyHost}`
}

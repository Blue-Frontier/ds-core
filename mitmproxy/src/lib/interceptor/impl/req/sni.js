const { appendInterceptorLabel, applyVerifyHost, joinLabels } = require('./interceptorUtil')

module.exports = {
  name: 'sni',
  priority: 123,
  requestIntercept (context, interceptOpt, req, res, _ssl, _next) {
    const { rOptions, log } = context

    // 只改 rOptions，返回 undefined 让拦截器链继续执行：
    // 同一规则里还可能有 unVerifySsl、overwall 等同样只改 rOptions 的拦截器。
    // 以前这里返回 true，导致 sni 与 unVerifySsl 变成「两个字段只能二选一」。
    if (interceptOpt.sni != null) {
      // 空字符串表示不发送 SNI 扩展（Node 在 servername 为空时不会发 SNI）；
      // 常规值用于握手伪装。SNI 与证书校验是两件事，这里不改校验策略。
      rOptions.servername = interceptOpt.sni
    }
    const verifyHostLabel = applyVerifyHost(rOptions, interceptOpt)

    const sniLabel = interceptOpt.sni == null
      ? null
      : (interceptOpt.sni === '' ? 'sni: (disabled)' : `sni: ${interceptOpt.sni}`)
    appendInterceptorLabel(res, joinLabels([sniLabel, verifyHostLabel]))

    const extra = verifyHostLabel ? `, ${verifyHostLabel}` : ''
    if (interceptOpt.sni === '') {
      log.info(`sni intercept: SNI 已禁用: ${rOptions.hostname}${extra}`)
    } else if (interceptOpt.sni != null) {
      log.info(`sni intercept: sni replace servername: ${rOptions.hostname} ➜ ${rOptions.servername}${extra}`)
    } else {
      log.info(`sni intercept: 未改写 SNI，仅指定证书校验域名: ${rOptions.hostname}${extra}`)
    }
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

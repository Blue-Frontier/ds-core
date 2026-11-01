const { appendInterceptorLabel, applyUnVerifySslAgent } = require('./interceptorUtil')

module.exports = {
  name: 'unVerifySsl',
  priority: 124,
  requestIntercept (context, interceptOpt, req, res) {
    const { rOptions, log } = context

    // 只改 rOptions，返回 undefined 让拦截器链继续（与 sni 等修改型拦截器叠加）
    if (applyUnVerifySslAgent(rOptions)) {
      log.info(`unVerifySsl intercept: ${rOptions.hostname}, unVerifySsl`)
      appendInterceptorLabel(res, 'unVerifySsl')
    } else {
      log.info(`unVerifySsl intercept: ${rOptions.hostname}, already unVerifySsl`)
      appendInterceptorLabel(res, 'already unVerifySsl')
    }
  },
  is (interceptOpt) {
    return interceptOpt.unVerifySsl === true || interceptOpt.ssl === false
  },
}

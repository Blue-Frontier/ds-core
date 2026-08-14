module.exports = {
  node: require('./node'),
  git: require('./git'),
  pip: require('./pip'),
  overwall: require('./overwall'),
  // free-eye 为 ESM 模块，CJS require() 得到 { default: ... }，需解包
  // 独立可执行文件（SEA）中无法打包/携带 free-eye，加载失败时降级为不可用，而不是崩溃
  get free_eye () {
    try {
      return require('./free-eye').default
    } catch (e) {
      const log = require('@docmirror/dev-sidecar/src/utils/util.log-or-console')
      log.warn('加载 free-eye 插件失败，该插件不可用:', e.message)
      return null
    }
  },
}

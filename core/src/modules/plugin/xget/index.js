/**
 * Xget 加速插件
 *
 * 规则合并由配置加载器完成（见 config/local-config-loader.js 的 getXgetOverlay）：
 * 启用且配置了实例地址时，把 xget_config.json5 里的 ${XGET_DOMAIN} 替换为该地址，
 * 并按用户配置层级的优先级合并 server.intercepts。插件本身不需要启动进程。
 */
const xgetConfig = require('./config')

const XgetPlugin = function () {
  return {
    async start () {},
    async stop () {},
  }
}

module.exports = {
  key: 'xget',
  config: xgetConfig,
  status: {
    enabled: false,
  },
  plugin: XgetPlugin,
}

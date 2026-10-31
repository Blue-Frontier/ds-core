/**
 * Xget 加速插件
 *
 * 规则合并由配置加载器完成（见 config/local-config-loader.js 的 getXgetOverlay）：
 * 启用且配置了实例地址时，把 xget_config.json5 里的 ${XGET_DOMAIN} 替换为该地址，
 * 并按用户配置层级的优先级合并 server.intercepts。插件本身不需要启动进程。
 *
 * Cloudflare Access 服务令牌不写配置文件：Secret 存 SecretStore（keytar 优先，
 * 即系统密钥库；不可用时回退到本机加密文件），启动代理时通过环境变量注入子进程，
 * 规则里只保留 ${env:...} 占位符，真实值不会出现在 config.json / running.json 里。
 */
const secretStore = require('../../../utils/util.secret-store')

// SecretStore 中的账户名
const CF_ACCESS_SECRET_ACCOUNT = 'xget-cf-access-secret'
// 注入子进程的环境变量名（规则占位符与它对应）
const CF_ACCESS_SECRET_ENV = 'DS_XGET_CF_ACCESS_SECRET'

function readSetting (context) {
  const all = context.config.get() || {}
  return (all.plugin && all.plugin.xget && all.plugin.xget.setting) || {}
}

function normalize (value) {
  return value == null ? '' : String(value).trim()
}

// 旧版本把 Secret 明文写在 config.json：迁移进 SecretStore 并从配置里清掉
async function migrateLegacySecret (context) {
  const legacy = normalize(readSetting(context).cfAccessClientSecret)
  if (!legacy) {
    return null
  }
  await secretStore.setSecret(CF_ACCESS_SECRET_ACCOUNT, legacy)
  await context.config.update({ plugin: { xget: { setting: { cfAccessClientSecret: '' } } } })
  return legacy
}

const XgetPlugin = function (context) {
  return {
    async start () {},
    async stop () {},

    /** 是否已保存服务令牌（供界面显示状态，不返回令牌内容） */
    async hasCfAccessSecret () {
      return secretStore.hasSecret(CF_ACCESS_SECRET_ACCOUNT)
    },

    /** 保存服务令牌到系统密钥库；写入后不再回显 */
    async setCfAccessSecret (secret) {
      const value = normalize(secret)
      if (!value) {
        throw new Error('服务令牌不能为空')
      }
      const ret = await secretStore.setSecret(CF_ACCESS_SECRET_ACCOUNT, value)
      // 顺手清掉旧版可能残留在配置文件里的明文
      await context.config.update({ plugin: { xget: { setting: { cfAccessClientSecret: '' } } } })
      return ret
    },

    /** 删除已保存的服务令牌 */
    async clearCfAccessSecret () {
      await secretStore.deleteSecret(CF_ACCESS_SECRET_ACCOUNT)
      return { ok: true }
    },

    /**
     * 代理子进程启动前准备环境变量：把服务令牌交给子进程。
     * 规则里只有占位符，真实值只存在于进程环境，不落盘。
     */
    async prepareEnv () {
      const legacy = await migrateLegacySecret(context)
      const secret = legacy || (await secretStore.getSecret(CF_ACCESS_SECRET_ACCOUNT))
      if (!secret) {
        return null
      }
      return { [CF_ACCESS_SECRET_ENV]: secret }
    },
  }
}

module.exports = {
  key: 'xget',
  config: require('./config'),
  status: {
    enabled: false,
  },
  plugin: XgetPlugin,
}

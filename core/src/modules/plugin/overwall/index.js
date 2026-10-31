const pluginConfig = require('./config')
const { vault, ACCOUNT_OVERWALL } = require('../../utils/util.secret-vault')

const Plugin = function (context) {
  const { config, shell, event, log } = context
  const api = {
    async start () {
      event.fire('status', { key: 'plugin.overwall.enabled', value: true })
      log.info('开启【Overwall】代理成功')
    },

    async close () {
      event.fire('status', { key: 'plugin.overwall.enabled', value: false })
      log.info('关闭【Overwall】代理成功')
    },

    async restart () {
      await api.close()
      await api.start()
    },

    /** 哪些服务器已保存口令（只返回布尔值，不回传口令） */
    async getServerPasswordStatus () {
      const map = await vault.readAccount(ACCOUNT_OVERWALL)
      const status = {}
      for (const domain of Object.keys(map)) {
        status[domain] = !!map[domain]
      }
      return status
    },

    /** 保存服务器口令到系统密钥库；空值表示不修改 */
    async setServerPasswords (passwords) {
      const map = await vault.readAccount(ACCOUNT_OVERWALL)
      for (const [domain, password] of Object.entries(passwords || {})) {
        const value = typeof password === 'string' ? password.trim() : ''
        if (value) {
          map[domain] = value
        }
      }
      await vault.writeAccount(ACCOUNT_OVERWALL, map)
      return { ok: true }
    },

    /** 删除某台服务器已保存的口令 */
    async clearServerPassword (domain) {
      const map = await vault.readAccount(ACCOUNT_OVERWALL)
      delete map[domain]
      await vault.writeAccount(ACCOUNT_OVERWALL, map)
      return { ok: true }
    },

    async  overrideRunningConfig_bak (serverConfig) {
      const conf = config.get().plugin.overwall
      if (!conf || !conf.enabled || !conf.targets) {
        return
      }
      const server = conf.server
      let i = 0
      let main
      const backup = []
      for (const key in server) {
        if (i === 0) {
          main = key
        } else {
          backup.push(key)
        }
        i++
      }
      for (const key in conf.targets) {
        serverConfig.intercepts[key] = {
          '.*': {
            proxy: `${main}/\${host}`,
            backup,
          },
        }
      }
    },
  }
  return api
}

module.exports = {
  key: 'overwall',
  config: pluginConfig,
  status: {
    enabled: false,
  },
  plugin: Plugin,
}

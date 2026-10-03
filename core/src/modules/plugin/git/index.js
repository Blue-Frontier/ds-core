const pluginConfig = require('./config')

const Plugin = function (context) {
  const { config, shell, event, log } = context
  const pluginApi = {
    async start () {
      const ip = '127.0.0.1'
      const port = config.get().server.port
      await pluginApi.setProxy(ip, port)
      return { ip, port }
    },

    async close () {
      return pluginApi.unsetProxy()
    },

    async restart () {
      await pluginApi.close()
      await pluginApi.start()
    },

    isEnabled () {
      return config.get().plugin.git.enabled
    },

    async save (newConfig) {
    },

    async setProxy (ip, port) {
      // 直接 execFile 调 git，避免每次经 cmd.exe / chcp
      const argsList = [
        ['config', '--global', 'http.proxy', `http://${ip}:${port}`],
        ['config', '--global', 'https.proxy', `http://${ip}:${port}`],
      ]

      if (config.get().plugin.git.setting.sslVerify === true) {
        argsList.push(['config', '--global', 'http.sslVerify', 'false'])
      }

      if (config.get().plugin.git.setting.noProxyUrls != null) {
        for (const url in config.get().plugin.git.setting.noProxyUrls) {
          argsList.push(['config', '--global', `http.${url}.proxy`, ''])
        }
      }

      const ret = []
      for (const args of argsList) {
        ret.push(await shell.execFile('git', args, { windowsHide: true }))
      }
      event.fire('status', { key: 'plugin.git.enabled', value: true })
      log.info('开启【Git】代理成功')

      return ret
    },

    // 当手动修改过 `~/.gitconfig` 时，`unset` 可能会执行失败，所以除了第一条命令外，其他命令都添加了try-catch，防止关闭Git代理失败
    async unsetProxy () {
      const ret = await shell.execFile('git', ['config', '--global', '--unset', 'http.proxy'], { windowsHide: true })

      try {
        await shell.execFile('git', ['config', '--global', '--unset', 'https.proxy'], { windowsHide: true })
      } catch {
      }

      if (config.get().plugin.git.setting.sslVerify === true) {
        try {
          await shell.execFile('git', ['config', '--global', '--unset', 'http.sslVerify'], { windowsHide: true })
        } catch {
        }
      }

      if (config.get().plugin.git.setting.noProxyUrls != null) {
        for (const url in config.get().plugin.git.setting.noProxyUrls) {
          try {
            await shell.execFile('git', ['config', '--global', '--unset', `http.${url}.proxy`], { windowsHide: true })
          } catch {
          }
        }
      }
      event.fire('status', { key: 'plugin.git.enabled', value: false })
      log.info('关闭【Git】代理成功')
      return ret
    },
  }
  return pluginApi
}

module.exports = {
  key: 'git',
  config: pluginConfig,
  status: {
    enabled: false,
  },
  plugin: Plugin,
}

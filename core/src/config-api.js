const fs = require('node:fs')
const jsonApi = require('@blue-frontier/mitmproxy/src/json')
const lodash = require('lodash')
const request = require('request')
const { defaultConfig: defConfig, applyRemoteConfigUrlFix } = require('./config/index.js')
const { REMOTE_CONFIG_URL_KEYS, isPlainHttpUrl, toHttpsUrl } = require('./config/remote-config-url.js')
const mergeApi = require('./merge.js')
const Shell = require('./shell')
const log = require('./utils/util.log.core')
const configLoader = require('./config/local-config-loader')

let configTarget = lodash.cloneDeep(defConfig)

function get () {
  return configTarget
}

let timer
const configApi = {
  /**
   * 启动远程配置定时下载。
   * @param {{ immediate?: boolean, onUpdated?: Function }} options
   *   immediate=true 时同步下载一次（兼容旧行为）；默认不阻塞调用方。
   *   下载内容有变化时 reload，并回调 onUpdated。
   */
  async startAutoDownloadRemoteConfig (options = {}) {
    if (timer != null) {
      clearInterval(timer)
    }
    const download = async () => {
      try {
        const updated = await configApi.downloadRemoteConfig()
        if (updated) {
          configApi.reload()
          if (typeof options.onUpdated === 'function') {
            try {
              options.onUpdated()
            } catch (e) {
              log.error('远程配置更新回调失败', e)
            }
          }
        }
      } catch (e) {
        log.error('下载远程配置失败', e)
      }
    }
    if (options.immediate) {
      await download()
    } else {
      // 异步下载，不阻塞启动
      download()
    }
    timer = setInterval(download, 24 * 60 * 60 * 1000) // 1天
  },
  /**
   * @returns {Promise<boolean>} 是否有内容更新（需要 reload）
   */
  async downloadRemoteConfig () {
    if (get().app.remoteConfig.enabled !== true) {
      // 删除保存的远程配置文件
      configApi.deleteRemoteConfigFile()
      configApi.deleteRemoteConfigFile('_personal')
      return false
    }

    const remoteConfig = get().app.remoteConfig
    const a = await configApi.doDownloadRemoteConfig(remoteConfig.url)
    const b = await configApi.doDownloadRemoteConfig(remoteConfig.personalUrl, '_personal')
    return a === true || b === true
  },
  doDownloadRemoteConfig (remoteConfigUrl, suffix = '') {
    if (!remoteConfigUrl) {
      // 删除保存的远程配置文件
      configApi.deleteRemoteConfigFile(suffix)
      return false
    }

    return new Promise((resolve, reject) => {
      log.info('开始下载远程配置:', remoteConfigUrl)

      const headers = {
        'Cache-Control': 'no-cache', // 禁止使用缓存
        'Pragma': 'no-cache', // 禁止使用缓存
      }
      if (remoteConfigUrl.startsWith('https://raw.githubusercontent.com/')) {
        headers['Server-Name'] = 'baidu.com'
      }
      // 禁用环境变量代理（HTTPS_PROXY/HTTP_PROXY）：
      // 当用户开启 proxy.setEnv 后，环境变量会指向 dev-sidecar 自己的代理端口，
      // 启动时本地代理尚未监听，走代理会导致下载失败（ECONNREFUSED 127.0.0.1:31181），
      // 新装用户会因此无法下载远程配置，只能使用内置规则。
      request(remoteConfigUrl, { headers, proxy: null }, (error, response, body) => {
        if (error) {
          log.error(`下载远程配置失败: ${remoteConfigUrl}, error:`, error, ', response:', response, ', body:', body)
          reject(error)
          return
        }
        if (response && response.statusCode === 200) {
          if (body == null || body.length < 2) {
            log.warn('下载远程配置成功，但内容为空:', remoteConfigUrl)
            resolve(false)
            return
          } else {
            log.info('下载远程配置成功:', remoteConfigUrl)
          }

          // 尝试解析远程配置，如果解析失败，则不保存它
          let remoteConfig
          try {
            remoteConfig = jsonApi.parse(body)
          } catch {
            log.error(`远程配置内容格式不正确, url: ${remoteConfigUrl}, body: ${body}`)
            remoteConfig = null
          }

          let changed = false
          if (remoteConfig != null) {
            const remoteSavePath = configLoader.getRemoteConfigPath(suffix)
            try {
              // 与本地已有内容比较，无变化则不写、不触发 reload
              let oldBody = null
              try {
                if (fs.existsSync(remoteSavePath)) {
                  oldBody = fs.readFileSync(remoteSavePath, 'utf-8')
                }
              } catch {
                oldBody = null
              }
              if (oldBody !== body) {
                fs.writeFileSync(remoteSavePath, body)
                changed = true
                log.info('保存远程配置文件成功:', remoteSavePath)
              } else {
                log.info('远程配置无变化，跳过保存:', remoteConfigUrl)
              }
            } catch (e) {
              log.error('保存远程配置文件失败:', remoteSavePath, ', error:', e)
              reject(new Error(`保存远程配置文件失败: ${e.message}`))
              return
            }
          } else {
            log.warn('远程配置对象为空:', remoteConfigUrl)
          }

          resolve(changed)
        } else {
          log.error(`下载远程配置失败: ${remoteConfigUrl}, response:`, response, ', body:', body)

          let message
          if (response) {
            message = `下载远程配置失败: ${remoteConfigUrl}, message: ${response.statusMessage}, code: ${response.statusCode}`
          } else {
            message = `下载远程配置失败: response: ${response}`
          }
          reject(new Error(message))
        }
      })
    })
  },
  deleteRemoteConfigFile (suffix = '') {
    const remoteSavePath = configLoader.getRemoteConfigPath(suffix)
    if (fs.existsSync(remoteSavePath)) {
      fs.unlinkSync(remoteSavePath)
      log.info('删除远程配置文件成功:', remoteSavePath)
    }
  },
  readRemoteConfigStr (suffix = '') {
    try {
      const path = configLoader.getRemoteConfigPath(suffix)
      if (fs.existsSync(path)) {
        const file = fs.readFileSync(path)
        log.info('读取远程配置文件内容成功:', path)
        return file.toString()
      } else {
        log.info('远程配置文件不存在:', path)
      }
    } catch (e) {
      log.error('读取远程配置文件内容失败:', e)
    }

    return '{}'
  },
  /**
   * 保存自定义的 config
   * @param newConfig
   */
  save (newConfig) {
    // 对比默认config的异同
    const defConfig = configApi.cloneDefault()

    // 如果开启了远程配置，则读取远程配置，合并到默认配置中
    if (get().app.remoteConfig.enabled === true) {
      if (get().app.remoteConfig.url) {
        mergeApi.doMerge(defConfig, configLoader.getRemoteConfig())
      }
      if (get().app.remoteConfig.personalUrl) {
        mergeApi.doMerge(defConfig, configLoader.getRemoteConfig('_personal'))
      }
    }

    // 计算新配置与默认配置（启用远程配置时，含远程配置）的差异
    const diffConfig = mergeApi.doDiff(defConfig, newConfig)

    // 将差异作为用户配置保存到 config.json 中
    const configPath = configLoader.getUserConfigPath()
    try {
      fs.writeFileSync(configPath, jsonApi.stringify(diffConfig))
      log.info('保存 config.json 自定义配置文件成功:', configPath)
    } catch (e) {
      log.error('保存 config.json 自定义配置文件失败:', configPath, ', error:', e)
      throw e
    }

    // 重载配置
    const allConfig = configApi.set(diffConfig)

    return {
      diffConfig,
      allConfig,
    }
  },
  doMerge: mergeApi.doMerge,
  doDiff: mergeApi.doDiff,
  /**
   * 读取 config.json 后，合并配置
   */
  reload () {
    const userConfig = configLoader.getUserConfig()
    return configApi.set(userConfig) || {}
  },
  update (partConfig) {
    const newConfig = lodash.merge(configApi.get(), partConfig)
    configApi.save(newConfig)
  },
  get,
  set (newConfig) {
    if (newConfig == null) {
      log.warn('newConfig 为空，不做任何操作')
      return configTarget
    }
    return configApi.load(newConfig)
  },
  load (newConfig) {
    const config = applyRemoteConfigUrlFix(configLoader.getConfigFromFiles(newConfig, defConfig))
    configTarget = config
    configApi.persistRemoteConfigUrlHttps(newConfig)
    return config
  },
  /**
   * 把「裸 HTTP → HTTPS」的改写结果持久化到用户配置文件（config.json）。
   *
   * 仅在用户配置里确实是 http:// 开头的地址时才写盘，且只改 app.remoteConfig 这两个字段，
   * 不动其它用户配置；改写后原值已是 https，再次加载不会重复写盘（幂等）。
   *
   * @param {object} newConfig load() 的入参（用户配置或差异配置）
   */
  persistRemoteConfigUrlHttps (newConfig) {
    try {
      const configPath = configLoader.getUserConfigPath()
      let userConfig = {}
      if (fs.existsSync(configPath)) {
        userConfig = configLoader.loadConfigFromFile(configPath)
      }
      if (typeof userConfig !== 'object' || userConfig == null) {
        userConfig = {}
      }

      const fixedRemoteConfig = configTarget?.app?.remoteConfig
      if (fixedRemoteConfig == null) {
        return
      }

      let changed = false
      for (const key of REMOTE_CONFIG_URL_KEYS) {
        const keyPath = ['app', 'remoteConfig', key]
        const oldUrl = lodash.get(userConfig, keyPath) ?? lodash.get(newConfig, keyPath)
        if (!isPlainHttpUrl(oldUrl)) {
          continue
        }
        // 优先用合并后已修正的值（历史废弃地址会被一次性纠正成官方地址）
        const fixedUrl = typeof fixedRemoteConfig[key] === 'string' && fixedRemoteConfig[key]
          ? fixedRemoteConfig[key]
          : toHttpsUrl(oldUrl)
        lodash.set(userConfig, keyPath, fixedUrl)
        changed = true
        log.info(`远程配置地址不再支持裸HTTP，已改写为HTTPS并保存到用户配置: ${oldUrl} -> ${fixedUrl}`)
      }

      if (!changed) {
        return
      }

      fs.writeFileSync(configPath, jsonApi.stringify(userConfig))
      log.info('保存 config.json（远程配置地址 HTTPS 改写）成功:', configPath)
    } catch (e) {
      // 持久化失败不影响本次运行：内存中的 configTarget 已是 https 地址
      log.error('保存远程配置地址 HTTPS 改写结果失败:', e)
    }
  },
  cloneDefault () {
    return lodash.cloneDeep(defConfig)
  },
  addDefault (key, defValue) {
    lodash.set(defConfig, key, defValue)
  },
  // 移除用户配置，用于恢复出厂设置功能
  async removeUserConfig () {
    const configPath = configLoader.getUserConfigPath()
    if (fs.existsSync(configPath)) {
      // 读取 config.json 文件内容
      const fileOriginalStr = fs.readFileSync(configPath).toString()

      // 判断文件内容是否为空或空配置
      const fileStr = fileOriginalStr.replace(/\s/g, '')
      if (fileStr.length < 5) {
        try {
          fs.writeFileSync(configPath, '{}')
        } catch (e) {
          log.warn('简化用户配置文件失败:', configPath, ', error:', e)
        }
        return false // config.json 内容为空，或为空json
      }

      // 备份用户自定义配置文件
      const bakConfigPath = `${configPath}.${Date.now()}.bak.json`
      try {
        fs.writeFileSync(bakConfigPath, fileOriginalStr)
        log.info('备份用户配置文件成功:', bakConfigPath)
      } catch (e) {
        log.error('备份用户配置文件失败:', bakConfigPath, ', error:', e)
        throw e
      }
      // 原配置文件内容设为空
      try {
        fs.writeFileSync(configPath, '{}')
      } catch (e) {
        log.error('初始化用户配置文件失败:', configPath, ', error:', e)
        throw e
      }

      // 重新加载配置
      configApi.load(null)

      return true // 删除并重新加载配置成功
    } else {
      return false // config.json 文件不存在
    }
  },
  resetDefault (key) {
    if (key) {
      let value = lodash.get(defConfig, key)
      value = lodash.cloneDeep(value)
      lodash.set(configTarget, key, value)
    } else {
      configTarget = lodash.cloneDeep(defConfig)
    }
    return configTarget
  },
  async getVariables (type) {
    const method = type === 'npm' ? Shell.getNpmEnv : Shell.getSystemEnv
    const currentMap = await method()
    const list = []
    const map = configTarget.variables[type]
    for (const key in map) {
      const exists = currentMap[key] != null
      list.push({
        key,
        value: map[key],
        exists,
      })
    }
    return list
  },
  async setVariables (type) {
    const list = await configApi.getVariables(type)
    const noSetList = list.filter((item) => {
      return !item.exists
    })
    if (noSetList.length > 0) {
      const context = {
        root_ca_cert_path: configApi.get().server.setting.rootCaFile.certPath,
      }
      for (const item of noSetList) {
        if (item.value.includes('${')) {
          for (const key in context) {
            item.value = item.value.replace(new RegExp(`\\$\\{${key}\\}`, 'g'), context[key])
          }
        }
      }
      const method = type === 'npm' ? Shell.setNpmEnv : Shell.setSystemEnv
      return method({ list: noSetList })
    }
  },
}

module.exports = configApi

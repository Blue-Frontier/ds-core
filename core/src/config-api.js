const fs = require('node:fs')
const http = require('node:http')
const https = require('node:https')
const net = require('node:net')
const path = require('node:path')
const jsonApi = require('@blue-frontier/mitmproxy/src/json')
const lodash = require('lodash')
const request = require('request')
const { defaultConfig: defConfig, applyRemoteConfigUrlFix } = require('./config/index.js')
const { REMOTE_CONFIG_URL_KEYS, isPlainHttpUrl, toHttpsUrl } = require('./config/remote-config-url.js')
const mergeApi = require('./merge.js')
const Shell = require('./shell')
const log = require('./utils/util.log.core')

/**
 * 远程配置下载超时（毫秒）。
 *
 * 必须设置：此前 request 不传 timeout，一旦网络卡住（DNS/TCP/TLS 挂起）回调永不触发，
 * 上层 await 永远不返回 —— 表现为「点重载远程配置后一直转圈」，且日志里既没有成功也没有失败。
 */
const CONFIG_DOWNLOAD_TIMEOUT_MS = 30 * 1000

/** 下载配置时使用的 User-Agent（带标识的浏览器 UA，避免被边缘 WAF 当作爬虫拒绝） */
const DOWNLOAD_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 dev-sidecar'

/** 等待本地代理就绪的总时长（启动期不阻塞：最多等这么久，然后退回直连） */
const PROXY_READY_TIMEOUT_MS = 15 * 1000
/**
 * 单次尝试的总时长上限。request 库的 timeout 只是"空闲"超时，连接半开或持续有零星数据时
 * 实测能拖到 20~30 秒以上，因此再加一道硬闸门（取 40s：比实测成功最慢的一次 28s 留出余量）。
 */
const CONFIG_DOWNLOAD_TOTAL_TIMEOUT_MS = 60 * 1000
/** 每档尝试次数与重试间隔：本机网络波动明显，成功的取回实测要 9~28 秒，单次尝试容易假失败 */
const CONFIG_DOWNLOAD_ATTEMPTS = 2
const CONFIG_DOWNLOAD_RETRY_DELAY_MS = 1000
/** 代理就绪探测的轮询间隔与单次连接超时 */
const PROXY_READY_POLL_MS = 500
const PROXY_READY_CONNECT_TIMEOUT_MS = 1000
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
  /**
   * 下载远程配置。
   *
   * 策略阶梯（穷尽 DS 自身默认模式的手段，不依赖该地址是否在用户规则里 ——
   * 该 host 的默认对抗规则由 modules/server 在代理启动前注入，见 applyRemoteConfigHostRules）：
   *   ① 经本地代理：DS 的 DNS 防污染 / SNI 伪装 / ECH / 预设 IP 全部生效
   *   ② 直连：本地代理不可用时的兜底（server 被关闭、代理一直没就绪等）
   * 每档独立超时，成功即止，并记录生效档位与耗时。
   *
   * 注：旧实现里给 raw.githubusercontent.com 加 `Server-Name: baidu.com` 头的做法已删除 ——
   * 全仓库没有任何消费者，它只是被原样发给了源站，从未真正改写 SNI。
   *
   * @returns {Promise<boolean>} 是否有内容更新（需要 reload）
   */
  async doDownloadRemoteConfig (remoteConfigUrl, suffix = '') {
    if (!remoteConfigUrl) {
      // 删除保存的远程配置文件
      configApi.deleteRemoteConfigFile(suffix)
      return false
    }

    const strategies = await configApi.buildDownloadStrategies()
    let lastError = null
    for (const strategy of strategies) {
      for (let attempt = 1; attempt <= CONFIG_DOWNLOAD_ATTEMPTS; attempt++) {
        if (attempt > 1) {
          await new Promise((resolve) => setTimeout(resolve, CONFIG_DOWNLOAD_RETRY_DELAY_MS))
        }
        const startedAt = Date.now()
        try {
        log.info(`开始下载远程配置（${strategy.name}）:`, remoteConfigUrl)
        const body = await requestRemoteConfig(remoteConfigUrl, strategy)
        if (body == null || body.length < 2) {
          log.warn('下载远程配置成功，但内容为空:', remoteConfigUrl)
          return false
        }
        log.info(`下载远程配置成功（${strategy.name}，耗时 ${Date.now() - startedAt} ms）:`, remoteConfigUrl)
        return saveRemoteConfig(body, remoteConfigUrl, suffix)
        } catch (e) {
          lastError = e
          log.warn(`下载远程配置失败（${strategy.name}${attempt > 1 ? ` 第 ${attempt} 次` : ''}，耗时 ${Date.now() - startedAt} ms）: ${remoteConfigUrl}, error: ${(e && e.message) || e}`)
        }
      }
    }

    throw lastError || new Error(`下载远程配置失败: ${remoteConfigUrl}`)
  },
  /**
   * 组装下载策略阶梯：本地代理就绪时优先走代理（对抗手段最全），否则只保留直连。
   *
   * @returns {Promise<Array<{name: string, proxy: (string|null)}>>}
   */
  async buildDownloadStrategies () {
    const strategies = []
    const port = lodash.get(get(), 'server.port')
    const serverStartup = lodash.get(get(), 'server.startup') !== false
    if (serverStartup && port) {
      if (await waitForLocalProxyReady(port)) {
        strategies.push({ name: '本地代理', proxy: `http://127.0.0.1:${port}` })
      } else {
        log.warn(`本地代理端口 ${port} 在 ${PROXY_READY_TIMEOUT_MS}ms 内未就绪，本次仅直连`)
      }
    }
    strategies.push({ name: '直连', proxy: null })
    return strategies
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

/**
 * 等待本地代理端口就绪（TCP 探测 + 轮询）。
 *
 * @param {number} port       本地代理端口
 * @param {number} deadlineMs 最长等待时间
 * @returns {Promise<boolean>}
 */
function waitForLocalProxyReady (port, deadlineMs = PROXY_READY_TIMEOUT_MS) {
  const startedAt = Date.now()
  return new Promise((resolve) => {
    const attempt = () => {
      const socket = net.connect({ host: '127.0.0.1', port })
      const settle = (ready) => {
        socket.removeAllListeners()
        socket.destroy()
        if (ready) {
          resolve(true)
        } else if (Date.now() - startedAt >= deadlineMs) {
          resolve(false)
        } else {
          setTimeout(attempt, PROXY_READY_POLL_MS)
        }
      }
      socket.setTimeout(PROXY_READY_CONNECT_TIMEOUT_MS)
      socket.once('connect', () => settle(true))
      socket.once('timeout', () => settle(false))
      socket.once('error', () => settle(false))
    }
    attempt()
  })
}

/**
 * 按指定策略发起一次下载请求，成功时返回响应体文本。
 *
 * @param {string} remoteConfigUrl
 * @param {{name: string, proxy: (string|null)}} strategy
 * @returns {Promise<string|null>}
 */
function requestRemoteConfig (remoteConfigUrl, strategy) {
  return new Promise((resolve, reject) => {
    const headers = {
      'Cache-Control': 'no-cache', // 禁止使用缓存
      'Pragma': 'no-cache', // 禁止使用缓存
      // 必须带 UA：裸请求（无 UA）会被 Cloudflare 这类边缘的 WAF 直接拒掉（实测 HTTP 500），
      // 这与 CI 侧 config_convert 用 python requests 拉取失败是同一类原因。
      'User-Agent': DOWNLOAD_USER_AGENT,
    }
    const options = {
      headers,
      proxy: strategy.proxy, // null = 直连（不读取环境变量里的代理）
      timeout: CONFIG_DOWNLOAD_TIMEOUT_MS,
    }
    if (strategy.proxy == null) {
      // 必须显式给 agent：本机开着 NODE_USE_ENV_PROXY=1（Node 24 的内建环境变量代理），
      // 不指定 agent 时请求会被 HTTPS_PROXY 拖去本地代理 —— 实测守护进程未运行时报
      // ECONNREFUSED 127.0.0.1:31181，指定 agent 后才是真直连（实测 HTTP 200）。
      // 注意：request 库只接受单个 Agent 实例，传 {http,https} 会直接报错
      options.agent = remoteConfigUrl.startsWith('https:')
        ? new https.Agent({ keepAlive: false })
        : new http.Agent({ keepAlive: false })
    } else {
      // 经 DS 自己的代理：上游看到的是 DS 的 MITM 证书，必须显式信任它的根证书；
      // 仍然保留 strictSSL，让"证书与域名不匹配"这类真问题继续暴露。
      const caPath = path.join(configLoader.getUserBasePath(), 'dev-sidecar.ca.crt')
      if (fs.existsSync(caPath)) {
        // 注意：request 库的 TLS 选项放在 agentOptions 里才生效（顶层 ca 会被忽略）
        options.agentOptions = { ca: fs.readFileSync(caPath) }
      } else {
        log.warn('未找到 DS 根证书，经代理下载将不校验证书:', caPath)
        options.strictSSL = false
      }
    }

    let settled = false
    let hardTimer = null
    const finish = (fn, value) => {
      if (settled) return
      settled = true
      if (hardTimer != null) {
        clearTimeout(hardTimer)
      }
      fn(value)
    }
    // 总时长闸门：request 的 timeout 只是空闲超时，连接半开时能拖很久
    hardTimer = setTimeout(() => {
      if (settled) return
      if (req != null) {
        req.abort()
      }
      finish(reject, new Error(`超过总时长上限 ${CONFIG_DOWNLOAD_TOTAL_TIMEOUT_MS}ms`))
    }, CONFIG_DOWNLOAD_TOTAL_TIMEOUT_MS)

    let req = null
    req = request(remoteConfigUrl, options, (error, response, body) => {
      if (error) {
        const isTimeout = error.code === 'ETIMEDOUT' || error.code === 'ESOCKETTIMEDOUT' || error.code === 'ECONNRESET'
        finish(reject, new Error(`${isTimeout ? '超时' : '请求失败'}（${CONFIG_DOWNLOAD_TIMEOUT_MS}ms 上限）: ${error.message || error}`))
        return
      }
      if (response == null) {
        finish(reject, new Error('无响应'))
        return
      }
      if (response.statusCode !== 200) {
        // 带上响应体片段：非 200 时体里通常写着是谁在拒（边缘 WAF / DS 自己的错误页）
        const snippet = typeof body === 'string' ? body.replace(/\s+/g, ' ').slice(0, 300) : ''
        finish(reject, new Error(`HTTP ${response.statusCode} ${response.statusMessage || ''} - ${snippet}`.trim()))
        return
      }
      finish(resolve, body)
    })
  })
}

/**
 * 解析并保存远程配置（与本地已有内容比较，无变化则不写、不触发 reload）。
 *
 * @param {string} body            响应体
 * @param {string} remoteConfigUrl 下载地址（仅用于日志）
 * @param {string} suffix          文件名后缀（个人配置为 '_personal'）
 * @returns {boolean} 是否有变化
 */
function saveRemoteConfig (body, remoteConfigUrl, suffix) {
  let remoteConfig
  try {
    remoteConfig = jsonApi.parse(body)
  } catch {
    log.error(`远程配置内容格式不正确, url: ${remoteConfigUrl}, body: ${body}`)
    remoteConfig = null
  }

  if (remoteConfig == null) {
    log.warn('远程配置对象为空:', remoteConfigUrl)
    return false
  }

  const remoteSavePath = configLoader.getRemoteConfigPath(suffix)
  let oldBody = null
  try {
    if (fs.existsSync(remoteSavePath)) {
      oldBody = fs.readFileSync(remoteSavePath, 'utf-8')
    }
  } catch {
    oldBody = null
  }
  if (oldBody === body) {
    log.info('远程配置无变化，跳过保存:', remoteConfigUrl)
    return false
  }

  try {
    fs.writeFileSync(remoteSavePath, body)
  } catch (e) {
    log.error('保存远程配置文件失败:', remoteSavePath, ', error:', e)
    throw new Error(`保存远程配置文件失败: ${e.message}`)
  }
  log.info('保存远程配置文件成功:', remoteSavePath)
  return true
}

module.exports = configApi

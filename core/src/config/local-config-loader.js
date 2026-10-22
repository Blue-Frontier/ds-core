const fs = require('node:fs')
const path = require('node:path')
const lodash = require('lodash')
const jsonApi = require('@blue-frontier/mitmproxy/src/json')
const mergeApi = require('../merge')
const logOrConsole = require('../utils/util.log-or-console')

function getUserBasePath (autoCreate = true) {
  const userHome = process.env.USERPROFILE || process.env.HOME || '/'
  const dir = path.resolve(userHome, './.dev-sidecar')

  // 自动创建目录
  if (autoCreate && !fs.existsSync(dir)) {
    fs.mkdirSync(dir)
  }

  return dir
}

function loadConfigFromFile (configFilePath) {
  if (configFilePath == null) {
    logOrConsole.error('配置文件地址为空')
    return {}
  }

  if (!fs.existsSync(configFilePath)) {
    logOrConsole.info('配置文件不存在:', configFilePath)
    return {} // 文件不存在，返回空配置
  }

  // 读取配置文件
  let configStr
  try {
    configStr = fs.readFileSync(configFilePath)
  } catch (e) {
    logOrConsole.error('读取配置文件失败:', configFilePath, ', error:', e)
    return {}
  }

  // 解析配置文件
  try {
    const config = jsonApi.parse(configStr)
    logOrConsole.info('读取配置文件成功:', configFilePath)
    return config
  } catch (e) {
    logOrConsole.error(`解析配置文件失败，文件内容格式不正确，文件路径: ${configFilePath}，文件内容：${configStr}，error:`, e)
    return {}
  }
}

function getUserConfigPath () {
  const dir = getUserBasePath()

  // 兼容1.7.3及以下版本的配置文件处理逻辑
  const newFilePath = path.join(dir, '/config.json')
  const oldFilePath = path.join(dir, '/config.json5')
  if (!fs.existsSync(newFilePath) && fs.existsSync(oldFilePath)) {
    return oldFilePath // 如果新文件不存在，但旧文件存在，则返回旧文件路径
  }

  return newFilePath
}

function getUserConfig () {
  const configFilePath = getUserConfigPath()
  return loadConfigFromFile(configFilePath)
}

function getRemoteConfigPath (suffix = '') {
  const dir = getUserBasePath()
  return path.join(dir, `/remote_config${suffix}.json5`)
}

function getRemoteHistoryDir (suffix = '') {
  return path.join(getUserBasePath(), `remote_config_history${suffix}`)
}

function getRemoteSelectionPath () {
  return path.join(getUserBasePath(), 'remote_config_selection.json')
}

function sanitizeRemoteVersion (version) {
  return String(version).replace(/[^\w.-]/gi, '_')
}

function getRemoteSelection () {
  const filePath = getRemoteSelectionPath()
  if (!fs.existsSync(filePath)) {
    return {}
  }
  try {
    return jsonApi.parse(fs.readFileSync(filePath)) || {}
  } catch (e) {
    logOrConsole.error('解析远程配置版本选择失败:', filePath, ', error:', e)
    return {}
  }
}

function setRemoteSelection (suffix, version) {
  const selection = getRemoteSelection()
  const key = suffix || 'shared'
  if (version == null || version === '') {
    delete selection[key]
  } else {
    selection[key] = String(version)
  }
  fs.writeFileSync(getRemoteSelectionPath(), jsonApi.stringify(selection))
}

function getRemoteConfigVersions (suffix = '') {
  const selection = getRemoteSelection()[suffix || 'shared'] || ''
  const dir = getRemoteHistoryDir(suffix)
  const versions = []
  if (fs.existsSync(dir)) {
    const names = fs.readdirSync(dir).filter(name => name.endsWith('.json5')).sort().reverse()
    for (const name of names) {
      const version = name.slice(0, -'.json5'.length)
      let meta = {}
      try {
        meta = jsonApi.parse(fs.readFileSync(path.join(dir, name)))?.app?.metaInfo || {}
      } catch (e) {
        logOrConsole.warn('解析远程配置历史失败:', name, ', error:', e)
      }
      versions.push({
        version,
        id: meta.id || '',
        label: meta.version != null ? meta.version : version,
        selected: selection === version,
      })
    }
  }

  const liveMeta = getLiveRemoteConfig(suffix)?.app?.metaInfo
  if (liveMeta != null && (liveMeta.id != null || liveMeta.version != null)) {
    const hasSelection = selection !== '' && versions.some(item => item.version === selection)
    versions.unshift({
      version: '',
      id: liveMeta.id || '',
      label: liveMeta.version != null ? liveMeta.version : '',
      latest: true,
      selected: !hasSelection,
    })
  }
  return versions
}

function getSelectedRemoteConfig (suffix = '') {
  const selected = getRemoteSelection()[suffix || 'shared']
  if (!selected || !/^[\w.-]+$/i.test(String(selected))) {
    return null
  }
  const filePath = path.join(getRemoteHistoryDir(suffix), `${sanitizeRemoteVersion(selected)}.json5`)
  return fs.existsSync(filePath) ? loadConfigFromFile(filePath) : null
}

function saveRemoteConfigVersion (content, suffix = '', version = Date.now().toString()) {
  const dir = getRemoteHistoryDir(suffix)
  fs.mkdirSync(dir, { recursive: true })
  const safeVersion = sanitizeRemoteVersion(version)
  const filePath = path.join(dir, `${safeVersion}.json5`)
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, content)
  }
  return path.basename(filePath, '.json5')
}

function getLiveRemoteConfig (suffix = '') {
  return loadConfigFromFile(getRemoteConfigPath(suffix))
}

function getRemoteConfig (suffix = '') {
  const selected = getSelectedRemoteConfig(suffix)
  return selected || getLiveRemoteConfig(suffix)
}

function getAutomaticCompatibleConfigPath () {
  const dir = getUserBasePath()
  return path.join(dir, '/automaticCompatibleConfig.json')
}

/**
 * 生成 Xget 加速规则覆盖层。
 *
 * 用户启用 xget 插件并填写实例地址后，把样例配置里的 ${XGET_DOMAIN} 替换为该地址，
 * 按「用户本地配置」的优先级参与合并（在用户配置之前合并，用户配置仍可覆盖同名规则）。
 */
function getXgetOverlay (userConfig) {
  const xget = userConfig && userConfig.plugin && userConfig.plugin.xget
  if (xget == null || xget.enabled !== true) {
    return null
  }
  const rawUrl = xget.setting && xget.setting.instanceUrl
  if (rawUrl == null || String(rawUrl).trim() === '') {
    return null
  }

  let parsed
  try {
    let url = String(rawUrl).trim()
    if (!/^[a-z][a-z\d+.-]*:\/\//i.test(url)) {
      url = `https://${url}`
    }
    parsed = new URL(url)
  } catch {
    logOrConsole.warn('Xget 实例地址格式不正确，已跳过:', rawUrl)
    return null
  }
  if (!parsed.host) {
    return null
  }

  // 支持子路径部署：https://host/xget 作为实例地址时，规则里的 /gh、/npm 会拼到 /xget 后面
  const pathSuffix = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/+$/, '')
  const baseUrl = `${parsed.protocol}//${parsed.host}${pathSuffix}`

  const samplePath = path.join(__dirname, '..', 'modules', 'plugin', 'xget', 'xget_config.json5')
  try {
    const content = fs.readFileSync(samplePath, 'utf8')
      .replaceAll('https://${XGET_DOMAIN}', baseUrl)
      .replaceAll('${XGET_DOMAIN}', parsed.host)
    return jsonApi.parse(content)
  } catch (e) {
    logOrConsole.warn('加载 Xget 配置失败:', e.message)
    return null
  }
}

/**
 * 从文件读取配置
 *
 * @param userConfig 用户配置
 * @param defaultConfig 默认配置
 */
function getConfigFromFiles (userConfig, defaultConfig) {
  const merged = userConfig != null ? lodash.cloneDeep(userConfig) : {}

  const personalRemoteConfig = getRemoteConfig('_personal')
  const shareRemoteConfig = getRemoteConfig()

  mergeApi.doMerge(merged, personalRemoteConfig) // 先合并一次个人远程配置，使配置顺序在前
  mergeApi.doMerge(merged, shareRemoteConfig) // 先合并一次共享远程配置，使配置顺序在前
  mergeApi.doMerge(merged, defaultConfig) // 合并默认配置，顺序排在最后
  mergeApi.doMerge(merged, shareRemoteConfig) // 再合并一次共享远程配置，使配置生效
  mergeApi.doMerge(merged, personalRemoteConfig) // 再合并一次个人远程配置，使配置生效

  const xgetOverlay = getXgetOverlay(userConfig)
  if (xgetOverlay != null) {
    mergeApi.doMerge(merged, xgetOverlay) // Xget 加速规则：与用户本地配置同层，用户配置仍优先
  }

  if (userConfig != null) {
    mergeApi.doMerge(merged, userConfig) // 再合并一次用户配置，使用户配置重新生效
  }
  // 删除为null及[delete]的项
  mergeApi.deleteNullItems(merged)

  logOrConsole.info('加载及合并远程配置完成')
  return merged
}

module.exports = {
  getUserBasePath,

  loadConfigFromFile,

  getUserConfigPath,
  getUserConfig,

  getRemoteConfigPath,
  getRemoteConfig,
  getLiveRemoteConfig,
  getRemoteSelection,
  setRemoteSelection,
  getRemoteConfigVersions,
  saveRemoteConfigVersion,

  getAutomaticCompatibleConfigPath,

  getConfigFromFiles,
}

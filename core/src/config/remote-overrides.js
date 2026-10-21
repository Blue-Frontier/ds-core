const fs = require('node:fs')
const lodash = require('lodash')
const jsonApi = require('@blue-frontier/mitmproxy/src/json')
const mergeApi = require('../merge')

function hasOwn (value, key) {
  return value != null && Object.prototype.hasOwnProperty.call(value, key)
}

function isPlainObject (value) {
  return value != null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * 删除用户配置中由旧远程层产生、且仍由新远程层覆盖的值。
 *
 * 只遍历 newRemote 的路径：远程配置删除的路径不应反向删除用户显式配置。
 * 数组按整体值比较；null 与缺失值通过 hasOwn 分开处理。
 */
function pruneRemoteOverrides (user, baseline, remote) {
  const result = lodash.cloneDeep(user || {})
  pruneObject(result, baseline, remote, [])
  return result
}

function pruneObject (user, baseline, remote, path) {
  if (!isPlainObject(user) || !isPlainObject(baseline) || !isPlainObject(remote)) {
    return
  }

  for (const key of Object.keys(remote)) {
    if (path.length === 1 && path[0] === 'app' && key === 'remoteConfig') {
      continue
    }
    if (!hasOwn(user, key) || !hasOwn(baseline, key)) {
      continue
    }

    const userValue = user[key]
    const baselineValue = baseline[key]
    const remoteValue = remote[key]

    if (isPlainObject(remoteValue) && isPlainObject(userValue) && isPlainObject(baselineValue)) {
      pruneObject(userValue, baselineValue, remoteValue, path.concat(key))
      if (Object.keys(userValue).length === 0) {
        delete user[key]
      }
      continue
    }

    if (lodash.isEqual(userValue, baselineValue)) {
      delete user[key]
    }
  }
}

function mergeRemoteLayers (shared, personal) {
  const result = lodash.cloneDeep(shared || {})
  mergeApi.doMerge(result, lodash.cloneDeep(personal || {}))
  return result
}

function getRemoteSettings (userConfig, defaultConfig) {
  const defaults = lodash.get(defaultConfig, 'app.remoteConfig', {}) || {}
  const configured = lodash.get(userConfig, 'app.remoteConfig', {}) || {}
  return { ...defaults, ...configured }
}

function isRemoteConfigActive (userConfig, defaultConfig) {
  const remoteConfig = getRemoteSettings(userConfig, defaultConfig)
  return remoteConfig.enabled === true && Boolean(remoteConfig.url || remoteConfig.personalUrl)
}

function readUserConfigStrict (loader) {
  const configPath = loader.getUserConfigPath()
  if (!fs.existsSync(configPath)) {
    return { path: configPath, exists: false, text: '', value: {} }
  }
  const text = fs.readFileSync(configPath, 'utf8')
  return { path: configPath, exists: true, text, value: jsonApi.parse(text) }
}

function writeUserConfig (userFile, nextUser, preserveComments) {
  if (lodash.isEqual(userFile.value, nextUser)) {
    return false
  }

  const jsonText = jsonApi.stringify(nextUser)
  const preservedText = typeof preserveComments === 'function'
    ? preserveComments(userFile.path, jsonText)
    : jsonText
  const backupPath = `${userFile.path}.${Date.now()}.bak.json`
  if (userFile.exists) {
    fs.writeFileSync(backupPath, userFile.text)
  }
  fs.writeFileSync(userFile.path, preservedText)
  return true
}

/**
 * 根据当前远程缓存清理一次用户配置中的重复远程值。
 * 配置关闭或没有有效远程 URL 时保持用户文件不变。
 */
function persist (loader, defaultConfig, preserveComments) {
  const userFile = readUserConfigStrict(loader)
  if (!isRemoteConfigActive(userFile.value, defaultConfig)) {
    return false
  }

  const settings = getRemoteSettings(userFile.value, defaultConfig)
  const shared = settings.url ? loader.getRemoteConfig() : {}
  const personal = settings.personalUrl ? loader.getRemoteConfig('_personal') : {}
  const baseline = mergeRemoteLayers(shared, personal)
  const nextUser = pruneRemoteOverrides(userFile.value, baseline, baseline)
  return writeUserConfig(userFile, nextUser, preserveComments)
}

/**
 * 远程缓存更新前清理用户配置。
 *
 * oldShared/oldPersonal 是更新前的远程层，newLayer 是本次下载的新层，
 * suffix 为空表示共享层，否则表示个人层。个人层始终覆盖共享层。
 */
function prepareForRemoteUpdate ({ loader, defaultConfig, oldShared, oldPersonal, newLayer, suffix, preserveComments }) {
  const userFile = readUserConfigStrict(loader)
  if (!isRemoteConfigActive(userFile.value, defaultConfig)) {
    return { userFile, changed: false }
  }

  const oldBaseline = mergeRemoteLayers(oldShared, oldPersonal)
  const newShared = suffix === '_personal' ? oldShared : newLayer
  const newPersonal = suffix === '_personal' ? newLayer : oldPersonal
  const newBaseline = mergeRemoteLayers(newShared, newPersonal)
  const nextUser = pruneRemoteOverrides(userFile.value, oldBaseline, newBaseline)
  const changed = writeUserConfig(userFile, nextUser, preserveComments)
  return { userFile, changed }
}

module.exports = {
  getRemoteSettings,
  isRemoteConfigActive,
  mergeRemoteLayers,
  prepareForRemoteUpdate,
  pruneRemoteOverrides,
  persist,
  readUserConfigStrict,
}

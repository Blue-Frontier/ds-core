const fs = require('node:fs')
const lodash = require('lodash')
const matchUtil = require('@blue-frontier/mitmproxy/src/utils/util.match.js')
const { defaultConfig: defConfig } = require('./config/index.js')
const mergeApi = require('./merge.js')
const configLoader = require('./config/local-config-loader')
const log = require('./utils/util.log.core')

/**
 * 服务分组
 *
 * 分组名读取自配置文件的 `//` 注释（`config.json`、`remote_config.json5`、`remote_config_personal.json5`）：
 * `//` 之后的文字，去掉所有空白符后即为组名（区分大小写）。
 * 被注释掉的 JSON 内容、以及 `/* *\/` 块注释，都不作为组名（即：忽略分组错误）。
 *
 * 一个「服务」= 一个域名（或域名通配符），它在 `intercepts`、`preSetIpList`、`dns.mapping`、
 * `dns.ech.domains`、`dns.nat64.domains`、`whiteList` 等配置里可能同时存在多个配置项，页面上的一个开关会同时启停这些配置项。
 */

// 参与分组的配置项定义（顺序即分组优先级：靠前的配置项上的注释优先决定服务所属分组）
const SECTIONS = [
  { name: 'intercepts', path: ['server', 'intercepts'], label: '拦截', type: 'map' },
  { name: 'preSetIpList', path: ['server', 'preSetIpList'], label: '预设IP', type: 'map' },
  { name: 'dnsMapping', path: ['server', 'dns', 'mapping'], label: 'DNS', type: 'map' },
  // familyMapping 的键带有 `_` 前缀（如 `_*.github.com`），这里去掉前缀，与其它配置项合并为同一个服务
  { name: 'dnsFamilyMapping', path: ['server', 'dns', 'familyMapping'], label: 'DNS族', type: 'map', keyPrefix: '_' },
  { name: 'echDomains', path: ['server', 'dns', 'ech', 'domains'], label: 'ECH', type: 'array' },
  { name: 'echPreSetIpDomains', path: ['server', 'dns', 'ech', 'preSetIpDomains'], label: 'ECH预设IP', type: 'array' },
  // NAT64直连的域名（这些域名会自动按ECH域名处理，无需再单独加入ECH名单）
  { name: 'nat64Domains', path: ['server', 'dns', 'nat64', 'domains'], label: 'NAT64', type: 'array' },
  { name: 'whiteList', path: ['server', 'whiteList'], label: '白名单', type: 'map' },
]

// 增强模式（梯子）的配置项，单独分区展示
const ENHANCED_SECTIONS = [
  { name: 'overwallTargets', path: ['plugin', 'overwall', 'targets'], label: '增强', type: 'map' },
]

const DEFAULT_GROUP = '未分组'
const REGISTRY_PATH = ['app', 'serviceGroups', 'disabled']

/**
 * 判断注释内容是否是被注释掉的 JSON（这类注释不参与分组）
 */
function isJsonLikeComment (comment) {
  if (/^[[{"'}\],]/.test(comment)) {
    return true
  }
  if (comment.includes('":') || comment.includes('\':')) {
    return true
  }
  // 只由 JSON 标点组成的注释（如 `},`、`]`），是被注释掉的 JSON 片段
  if (/^[\s{}[\](),:"'`]+$/.test(comment)) {
    return true
  }
  // jsdoc 标记
  if (comment.startsWith('@')) {
    return true
  }
  return false
}

/**
 * 读取一个字符串（支持单引号、双引号与转义）
 */
function readStringAt (text, index) {
  const quote = text[index]
  let value = ''
  let i = index + 1
  while (i < text.length) {
    const ch = text[i]
    if (ch === '\\') {
      const nextChar = text[i + 1]
      if (nextChar === 'n') {
        value += '\n'
      } else if (nextChar === 't') {
        value += '\t'
      } else if (nextChar === 'r') {
        value += '\r'
      } else {
        value += nextChar
      }
      i += 2
      continue
    }
    if (ch === quote) {
      i++
      break
    }
    value += ch
    i++
  }
  return { value, next: i }
}

/**
 * 对象键的路径
 */
function keyPath (path, key) {
  return [...path, key].join('/')
}

/**
 * 数组项的路径（使用值本身作为路径的一部分，避免数组下标变化导致注释错位）
 */
function arrayItemPath (path, value) {
  return `${path.join('/')}#${value}`
}

/**
 * 未加引号的键的首字符（json5 允许，如 `server:`、`intercepts:`）
 */
function isIdentifierStart (ch) {
  return ch != null && /[a-z_$]/i.test(ch)
}

/**
 * 未加引号的键的后续字符
 */
function isIdentifierChar (ch) {
  return ch != null && /[\w$.-]/.test(ch)
}

/**
 * 解析配置文本里的 `//` 注释，得到「配置路径 → 组名」的映射
 *
 * @param text 配置文本（json5）
 * @returns {Map<string, string>} 「配置路径 → 组名」映射
 */
function parseCommentMap (text) {
  const map = new Map()
  if (text == null || text.length === 0) {
    return map
  }

  const stack = [] // 容器栈：{ path, type, group }
  let currentGroup = null // 当前生效的组名
  let lineHasContent = false // 注释之前，当前行是否已经有内容（用于区分整行注释与行尾注释）
  let lastPathKey = null // 最近一项的路径（用于行尾注释）
  let pendingKeyPath = null // 刚读取到的键的路径，等待其后是否跟着容器
  let i = 0

  const topPath = () => (stack.length === 0 ? [] : stack[stack.length - 1].path)
  const topType = () => (stack.length === 0 ? null : stack[stack.length - 1].type)

  while (i < text.length) {
    const ch = text[i]

    if (ch === '\n') {
      lineHasContent = false
      i++
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      i++
      continue
    }

    // 行注释
    if (ch === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i)
      const comment = text.slice(i + 2, end === -1 ? text.length : end).trim()
      i = end === -1 ? text.length : end
      if (comment && !isJsonLikeComment(comment)) {
        if (lineHasContent) {
          // 行尾注释：只作用于当前这一项
          if (lastPathKey != null) {
            map.set(lastPathKey, comment)
          }
        } else {
          currentGroup = comment
        }
      }
      continue
    }

    // 块注释
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end === -1 ? text.length : end + 2
      continue
    }

    // 字符串：可能是对象的键，也可能是数组里的项
    if (ch === '"' || ch === '\'') {
      const str = readStringAt(text, i)
      i = str.next
      lineHasContent = true

      // 判断后面是否跟着冒号（是冒号则说明这是一个键）
      let j = i
      while (j < text.length && (text[j] === ' ' || text[j] === '\t' || text[j] === '\r')) {
        j++
      }
      if (text[j] === ':') {
        const path = [...topPath(), str.value]
        const pathKey = keyPath(topPath(), str.value)
        lastPathKey = pathKey
        pendingKeyPath = path
        if (currentGroup != null) {
          map.set(pathKey, currentGroup)
        }
        i = j + 1
        continue
      }

      // 数组里的字符串项
      if (topType() === 'array') {
        const pathKey = arrayItemPath(topPath(), str.value)
        lastPathKey = pathKey
        if (currentGroup != null) {
          map.set(pathKey, currentGroup)
        }
      }
      continue
    }

    // 容器开始
    if (ch === '{' || ch === '[') {
      const parentArray = topType() === 'array' && pendingKeyPath == null
      const frame = {
        path: pendingKeyPath != null ? pendingKeyPath : (parentArray ? [...topPath(), `#${lodash.get(stack[stack.length - 1], 'index', 0)}`] : topPath()),
        type: ch === '{' ? 'object' : 'array',
        group: currentGroup,
        index: 0,
      }
      if (parentArray) {
        stack[stack.length - 1].index = lodash.get(stack[stack.length - 1], 'index', 0) + 1
      }
      stack.push(frame)
      // 进入子容器后，分组注释从空开始，避免外层的注释被错误地应用到内层的配置项上
      currentGroup = null
      pendingKeyPath = null
      lineHasContent = true
      i++
      continue
    }

    // 容器结束：还原进入容器前的组名，避免容器内部的说明性注释影响到外面的项
    if (ch === '}' || ch === ']') {
      const frame = stack.pop()
      if (frame != null) {
        currentGroup = frame.group
      }
      pendingKeyPath = null
      lineHasContent = true
      i++
      continue
    }

    // 未加引号的键（json5 允许），如 `server:`、`intercepts:`
    // 不识别它们会导致路径缺失层级，注释映射的键与配置项的实际路径对不上，分组全部失效
    if (isIdentifierStart(ch)) {
      let j = i
      while (j < text.length && isIdentifierChar(text[j])) {
        j++
      }
      const name = text.slice(i, j)
      let k = j
      while (k < text.length && (text[k] === ' ' || text[k] === '\t' || text[k] === '\r')) {
        k++
      }
      if (text[k] === ':') {
        const path = [...topPath(), name]
        const pathKey = keyPath(topPath(), name)
        lastPathKey = pathKey
        pendingKeyPath = path
        if (currentGroup != null) {
          map.set(pathKey, currentGroup)
        }
        i = k + 1
      } else {
        // 不是键，跳过这段标识符
        i = j
      }
      lineHasContent = true
      continue
    }

    // 分隔符与其它字符
    lineHasContent = true
    i++
  }

  return map
}

/**
 * 提取配置文本中的真实注释，跳过字符串内容里的行注释和块注释。
 * 这些注释不一定仍对应当前 JSON 节点（例如节点被远程配置清理），
 * 但仍应保留在用户配置文件中。
 */
function extractComments (text) {
  const comments = []
  if (text == null || text.length === 0) {
    return comments
  }

  let i = 0
  while (i < text.length) {
    const ch = text[i]
    if (ch === '"' || ch === '\'') {
      i = readStringAt(text, i).next
      continue
    }

    if (ch === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i + 2)
      const content = text.slice(i + 2, end === -1 ? text.length : end).trim()
      if (content) {
        comments.push(`// ${content}`)
      }
      i = end === -1 ? text.length : end + 1
      continue
    }

    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      const content = text.slice(i + 2, end === -1 ? text.length : end).trim()
      if (content) {
        comments.push(`/* ${content} */`)
      }
      i = end === -1 ? text.length : end + 2
      continue
    }

    i++
  }

  return [...new Set(comments)]
}

/**
 * 读取所有配置文件里的分组注释（用户配置 > 个人远程配置 > 共享远程配置）
 *
 * @returns {Map<string, string>} 「配置路径 → 组名」映射
 */
function getCommentMap () {
  const map = new Map()
  const files = [
    configLoader.getRemoteConfigPath(''),
    configLoader.getRemoteConfigPath('_personal'),
    configLoader.getUserConfigPath(),
  ]
  for (const file of files) {
    try {
      if (file && fs.existsSync(file)) {
        const text = fs.readFileSync(file).toString()
        for (const [key, value] of parseCommentMap(text)) {
          map.set(key, value)
        }
      }
    } catch (e) {
      log.warn('读取配置文件注释失败:', file, ', error:', e)
    }
  }
  return map
}

/**
 * 把注释写回 JSON 文本（保证在页面里启停服务后，配置文件里的分组注释不会丢失）
 *
 * @param jsonText JSON.stringify 生成的文本
 * @param commentMap 「配置路径 → 组名」映射
 */
function injectComments (jsonText, commentMap) {
  if (jsonText == null || commentMap == null || commentMap.size === 0) {
    return jsonText
  }

  const keyRe = /^(\s*)"((?:[^"\\]|\\.)*)"\s*:/
  const valueRe = /^(\s*)"((?:[^"\\]|\\.)*)"\s*,?$/
  const indentDepth = indent => indent.includes('\t') ? indent.length : Math.floor(indent.length / 2)
  const stack = []
  const lines = []

  const unescape = (text) => {
    try {
      return JSON.parse(`"${text}"`)
    } catch {
      return text
    }
  }

  for (const line of jsonText.split('\n')) {
    const keyMatch = keyRe.exec(line)
    if (keyMatch != null) {
      const depth = indentDepth(keyMatch[1])
      const key = unescape(keyMatch[2])
      stack.length = depth - 1
      const path = [...stack, key].join('/')
      const comment = commentMap.get(path)
      stack.push(key)
      if (comment != null) {
        lines.push(`${keyMatch[1]}// ${comment}`)
      }
      lines.push(line)
      continue
    }

    const valueMatch = valueRe.exec(line)
    if (valueMatch != null) {
      const depth = indentDepth(valueMatch[1])
      const value = unescape(valueMatch[2])
      stack.length = depth - 1
      const comment = commentMap.get(`${stack.join('/')}#${value}`)
      if (comment != null) {
        lines.push(`${valueMatch[1]}// ${comment}`)
      }
      lines.push(line)
      continue
    }

    lines.push(line)
  }

  return lines.join('\n')
}

/**
 * 保存配置前，把旧文件里的注释保留下来
 *
 * @param configPath 配置文件路径
 * @param jsonText 新的配置文本
 */
function preserveComments (configPath, jsonText) {
  try {
    if (configPath == null || !fs.existsSync(configPath)) {
      return jsonText
    }
    const oldText = fs.readFileSync(configPath).toString()
    const commentMap = parseCommentMap(oldText)
    const preserved = injectComments(jsonText, commentMap)
    const existingComments = new Set(extractComments(preserved))
    const orphanComments = extractComments(oldText).filter(comment => !existingComments.has(comment))
    if (orphanComments.length === 0) {
      return preserved
    }
    return `${preserved.trimEnd()}\n${orphanComments.join('\n')}\n`
  } catch (e) {
    log.warn('保留配置文件注释失败:', configPath, ', error:', e)
    return jsonText
  }
}

/**
 * 计算各个层级的配置对象（同时用于判断配置项的来源）
 *
 * @param config 当前生效的配置
 */
function getLevels (config) {
  const remoteEnabled = lodash.get(config, ['app', 'remoteConfig', 'enabled']) === true
  const remoteConfig = remoteEnabled ? configLoader.getRemoteConfig() : null
  const personalConfig = remoteEnabled ? configLoader.getRemoteConfig('_personal') : null
  const userConfig = configLoader.getUserConfig() || {}

  const baseConfig = lodash.cloneDeep(defConfig)
  if (remoteConfig != null) {
    mergeApi.doMerge(baseConfig, remoteConfig)
  }
  if (personalConfig != null) {
    mergeApi.doMerge(baseConfig, personalConfig)
  }
  // 这里不删除 null 项，这样被停用的配置项依然可以被列出来
  const allConfig = mergeApi.doMerge(lodash.cloneDeep(baseConfig), lodash.cloneDeep(userConfig))

  // 各层级的名称：取自各配置内的 app.metaInfo.id（内置配置是 internal，官方远程配置通常是 official）
  const ids = {
    internal: lodash.get(defConfig, ['app', 'metaInfo', 'id']) || 'internal',
    official: lodash.get(remoteConfig, ['app', 'metaInfo', 'id']) || 'official',
    personal: lodash.get(personalConfig, ['app', 'metaInfo', 'id']) || 'personal',
    user: 'user',
  }

  // 按优先级从高到低排列，用于判断某个配置项最终来自哪一层
  const sources = [
    { id: ids.user, config: userConfig },
    { id: ids.personal, config: personalConfig },
    { id: ids.official, config: remoteConfig },
    { id: ids.internal, config: defConfig },
  ].filter(level => level.config != null)

  return { baseConfig, allConfig, userConfig, ids, sources }
}

/**
 * 判断配置项（对象里的某个键）来自哪一层配置
 *
 * @param levels getLevels() 的结果
 * @param path 配置路径
 * @param key 配置项的键
 * @returns 层级名称，找不到时返回 null
 */
function getValueSource (levels, path, key) {
  for (const level of levels.sources) {
    const value = lodash.get(level.config, key == null ? path : [...path, key])
    // null 表示用户停用了该项，不算作该层提供了值
    if (value !== undefined && value !== null) {
      return level.id
    }
  }
  return null
}

/**
 * 判断数组类型的配置项来自哪一层配置
 *
 * @param levels getLevels() 的结果
 * @param path 配置路径
 * @param item 数组里的值
 * @returns 层级名称，找不到时返回 null
 */
function getArrayItemSource (levels, path, item) {
  for (const level of levels.sources) {
    const list = lodash.get(level.config, path)
    if (Array.isArray(list) && list.includes(item)) {
      return level.id
    }
  }
  return null
}

function isEnabledValue (value) {
  return value != null && value !== false && value !== 'false'
}

/**
 * 收集某个分区下的所有服务
 */
function collectItems (options) {
  const { sections, sectionPrefix, levels, commentMap, registry, config } = options
  const items = new Map()

  const addPart = (name, part, comment) => {
    const id = `${sectionPrefix}${name}`
    let item = items.get(id)
    if (item == null) {
      item = { id, name, group: comment || DEFAULT_GROUP, parts: [] }
      items.set(id, item)
    }
    if (item.group === DEFAULT_GROUP && comment != null) {
      item.group = comment
    }
    item.parts.push(part)
  }

  for (const section of sections) {
    const allValues = lodash.get(levels.allConfig, section.path)
    const baseValues = lodash.get(levels.baseConfig, section.path)
    const currentValues = lodash.get(config, section.path)

    if (section.type === 'map') {
      for (const key of Object.keys(allValues || {})) {
        const value = allValues[key]
        const baseValue = baseValues == null ? undefined : baseValues[key]
        const name = section.keyPrefix != null && key.startsWith(section.keyPrefix)
          ? key.slice(section.keyPrefix.length)
          : key
        let comment = commentMap.get(keyPath(section.path, key))
        if (comment == null && name !== key) {
          comment = commentMap.get(keyPath(section.path, name))
        }
        // 该配置项在内置/远程配置里已存在，且用户没有改动过：停用后只需忽略用户配置里的键即可恢复默认值
        const fromBase = baseValue !== undefined && lodash.isEqual(value, baseValue)
        addPart(name, {
          section: section.name,
          label: section.label,
          type: 'mapKey',
          path: section.path,
          key,
          // 该配置项的来源（internal / official / personal / user）
          source: getValueSource(levels, section.path, key),
          enabled: isEnabledValue(value),
          // 启用时用于恢复的值：优先使用内置/远程默认值，其次使用用户配置里的值
          value: baseValue !== undefined ? baseValue : value,
          // 用户配置里的值（未在用户配置里出现时为 undefined）
          currentValue: value,
          // 默认配置（内置+远程）里的值，未定义表示默认配置里没有这一项
          defaultValue: baseValue,
          hasDefault: baseValue !== undefined,
          fromBase,
        }, comment)
      }
    } else {
      const baseList = baseValues || []
      for (const value of allValues || []) {
        if (value == null) {
          continue
        }
        const hasDefault = baseList.includes(value)
        addPart(value, {
          section: section.name,
          label: section.label,
          type: 'arrayItem',
          path: section.path,
          value,
          source: getArrayItemSource(levels, section.path, value),
          enabled: (currentValues || []).includes(value),
          currentValue: value,
          defaultValue: hasDefault ? value : undefined,
          hasDefault,
        }, commentMap.get(arrayItemPath(section.path, value)))
      }
    }
  }

  // 被停用的服务（已从配置里移除），从停用记录中补回来
  for (const [id, entry] of Object.entries(registry || {})) {
    if (!id.startsWith(sectionPrefix) || !Array.isArray(entry?.parts)) {
      continue
    }
    const name = id.slice(sectionPrefix.length)
    let item = items.get(id)
    if (item == null) {
      item = { id, name, group: entry.group || DEFAULT_GROUP, parts: [] }
      items.set(id, item)
    }
    for (const part of entry.parts) {
      const exists = item.parts.find(itemPart => itemPart.section === part.section)
      if (exists == null) {
        item.parts.push({ ...part, enabled: false })
      } else if (part.source != null) {
        // 停用时记录下来的来源更准确（用户可能改过该配置项的值）
        exists.source = part.source
      }
    }
  }

  for (const item of items.values()) {
    for (const part of item.parts) {
      if (part.enabled == null) {
        part.enabled = isPartEnabled(config, part)
      }
    }
    item.enabled = item.parts.some(part => part.enabled === true)
    item.partial = item.enabled && item.parts.some(part => part.enabled !== true)
    // 该服务涉及到的所有来源，按优先级（user > personal > official > internal）排序
    const sourceOrder = levels.sources.map(level => level.id)
    item.sources = [...new Set(item.parts.map(part => part.source).filter(source => source != null))]
      .sort((a, b) => sourceOrder.indexOf(a) - sourceOrder.indexOf(b))
    item.source = item.sources[0] || null
  }

  return items
}

function isPartEnabled (config, part) {
  if (part.type === 'mapKey') {
    return isEnabledValue(lodash.get(config, [...part.path, part.key]))
  }
  return (lodash.get(config, part.path) || []).includes(part.value)
}

function buildGroups (items) {
  const groups = new Map()
  for (const item of items.values()) {
    const name = item.group || DEFAULT_GROUP
    if (!groups.has(name)) {
      groups.set(name, [])
    }
    groups.get(name).push(item)
  }

  const list = [...groups.entries()].map(([name, groupItems]) => ({
    name,
    items: groupItems.sort((a, b) => a.name.localeCompare(b.name)),
  }))

  // 「未分组」放到最后
  list.sort((a, b) => {
    if (a.name === DEFAULT_GROUP) {
      return 1
    }
    if (b.name === DEFAULT_GROUP) {
      return -1
    }
    return 0
  })

  return list
}

/**
 * 列出所有服务分组
 *
 * @param config 当前生效的配置
 * @param options { enhancedEnabled } 是否开启增强模式
 */
function listCatalog (config, options = {}) {
  const levels = getLevels(config)
  const commentMap = getCommentMap()
  const registry = lodash.get(config, REGISTRY_PATH) || {}
  const enhancedEnabled = options.enhancedEnabled === true

  const groups = buildGroups(collectItems({
    sections: SECTIONS,
    sectionPrefix: 'service::',
    levels,
    commentMap,
    registry,
    config,
  }))

  const enhanced = buildGroups(enhancedEnabled
    ? collectItems({
        sections: ENHANCED_SECTIONS,
        sectionPrefix: 'overwall::',
        levels,
        commentMap,
        registry,
        config,
      })
    : new Map())

  return {
    groups,
    enhanced: { enabled: enhancedEnabled, groups: enhanced },
    // 各层配置的名称，供界面显示配置来源
    sources: levels.ids,
  }
}

function readPartValue (config, part) {
  if (part.type === 'mapKey') {
    return lodash.get(config, [...part.path, part.key])
  }
  return part.value
}

function disablePart (config, part) {
  if (part.type === 'mapKey') {
    lodash.set(config, [...part.path, part.key], null)
    return
  }
  const values = lodash.get(config, part.path) || []
  lodash.set(config, part.path, values.filter(value => value !== part.value))
}

function enablePart (config, part) {
  if (part.type === 'mapKey') {
    if (part.fromBase === true) {
      // 该配置项来自内置/远程默认配置：把值置为 undefined，保存差异时会忽略这个键，
      // 从而回落到默认/远程配置里的值（config.json 里不会留下冗余内容）
      lodash.set(config, [...part.path, part.key], undefined)
      return
    }
    lodash.set(config, [...part.path, part.key], part.value)
    return
  }
  const values = lodash.get(config, part.path) || []
  if (!values.includes(part.value)) {
    lodash.set(config, part.path, [...values, part.value])
  }
}

/**
 * 启用/停用一批服务（直接修改传入的配置对象）
 *
 * @param config 当前生效的配置
 * @param ids 服务的 id 列表
 * @param enabled 是否启用
 * @param options { enhancedEnabled }
 * @returns 被修改的服务数量
 */
function applyEnabled (config, ids, enabled, options = {}) {
  const idSet = new Set(ids || [])
  if (idSet.size === 0) {
    return 0
  }

  const catalog = listCatalog(config, options)
  const items = [...catalog.groups, ...catalog.enhanced.groups].flatMap(group => group.items)
  const registry = lodash.cloneDeep(lodash.get(config, REGISTRY_PATH) || {})
  let count = 0

  for (const item of items) {
    if (!idSet.has(item.id)) {
      continue
    }
    count++

    if (enabled === true) {
      const entry = registry[item.id]
      const parts = entry != null && Array.isArray(entry.parts) ? entry.parts : item.parts
      for (const part of parts) {
        enablePart(config, part)
      }
      delete registry[item.id]
      continue
    }

    const parts = []
    for (const part of item.parts) {
      if (isPartEnabled(config, part)) {
        parts.push({
          ...part,
          enabled: false,
          // 来自内置/远程默认配置的项，恢复时只需要删除用户配置里的键，不必记录原值
          value: part.fromBase === true ? undefined : readPartValue(config, part),
        })
        disablePart(config, part)
      }
    }
    if (parts.length > 0) {
      registry[item.id] = { name: item.name, group: item.group, parts }
    }
  }

  if (Object.keys(registry).length === 0) {
    lodash.unset(config, REGISTRY_PATH)
    if (lodash.isEmpty(lodash.get(config, ['app', 'serviceGroups']))) {
      lodash.unset(config, ['app', 'serviceGroups'])
    }
  } else {
    lodash.set(config, REGISTRY_PATH, registry)
  }

  return count
}

/**
 * 修改用户自己添加/修改的配置项的值
 *
 * @param config 当前生效的配置
 * @param ids 服务的 id 列表
 * @param section 分区名
 * @param value 新的配置值
 * @param options { enhancedEnabled }
 * @returns 被修改的配置项数量
 */
function setPartValue (config, ids, section, value, options = {}) {
  const idSet = new Set(ids || [])
  if (idSet.size === 0 || section == null) {
    return 0
  }

  const levels = getLevels(config)
  const catalog = listCatalog(config, options)
  const items = [...catalog.groups, ...catalog.enhanced.groups].flatMap(group => group.items)

  for (const item of items) {
    if (!idSet.has(item.id)) {
      continue
    }
    for (const part of item.parts) {
      // 只能修改用户自己添加/修改的配置项
      if (part.section !== section || part.source !== levels.ids.user) {
        continue
      }
      if (part.type === 'mapKey') {
        lodash.set(config, [...part.path, part.key], value)
        return 1
      }
      const values = lodash.get(config, part.path) || []
      const next = values.includes(part.value)
        ? values.map(item0 => item0 === part.value ? value : item0)
        : [...values, value]
      lodash.set(config, part.path, next)
      return 1
    }
  }

  return 0
}

/**
 * 从生效配置里删除用户自己添加/修改的配置项
 *
 * @param config 当前生效的配置
 * @param part 配置项
 */
function removeUserPart (config, part) {
  if (part.type === 'mapKey') {
    // 置为 undefined：保存差异时会忽略该键，从而回落到默认/远程配置里的值；
    // 默认配置里没有该项时，这个键会从 config.json 里消失（即删除）
    lodash.set(config, [...part.path, part.key], undefined)
    return
  }
  const values = lodash.get(config, part.path) || []
  const rest = values.filter(value => value !== part.value)
  // 数组里没有其它值了，就把整个键删掉，回落到默认配置的数组
  lodash.set(config, part.path, rest.length === 0 ? undefined : rest)
}

/**
 * 把用户自己添加/修改的配置项恢复成默认值（内置 + 远程配置）
 * 默认配置里不存在该项时，直接删除
 *
 * @param config 当前生效的配置
 * @param ids 服务的 id 列表
 * @param sections 需要恢复的分区名列表（为空表示该服务的全部配置项）
 * @param options { enhancedEnabled }
 * @returns 被恢复的配置项数量
 */
function resetParts (config, ids, sections, options = {}) {
  const idSet = new Set(ids || [])
  if (idSet.size === 0) {
    return 0
  }
  const sectionSet = new Set(sections || [])

  const levels = getLevels(config)
  const catalog = listCatalog(config, options)
  const items = [...catalog.groups, ...catalog.enhanced.groups].flatMap(group => group.items)
  const registry = lodash.cloneDeep(lodash.get(config, REGISTRY_PATH) || {})
  let count = 0

  for (const item of items) {
    if (!idSet.has(item.id)) {
      continue
    }
    for (const part of item.parts) {
      // 只能恢复用户自己添加/修改的配置项
      if (part.source !== levels.ids.user) {
        continue
      }
      if (sectionSet.size > 0 && !sectionSet.has(part.section)) {
        continue
      }
      removeUserPart(config, part)
      count++

      // 同步停用记录：恢复即彻底删除，不再需要记录该项
      const entry = registry[item.id]
      if (entry != null && Array.isArray(entry.parts)) {
        entry.parts = entry.parts.filter(entryPart => entryPart.section !== part.section)
        if (entry.parts.length === 0) {
          delete registry[item.id]
        }
      }
    }
  }

  if (count > 0) {
    if (Object.keys(registry).length === 0) {
      lodash.unset(config, REGISTRY_PATH)
      if (lodash.isEmpty(lodash.get(config, ['app', 'serviceGroups']))) {
        lodash.unset(config, ['app', 'serviceGroups'])
      }
    } else {
      lodash.set(config, REGISTRY_PATH, registry)
    }
  }

  return count
}

/**
 * 判断一个服务（配置里的域名匹配串）是否会作用于指定域名。
 *
 * 判断规则与代理（mitmproxy 的 `domainRegexply` + `matchHostname`）保持一致：
 * - `.*` / `*` / `true`：匹配所有域名
 * - 以 `^` 开头：按正则表达式匹配
 * - 含 `*`：按通配符匹配（`.` 转义，`*` 转成 `.*`）
 * - 其它：精确匹配；另外 `*.域名`、`*域名` 也能匹配到 `域名` 本身
 *
 * @param {string} pattern 配置里的域名匹配串（服务名）
 * @param {string} hostname 待查找的域名
 * @returns {boolean} 该匹配串是否会作用于这个域名
 */
function isHostnameMatched (pattern, hostname) {
  if (pattern == null || hostname == null) {
    return false
  }
  const host = String(hostname).trim().toLowerCase()
  const name = String(pattern).trim()
  if (host.length === 0 || name.length === 0) {
    return false
  }
  if (name === '.*' || name === '*' || name === 'true') {
    return true
  }
  try {
    const hostMap = matchUtil.domainMapRegexply({ [name]: true })
    if (hostMap.origin[host] != null
      || hostMap.origin[`*.${host}`] != null
      || hostMap.origin[`*${host}`] != null) {
      return true
    }
    for (const regexp of Object.keys(hostMap)) {
      if (regexp === 'origin') {
        continue
      }
      if (host.match(regexp) != null) {
        return true
      }
    }
  } catch {
    // 匹配串本身不是合法的正则表达式（代理里同样会被忽略）
  }
  return false
}

/**
 * 找出所有会作用于指定域名的服务（普通分区 + 增强模式分区）
 * @param {object} catalog listCatalog() 的返回值
 * @param {string} hostname 待查找的域名
 * @returns {Array<object>} 命中的服务（含 id、name、group、enhanced）
 */
function matchCatalog (catalog, hostname) {
  const result = []
  const sections = [
    { groups: catalog == null ? [] : catalog.groups, enhanced: false },
    { groups: catalog == null || catalog.enhanced == null ? [] : catalog.enhanced.groups, enhanced: true },
  ]
  for (const section of sections) {
    for (const group of section.groups || []) {
      for (const item of group.items || []) {
        if (isHostnameMatched(item.name, hostname)) {
          result.push({ id: item.id, name: item.name, group: group.name, enhanced: section.enhanced, enabled: item.enabled })
        }
      }
    }
  }
  return result
}

module.exports = {
  DEFAULT_GROUP,
  SECTIONS,
  ENHANCED_SECTIONS,
  parseCommentMap,
  getCommentMap,
  injectComments,
  preserveComments,
  listCatalog,
  applyEnabled,
  setPartValue,
  resetParts,
  isHostnameMatched,
  matchCatalog,
}

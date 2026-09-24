/**
 * ds-p2p://token@host:port#name
 * - token 可省略：ds-p2p://host:port#name
 * - 多节点订阅：一行一个 ds-p2p://
 */

const SCHEME = 'ds-p2p:'

function encodeName (name) {
  return name ? `#${encodeURIComponent(name)}` : ''
}

/**
 * @param {{token?: string, host: string, port: number|string, name?: string}} node
 * @returns {string}
 */
function formatLink (node) {
  if (!node || !node.host) {
    throw new Error('ds-p2p link requires host')
  }
  const port = node.port || 31288
  const auth = node.token ? `${encodeURIComponent(node.token)}@` : ''
  return `${SCHEME}//${auth}${node.host}:${port}${encodeName(node.name || '')}`
}

/**
 * @param {string} raw
 * @returns {{token?: string, host: string, port: number, name?: string}}
 */
function parseLink (raw) {
  const value = String(raw || '').trim()
  if (!value) {
    return null
  }
  if (!value.startsWith(`${SCHEME}//`) && !value.startsWith('ds-p2p://')) {
    // 允许省略 scheme
    return parseLink(`ds-p2p://${value}`)
  }
  let rest = value.replace(/^ds-p2p:\/\//i, '')
  let name
  const hashIdx = rest.indexOf('#')
  if (hashIdx >= 0) {
    name = decodeURIComponent(rest.slice(hashIdx + 1))
    rest = rest.slice(0, hashIdx)
  }
  let token
  const atIdx = rest.lastIndexOf('@')
  if (atIdx >= 0) {
    token = decodeURIComponent(rest.slice(0, atIdx))
    rest = rest.slice(atIdx + 1)
  }
  let host
  let port = 31288
  const v6 = rest.match(/^\[([^\]]+)\](?::(\d+))?$/)
  if (v6) {
    host = v6[1]
    port = v6[2] ? Number(v6[2]) : 31288
  } else {
    const parts = rest.split(':')
    if (parts.length === 1 && parts[0]) {
      host = parts[0]
    } else if (parts.length === 2 && parts[0] && parts[1]) {
      host = parts[0]
      port = Number(parts[1])
    } else {
      return null
    }
  }
  if (!host || !Number.isFinite(port) || port <= 0 || port > 65535) {
    return null
  }
  const node = { host, port }
  if (token) {
    node.token = token
  }
  if (name) {
    node.name = name
  }
  return node
}

/**
 * 解析多行订阅文本，忽略空行与 # 注释
 * @returns {Array<{token?: string, host: string, port: number, name?: string}>}
 */
function parsePeerList (text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map(parseLink)
    .filter(Boolean)
}

module.exports = {
  SCHEME,
  formatLink,
  parseLink,
  parsePeerList,
}

/**
 * ds-p2p 链接（单一格式）
 * ds-p2p://<ek>.<iv>.<ct>#name
 *   ek / iv / ct 均为 base64url；用 . 分段
 *   AES-128-CTR，ek 每次随机 16B，iv 16B
 */

const SCHEME = 'ds-p2p:'
const net = require('node:net')
const crypto = require('node:crypto')

const EK_LEN = 16
const IV_LEN = 16

function toBase64Url (buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function fromBase64Url (str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/')
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  return Buffer.from(s + pad, 'base64')
}

function encodeName (name) {
  return name ? `#${encodeURIComponent(name)}` : ''
}

function packBinary (token, host, port) {
  const ipVersion = net.isIP(host)
  const tokenBuf = token ? Buffer.from(String(token), 'utf8') : Buffer.alloc(0)
  if (ipVersion === 4) {
    const addr = host.split('.').map((x) => Number(x) & 0xff)
    const buf = Buffer.alloc(2 + 2 + 4 + tokenBuf.length)
    buf[0] = 2
    buf[1] = token ? 1 : 0
    buf.writeUInt16BE(port, 2)
    addr.forEach((b, i) => {
      buf[4 + i] = b
    })
    tokenBuf.copy(buf, 8)
    return buf
  }
  const hostBuf = Buffer.from(host, 'utf8')
  const flags = (token ? 1 : 0) | (ipVersion === 6 ? 2 : 4)
  const buf = Buffer.alloc(2 + 2 + 1 + hostBuf.length + tokenBuf.length)
  buf[0] = 2
  buf[1] = flags
  buf.writeUInt16BE(port, 2)
  buf[4] = hostBuf.length
  hostBuf.copy(buf, 5)
  tokenBuf.copy(buf, 5 + hostBuf.length)
  return buf
}

function unpackBinary (buf) {
  if (!buf || buf.length < 4 || buf[0] !== 2) {
    return null
  }
  const flags = buf[1]
  const port = buf.readUInt16BE(2)
  const hasToken = (flags & 1) === 1
  const isV6 = (flags & 2) === 2
  const isName = (flags & 4) === 4
  if (isV6 || isName) {
    const len = buf[4]
    const host = buf.subarray(5, 5 + len).toString('utf8')
    const token = hasToken ? buf.subarray(5 + len).toString('utf8') : ''
    const node = { host, port }
    if (token) {
      node.token = token
    }
    return node
  }
  if (buf.length < 8) {
    return null
  }
  const host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`
  const token = hasToken ? buf.subarray(8).toString('utf8') : ''
  const node = { host, port }
  if (token) {
    node.token = token
  }
  return node
}

function formatLink (node) {
  if (!node || !node.host) {
    throw new Error('ds-p2p link requires host')
  }
  const port = Number(node.port) || 31288
  const payload = packBinary(node.token, node.host, port)
  const ek = crypto.randomBytes(EK_LEN)
  const iv = crypto.randomBytes(IV_LEN)
  const cipher = crypto.createCipheriv('aes-128-ctr', ek, iv)
  const ct = Buffer.concat([cipher.update(payload), cipher.final()])
  return `${SCHEME}//${toBase64Url(ek)}.${toBase64Url(iv)}.${toBase64Url(ct)}${encodeName(node.name || '')}`
}

function parseLink (raw) {
  const value = String(raw || '').trim()
  if (!value || !/^ds-p2p:\/\//i.test(value)) {
    return null
  }
  let rest = value.replace(/^ds-p2p:\/\//i, '')
  let name
  const hashIdx = rest.indexOf('#')
  if (hashIdx >= 0) {
    try {
      name = decodeURIComponent(rest.slice(hashIdx + 1))
    } catch {
      name = rest.slice(hashIdx + 1)
    }
    rest = rest.slice(0, hashIdx)
  }
  const parts = rest.split('.')
  if (parts.length !== 3) {
    return null
  }
  const ek = fromBase64Url(parts[0])
  const iv = fromBase64Url(parts[1])
  const ct = fromBase64Url(parts[2])
  if (ek.length !== EK_LEN || iv.length !== IV_LEN || !ct.length) {
    return null
  }
  const decipher = crypto.createDecipheriv('aes-128-ctr', ek, iv)
  const plain = Buffer.concat([decipher.update(ct), decipher.final()])
  const node = unpackBinary(plain)
  if (!node) {
    return null
  }
  if (name) {
    node.name = name
  }
  return node
}

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

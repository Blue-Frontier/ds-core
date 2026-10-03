/**
 * 离线卡密（Ed25519 签名），开发期实现，便于以后迁链上核销。
 *
 * 格式: ds-card://<b64url(payloadJson)>.<b64url(sig)>
 * payload: { id, gb, exp, node, n }
 *   id   随机 16B hex（防重放键）
 *   gb   流量配额（数字）
 *   exp  过期时间 Unix 秒
 *   node 发行节点公钥 base64url（SPKI der）
 *   n    随机 nonce
 */
const fs = require('node:fs')
const crypto = require('node:crypto')
const identity = require('./identity')

const SCHEME = 'ds-card:'

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

function loadPrivateKey () {
  return identity.getPrivateKeyObject()
}

async function ensureKeys () {
  await identity.ensureIdentity()
}

function loadPublicKey () {
  return identity.getPublicKeyObject()
}

/**
 * @param {{gb: number, expireAt?: number, ttlDays?: number, node?: string}} options
 * @returns {string} ds-card://...
 */
async function issueCard (options = {}) {
  await ensureKeys()
  const gb = Number(options.gb)
  if (!Number.isFinite(gb) || gb <= 0) {
    throw new Error('gb must be positive')
  }
  const expireAt = options.expireAt
    || Math.floor(Date.now() / 1000) + Math.floor((options.ttlDays || 30) * 24 * 3600)
  const pub = loadPublicKey()
  const payload = {
    id: crypto.randomBytes(16).toString('hex'),
    gb,
    exp: expireAt,
    node: toBase64Url(pub.export({ type: 'spki', format: 'der' })),
    n: toBase64Url(crypto.randomBytes(8)),
  }
  const body = Buffer.from(JSON.stringify(payload), 'utf8')
  const sig = crypto.sign(null, body, loadPrivateKey())
  return `${SCHEME}//${toBase64Url(body)}.${toBase64Url(sig)}`
}

function parseCard (raw) {
  const value = String(raw || '').trim()
  if (!value || !/^ds-card:\/\//i.test(value)) {
    return null
  }
  const rest = value.replace(/^ds-card:\/\//i, '')
  const parts = rest.split('.')
  if (parts.length !== 2) {
    return null
  }
  let payload
  try {
    payload = JSON.parse(fromBase64Url(parts[0]).toString('utf8'))
  } catch {
    return null
  }
  const sig = fromBase64Url(parts[1])
  return { payload, sig, body: fromBase64Url(parts[0]) }
}

/**
 * @returns {{ok: boolean, reason?: string, payload?: object}}
 */
async function verifyCard (raw, options = {}) {
  await ensureKeys()
  const parsed = parseCard(raw)
  if (!parsed) {
    return { ok: false, reason: 'bad format' }
  }
  const { payload, sig, body } = parsed
  if (!payload || !payload.id || !Number.isFinite(Number(payload.gb))) {
    return { ok: false, reason: 'bad payload' }
  }
  try {
    let pub
    if (payload.node) {
      pub = crypto.createPublicKey({
        key: fromBase64Url(payload.node),
        format: 'der',
        type: 'spki',
      })
    } else {
      pub = loadPublicKey()
    }
    const ok = crypto.verify(null, body, pub, sig)
    if (!ok) {
      return { ok: false, reason: 'bad signature' }
    }
  } catch (e) {
    return { ok: false, reason: e.message }
  }
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp && Number(payload.exp) < now) {
    return { ok: false, reason: 'expired' }
  }
  return { ok: true, payload }
}

function defaultStorePath () {
  const path = require('node:path')
  const os = require('node:os')
  const home = process.env.USERPROFILE || process.env.HOME || os.homedir()
  return path.resolve(home, './.dev-sidecar/p2p-cards.json')
}

function loadUsedCards (storePath) {
  try {
    const p = storePath || defaultStorePath()
    if (!fs.existsSync(p)) {
      return {}
    }
    return JSON.parse(fs.readFileSync(p, 'utf8')) || {}
  } catch {
    return {}
  }
}

function saveUsedCards (map, storePath) {
  const p = storePath || defaultStorePath()
  fs.mkdirSync(require('node:path').dirname(p), { recursive: true })
  fs.writeFileSync(p, `${JSON.stringify(map, null, 2)}\n`, 'utf8')
}

/**
 * 核销：验签 + 过期 + 防双花
 */
async function redeemCard (raw, options = {}) {
  const result = await verifyCard(raw, options)
  if (!result.ok) {
    return result
  }
  const storePath = options.storePath
  const used = loadUsedCards(storePath)
  const id = result.payload.id
  if (used[id]) {
    return { ok: false, reason: 'already used' }
  }
  used[id] = { redeemedAt: Date.now(), gb: result.payload.gb }
  saveUsedCards(used, storePath)
  return { ok: true, payload: result.payload }
}

module.exports = {
  SCHEME,
  issueCard,
  parseCard,
  verifyCard,
  redeemCard,
  loadPrivateKey,
  loadPublicKey,
  nodeKeyPath: identity.identityPath,
}

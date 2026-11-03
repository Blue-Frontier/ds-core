/**
 * 节点身份：公钥/nodeId 可明文；私钥走 SecretStore（keytar / 口令加密文件）。
 * 每次 getIdentity() 检测，缺失则重新生成。
 */
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const crypto = require('node:crypto')
const secretStore = require('@blue-frontier/dev-sidecar/src/utils/util.secret-store')
const log = require('../../utils/util.log.server')

const SECRET_ACCOUNT = 'p2p-identity-private-key'

function userBase () {
  const home = process.env.USERPROFILE || process.env.HOME || os.homedir()
  return path.resolve(home, './.dev-sidecar')
}

function identityPath () {
  return path.join(userBase(), 'p2p-identity.json')
}

function nodeIdFromPublicKey (publicKeyDer) {
  return crypto.createHash('sha256').update(publicKeyDer).digest('base64url')
}

function loadOrCreateIdentity () {
  const file = identityPath()
  let record = null
  if (fs.existsSync(file)) {
    try {
      record = JSON.parse(fs.readFileSync(file, 'utf8'))
    } catch {
      record = null
    }
  }

  if (record && record.publicKey && record.nodeId && (record.privateKey || record.privateKeyStored)) {
    const expected = nodeIdFromPublicKey(Buffer.from(record.publicKey, 'base64'))
    if (record.nodeId !== expected) {
      record.nodeId = expected
      fs.writeFileSync(file, `${JSON.stringify(stripPrivate(record), null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    }
    return record
  }

  // 生成新身份
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  const pubDer = publicKey.export({ type: 'spki', format: 'der' })
  const privB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
  record = {
    nodeId: nodeIdFromPublicKey(pubDer),
    createdAt: new Date().toISOString(),
    publicKey: pubDer.toString('base64'),
    privateKeyStored: true,
  }
  fs.mkdirSync(userBase(), { recursive: true })
  // 私钥不写进 json，交给 SecretStore
  fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
  // 同步写入（首次）
  record.privateKey = privB64
  // fire and forget 会导致首次读不到；改为在 loadIdentity 时 ensure
  return record
}

function stripPrivate (record) {
  const copy = { ...record }
  delete copy.privateKey
  copy.privateKeyStored = true
  return copy
}

/** 确保 SecretStore 中有私钥；若仅有旧明文则迁移 */
function ensurePrivateKeyStored (record) {
  return (async () => {
    if (record.privateKey) {
      await secretStore.setSecret(SECRET_ACCOUNT, record.privateKey)
      const file = identityPath()
      if (fs.existsSync(file)) {
        try {
          const onDisk = JSON.parse(fs.readFileSync(file, 'utf8'))
          if (onDisk.privateKey) {
            fs.writeFileSync(file, `${JSON.stringify(stripPrivate(onDisk), null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
          }
        } catch {
          // ignore
        }
      }
      reconcilePublicKey(record, record.privateKey)
      return record.privateKey
    }
    let stored = await secretStore.getSecret(SECRET_ACCOUNT)
    if (!stored) {
      const { privateKey } = crypto.generateKeyPairSync('ed25519')
      // 重新生成会改公钥，应仅在丢失时走到这里
      const pubDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
      stored = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
      await secretStore.setSecret(SECRET_ACCOUNT, stored)
      record.publicKey = pubDer.toString('base64')
      record.nodeId = nodeIdFromPublicKey(pubDer)
      record.privateKeyStored = true
      fs.writeFileSync(identityPath(), `${JSON.stringify(stripPrivate(record), null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    }
    record.privateKey = stored
    reconcilePublicKey(record, stored)
    return stored
  })()
}

/**
 * 密钥库里的私钥才是可用的那一半：如果它和 identity.json 里的公钥对不上，
 * 按私钥重建公钥与 nodeId（私钥无法从公钥反推）。
 *
 * 这种不一致常见于 SecretStore 后端切换（keytar ↔ 口令加密文件）后两边各存了一把键：
 * 用密钥库私钥签名、却把文件里的公钥写进卡密，验签必然 bad signature，
 * 而且每个用到身份的地方都会跟着错。发现即修复，并写回身份文件。
 */
function reconcilePublicKey (record, privateKeyB64) {
  let pubDer
  try {
    pubDer = crypto.createPublicKey(crypto.createPrivateKey({
      key: Buffer.from(privateKeyB64, 'base64'),
      format: 'der',
      type: 'pkcs8',
    })).export({ type: 'spki', format: 'der' })
  } catch (e) {
    log.warn('节点私钥无法解析，跳过公钥一致性修复:', e.message)
    return record
  }
  const nodeId = nodeIdFromPublicKey(pubDer)
  const publicKey = pubDer.toString('base64')
  if (record.publicKey === publicKey && record.nodeId === nodeId) {
    return record
  }
  log.warn('节点身份的公钥与系统密钥库里的私钥不一致，已按私钥重建公钥与 nodeId')
  record.publicKey = publicKey
  record.nodeId = nodeId
  record.privateKeyStored = true
  try {
    fs.writeFileSync(identityPath(), `${JSON.stringify(stripPrivate(record), null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
  } catch (e) {
    log.warn('写回节点身份文件失败:', e)
  }
  return record
}

let cached = null
let pendingEnsure = null

function getIdentity () {
  if (cached) {
    return cached
  }
  cached = loadOrCreateIdentity()
  return cached
}

/** 异步：保证私钥在 SecretStore 中，并返回 identity */
async function ensureIdentity () {
  const rec = getIdentity()
  // 并发调用共享同一次初始化。原先在 await 期间缓存会被 getIdentity() 重建
  // （旧判断条件依赖 privateKey，此时尚未写入），致后续 getPrivateKeyObject() 读到的
  // 记录与 ensureIdentity() 填充的不是同一个而报“private key not loaded”；
  // 私钥缺失时并发还会各自生成新身份，导致公钥/nodeId 漂移。
  if (!pendingEnsure) {
    pendingEnsure = ensurePrivateKeyStored(rec).finally(() => {
      pendingEnsure = null
    })
  }
  await pendingEnsure
  return rec
}

function getPublicKeyObject () {
  const rec = getIdentity()
  return crypto.createPublicKey({
    key: Buffer.from(rec.publicKey, 'base64'),
    format: 'der',
    type: 'spki',
  })
}

function getPrivateKeyObject () {
  const rec = getIdentity()
  if (!rec.privateKey) {
    throw new Error('identity private key not loaded; call ensureIdentity() first')
  }
  return crypto.createPrivateKey({
    key: Buffer.from(rec.privateKey, 'base64'),
    format: 'der',
    type: 'pkcs8',
  })
}

function signBytes (data) {
  return crypto.sign(null, Buffer.from(data), getPrivateKeyObject())
}

function verifyBytes (data, sig, publicKeyDerB64) {
  const key = crypto.createPublicKey({
    key: Buffer.from(publicKeyDerB64, 'base64'),
    format: 'der',
    type: 'spki',
  })
  return crypto.verify(null, Buffer.from(data), key, sig)
}

module.exports = {
  identityPath,
  getIdentity,
  ensureIdentity,
  nodeIdFromPublicKey,
  getPublicKeyObject,
  getPrivateKeyObject,
  signBytes,
  verifyBytes,
  SECRET_ACCOUNT,
}

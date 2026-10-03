/**
 * 节点身份：公钥/nodeId 可明文；私钥走 SecretStore（keytar / 口令加密文件）。
 * 每次 getIdentity() 检测，缺失则重新生成。
 */
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const crypto = require('node:crypto')
const secretStore = require('@blue-frontier/dev-sidecar/src/utils/util.secret-store')

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
    return stored
  })()
}

let cached = null

function getIdentity () {
  if (cached && cached.privateKey) {
    return cached
  }
  cached = loadOrCreateIdentity()
  return cached
}

/** 异步：保证私钥在 SecretStore 中，并返回 identity */
async function ensureIdentity () {
  const rec = getIdentity()
  await ensurePrivateKeyStored(rec)
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

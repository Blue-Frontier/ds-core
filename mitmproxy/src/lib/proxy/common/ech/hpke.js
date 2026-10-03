const crypto = require('node:crypto')

/**
 * HPKE（RFC 9180）Base Mode 实现，只覆盖 ECH（RFC 9849）需要的算法组合：
 *   KEM  DHKEM(X25519, HKDF-SHA256)  = 0x0020
 *   KDF  HKDF-SHA256                 = 0x0001
 *   AEAD AES-128-GCM                 = 0x0001
 *
 * 文件里同时提供 TLS 1.3 记录层需要的 HKDF / AEAD 工具，避免重复实现。
 */

const KEM_X25519_HKDF_SHA256 = 0x0020
const KDF_HKDF_SHA256 = 0x0001
const AEAD_AES_128_GCM = 0x0001

const HPKE_HASH = 'sha256'
const HPKE_AEAD_CIPHER = 'aes-128-gcm'
const HPKE_AEAD_KEY_LENGTH = 16
const HPKE_AEAD_NONCE_LENGTH = 12
const HPKE_AEAD_TAG_LENGTH = 16

const KEM_SUITE_ID = Buffer.concat([Buffer.from('KEM'), i2osp2(KEM_X25519_HKDF_SHA256)])
const HPKE_SUITE_ID = Buffer.concat([
  Buffer.from('HPKE'),
  i2osp2(KEM_X25519_HKDF_SHA256),
  i2osp2(KDF_HKDF_SHA256),
  i2osp2(AEAD_AES_128_GCM),
])

function i2osp2 (value) {
  const buf = Buffer.alloc(2)
  buf.writeUInt16BE(value >>> 0, 0)
  return buf
}

function hashLength (hashName) {
  return crypto.createHash(hashName).digest().length
}

function hmac (hashName, key, data) {
  return crypto.createHmac(hashName, key).update(data).digest()
}

/**
 * HKDF-Extract（RFC 5869）
 */
function hkdfExtract (hashName, salt, ikm) {
  return hmac(hashName, salt, ikm)
}

/**
 * HKDF-Expand（RFC 5869）
 */
function hkdfExpand (hashName, prk, info, length) {
  const hashLen = hashLength(hashName)
  const blocks = Math.ceil(length / hashLen)
  const output = Buffer.alloc(blocks * hashLen)
  let prev = Buffer.alloc(0)
  for (let i = 0; i < blocks; i++) {
    prev = hmac(hashName, prk, Buffer.concat([prev, info, Buffer.from([i + 1])]))
    prev.copy(output, i * hashLen)
  }
  return output.subarray(0, length)
}

/**
 * TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）
 */
function hkdfExpandLabel (hashName, secret, label, context, length) {
  const fullLabel = Buffer.concat([Buffer.from('tls13 '), Buffer.from(label)])
  const hkdfLabel = Buffer.concat([
    i2osp2(length),
    Buffer.from([fullLabel.length]),
    fullLabel,
    Buffer.from([context.length]),
    context,
  ])
  return hkdfExpand(hashName, secret, hkdfLabel, length)
}

/**
 * TLS 1.3 Derive-Secret（RFC 8446 §7.1）：messages 传入的是 Transcript-Hash 结果
 */
function deriveSecret (hashName, secret, label, transcriptHash) {
  return hkdfExpandLabel(hashName, secret, label, transcriptHash, hashLength(hashName))
}

/**
 * HPKE LabeledExtract / LabeledExpand（RFC 9180 §4）
 */
function labeledExtract (suiteId, salt, label, ikm) {
  return hkdfExtract(HPKE_HASH, salt, Buffer.concat([Buffer.from('HPKE-v1'), suiteId, Buffer.from(label), ikm]))
}

function labeledExpand (suiteId, prk, label, info, length) {
  const labeledInfo = Buffer.concat([
    i2osp2(length),
    Buffer.from('HPKE-v1'),
    suiteId,
    Buffer.from(label),
    info,
  ])
  return hkdfExpand(HPKE_HASH, prk, labeledInfo, length)
}

/**
 * 把 AEAD 序号异或到 nonce 的后 8 字节（RFC 8446 §5.3 / RFC 9180 §5.2）
 */
function buildNonce (iv, seq) {
  const nonce = Buffer.from(iv)
  const offset = nonce.length - 8
  const high = Math.floor(seq / 0x100000000)
  const low = seq >>> 0
  nonce.writeUInt32BE((nonce.readUInt32BE(offset) ^ (high >>> 0)) >>> 0, offset)
  nonce.writeUInt32BE((nonce.readUInt32BE(offset + 4) ^ low) >>> 0, offset + 4)
  return nonce
}

/**
 * 通用 AEAD 加密，返回 密文||tag
 */
function aeadSeal ({ cipher, key, iv, seq = 0, aad, plaintext }) {
  const nonce = buildNonce(iv, seq)
  const cipheriv = crypto.createCipheriv(cipher, key, nonce, { authTagLength: 16 })
  cipheriv.setAAD(aad)
  return Buffer.concat([cipheriv.update(plaintext), cipheriv.final(), cipheriv.getAuthTag()])
}

/**
 * 通用 AEAD 解密，入参为 密文||tag
 */
function aeadOpen ({ cipher, key, iv, seq = 0, aad, ciphertext }) {
  const tagOffset = ciphertext.length - 16
  const nonce = buildNonce(iv, seq)
  const decipher = crypto.createDecipheriv(cipher, key, nonce, { authTagLength: 16 })
  decipher.setAAD(aad)
  decipher.setAuthTag(ciphertext.subarray(tagOffset))
  return Buffer.concat([decipher.update(ciphertext.subarray(0, tagOffset)), decipher.final()])
}

/** X25519 公钥的 SPKI(DER) 前缀：SEQUENCE(42){ SEQUENCE(5){ OID 1.3.101.110 }, BIT STRING(33) } */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')
/** X25519 私钥的 PKCS8(DER) 前缀：SEQUENCE(46){ INTEGER 0, SEQUENCE(5){ OID 1.3.101.110 }, OCTET STRING(34){ OCTET STRING(32) } } */
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

/**
 * 生成 X25519 密钥对（Node 的 crypto.createECDH 不支持 x25519）
 */
function generateX25519KeyPair () {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519')
  return {
    publicKey,
    privateKey,
    publicKeyRaw: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32),
  }
}

function x25519PublicKeyFromRaw (raw) {
  return crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  })
}

function x25519PrivateKeyFromRaw (raw) {
  return crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  })
}

/**
 * X25519 ECDH：返回32字节共享密钥
 */
function x25519SharedSecret (privateKey, peerPublicKeyRaw) {
  return crypto.diffieHellman({
    privateKey,
    publicKey: x25519PublicKeyFromRaw(peerPublicKeyRaw),
  })
}

/**
 * HPKE Base Mode SetupBaseS（RFC 9180 §5.1.1）
 *
 * @param pkR  接收方公钥（ECHConfig 里的 public_key）
 * @param info HPKE info，ECH 场景为 "tls ech" || 0x00 || ECHConfig
 * @returns {{ enc: Buffer, seal: Function, sequenceNumber: number }}
 */
function setupBaseS (pkR, info, keyPair = generateX25519KeyPair()) {
  const enc = keyPair.publicKeyRaw
  const dh = x25519SharedSecret(keyPair.privateKey, pkR)

  const eaePrk = labeledExtract(KEM_SUITE_ID, Buffer.alloc(0), 'eae_prk', dh)
  const sharedSecret = labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', Buffer.concat([enc, pkR]), hashLength(HPKE_HASH))

  const pskIdHash = labeledExtract(HPKE_SUITE_ID, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0))
  const infoHash = labeledExtract(HPKE_SUITE_ID, Buffer.alloc(0), 'info_hash', info)
  const keyScheduleContext = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash])

  const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, 'secret', Buffer.alloc(0))
  const key = labeledExpand(HPKE_SUITE_ID, secret, 'key', keyScheduleContext, HPKE_AEAD_KEY_LENGTH)
  const baseNonce = labeledExpand(HPKE_SUITE_ID, secret, 'base_nonce', keyScheduleContext, HPKE_AEAD_NONCE_LENGTH)

  let sequenceNumber = 0
  return {
    enc,
    // 以下字段仅用于测试向量校验（RFC 9180 附录 A）
    sharedSecret,
    keyScheduleContext,
    key,
    baseNonce,
    get sequenceNumber () {
      return sequenceNumber
    },
    seal (aad, plaintext) {
      const ciphertext = aeadSeal({
        cipher: HPKE_AEAD_CIPHER,
        key,
        iv: baseNonce,
        seq: sequenceNumber,
        aad,
        plaintext,
      })
      sequenceNumber++
      return ciphertext
    },
  }
}

module.exports = {
  KEM_X25519_HKDF_SHA256,
  KDF_HKDF_SHA256,
  AEAD_AES_128_GCM,
  HPKE_AEAD_TAG_LENGTH,
  HPKE_AEAD_KEY_LENGTH,
  HPKE_AEAD_NONCE_LENGTH,
  i2osp2,
  hashLength,
  hmac,
  hkdfExtract,
  hkdfExpand,
  hkdfExpandLabel,
  deriveSecret,
  buildNonce,
  aeadSeal,
  aeadOpen,
  setupBaseS,
  generateX25519KeyPair,
  x25519PublicKeyFromRaw,
  x25519PrivateKeyFromRaw,
  x25519SharedSecret,
}

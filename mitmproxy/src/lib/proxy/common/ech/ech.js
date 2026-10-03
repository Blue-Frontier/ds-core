const hpke = require('./hpke')
const svcbUtil = require('../../../dns/util.svcb')

/**
 * ECH（RFC 9849）客户端侧工具：
 *  - 从 DNS 下发的 ECHConfigList 中挑选可用配置
 *  - 构造 HPKE 上下文并密封 EncodedClientHelloInner
 *  - 计算 ECH 接受确认值（accept_confirmation）
 *  - 计算 EncodedClientHelloInner 的填充长度
 */

// ECHClientHelloType
const ECH_CLIENT_HELLO_OUTER = 0x00
const ECH_CLIENT_HELLO_INNER = 0x01

// 只支持 DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
const SUPPORTED_KDF = hpke.KDF_HKDF_SHA256
const SUPPORTED_AEAD = hpke.AEAD_AES_128_GCM

// ClientHelloInner 中的 encrypted_client_hello 扩展（inner 变体为空结构）
const INNER_EXTENSION_DATA = Buffer.from([ECH_CLIENT_HELLO_INNER])

/**
 * ECHConfig 结构体序列化：version || length || contents
 * HPKE 的 info 必须使用完整的 ECHConfig 结构体（含 version/length 字段）
 */
function encodeEchConfig (config) {
  if (!config || !Buffer.isBuffer(config.raw)) {
    throw new Error('ECHConfig 内容不完整')
  }
  return Buffer.concat([hpke.i2osp2(config.versionCode), hpke.i2osp2(config.raw.length), config.raw])
}

/**
 * 配置里是否有客户端支持的 KDF/AEAD 组合
 */
function supportedCipherSuite (config) {
  const suites = config.cipherSuites || []
  for (let i = 0; i + 1 < suites.length; i += 2) {
    if (suites[i] === SUPPORTED_KDF && suites[i + 1] === SUPPORTED_AEAD) {
      return { kdfId: suites[i], aeadId: suites[i + 1] }
    }
  }
  return null
}

/**
 * public_name 必须是合法的 DNS 名称（RFC 9849 §6.1.7）
 */
function validatePublicName (name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 253) {
    return false
  }
  if (name.startsWith('.') || name.endsWith('.')) {
    return false
  }
  const labels = name.split('.')
  if (labels.some(label => label.length === 0 || label.length > 63)) {
    return false
  }
  return true
}

/**
 * 判断某个 ECHConfig 是否可用（版本、KEM、KDF/AEAD、public_name）
 */
function isUsableEchConfig (config) {
  if (!config || config.versionCode !== 0xFE0D) {
    return false
  }
  if (config.kemId !== hpke.KEM_X25519_HKDF_SHA256) {
    return false
  }
  if (!config.publicKey || config.publicKey.length === 0) {
    return false
  }
  if (!validatePublicName(config.publicName)) {
    return false
  }
  return supportedCipherSuite(config) != null
}

/**
 * 从 ECHConfigList 中挑选可用配置，优先 X25519
 *
 * @param data base64 字符串或 Buffer
 */
function selectEchConfig (data) {
  let list
  try {
    list = svcbUtil.parseEchConfigList(data)
  } catch {
    return null
  }
  const usable = list.filter(isUsableEchConfig)
  if (usable.length === 0) {
    return null
  }
  return usable.find(item => item.kemId === hpke.KEM_X25519_HKDF_SHA256) || usable[0]
}

/**
 * 创建 HPKE 上下文：enc, context = SetupBaseS(pkR, "tls ech" || 0x00 || ECHConfig)
 */
function createEchContext (config) {
  const cipherSuite = supportedCipherSuite(config)
  if (!cipherSuite) {
    throw new Error('ECHConfig 不支持 HKDF-SHA256 + AES-128-GCM')
  }
  const info = Buffer.concat([Buffer.from('tls ech'), Buffer.from([0x00]), encodeEchConfig(config)])
  const context = hpke.setupBaseS(config.publicKey, info)
  return {
    config,
    configId: config.configId,
    kdfId: cipherSuite.kdfId,
    aeadId: cipherSuite.aeadId,
    enc: context.enc,
    seal: context.seal,
  }
}

/**
 * 序列化 ECHClientHello（outer 变体）作为 encrypted_client_hello 扩展的数据
 */
function encodeOuterExtension (context, payload) {
  const enc = context.enc
  const head = Buffer.alloc(1 + 4 + 1 + 2)
  head.writeUInt8(ECH_CLIENT_HELLO_OUTER, 0)
  head.writeUInt16BE(context.kdfId, 1)
  head.writeUInt16BE(context.aeadId, 3)
  head.writeUInt8(context.configId, 5)
  head.writeUInt16BE(enc.length, 6)
  const payloadHeader = Buffer.alloc(2)
  payloadHeader.writeUInt16BE(payload.length, 0)
  return Buffer.concat([head, enc, payloadHeader, payload])
}

/**
 * 计算 EncodedClientHelloInner 的填充长度（RFC 9849 §6.1.3）
 *
 * @param encodedLength        已序列化的 ClientHello（不含 4 字节握手头）长度
 * @param innerServername      内层 SNI（没有则传 null）
 * @param maximumNameLength    ECHConfig.maximum_name_length
 */
function paddingLength (encodedLength, innerServername, maximumNameLength) {
  let length = encodedLength
  if (innerServername) {
    length += Math.max(0, (maximumNameLength || 0) - Buffer.byteLength(innerServername))
  } else {
    length += (maximumNameLength || 0) + 9
  }
  const rest = (length - 1) % 32
  return length - encodedLength + (31 - rest)
}

/**
 * 计算 ECH 接受确认值（RFC 9849 §7.2）
 *
 * accept_confirmation = HKDF-Expand-Label(
 *    HKDF-Extract(0, ClientHelloInner.random),
 *    "ech accept confirmation",
 *    transcript_ech_conf,
 *    8)
 *
 * @param hashName         协商出来的哈希算法
 * @param innerRandom      ClientHelloInner.random
 * @param transcriptHash   ClientHelloInner..ServerHello（random 后 8 字节置零）的 Transcript-Hash
 */
function computeAcceptConfirmation ({ hashName, innerRandom, transcriptHash }) {
  const zeroSalt = Buffer.alloc(hpke.hashLength(hashName))
  const extracted = hpke.hkdfExtract(hashName, zeroSalt, innerRandom)
  return hpke.hkdfExpandLabel(hashName, extracted, 'ech accept confirmation', transcriptHash, 8)
}

/**
 * EncryptedExtensions 中的 encrypted_client_hello 扩展即新的 ECHConfigList（retry_configs）
 */
function parseRetryConfigs (extensionData) {
  if (!Buffer.isBuffer(extensionData) || extensionData.length < 2) {
    return null
  }
  return Buffer.from(extensionData)
}

module.exports = {
  ECH_CLIENT_HELLO_OUTER,
  ECH_CLIENT_HELLO_INNER,
  INNER_EXTENSION_DATA,
  encodeEchConfig,
  supportedCipherSuite,
  validatePublicName,
  isUsableEchConfig,
  selectEchConfig,
  createEchContext,
  encodeOuterExtension,
  paddingLength,
  computeAcceptConfirmation,
  parseRetryConfigs,
}

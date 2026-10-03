const crypto = require('node:crypto')
const tls = require('node:tls')
const { EventEmitter } = require('node:events')
const log = require('../../../../utils/util.log.server')
const hpke = require('./hpke')
const echUtil = require('./ech')

/**
 * 纯 JS 实现的 TLS 1.3 客户端（RFC 8446）+ ECH（RFC 9849）。
 *
 * 存在的意义：Node/OpenSSL（Node 24 + OpenSSL 3.5）没有暴露任何 ECH 接口，
 * 无法把 DNS 下发的 ECHConfig 用于上游 TLS 握手，因此这里自己实现握手，
 * 只支持 ECH 上游请求所需的必要能力：
 *   - TLS 1.3，X25519 密钥交换
 *   - TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256
 *   - 证书链校验（crypto.X509Certificate + tls.rootCertificates）
 *   - 不带压缩的 ECH（ClientHelloInner 与 ClientHelloOuter 重复携带扩展）
 *   - 不支持 PSK/会话恢复/客户端证书/HelloRetryRequest（遇到时抛错，由上层回退到原生 TLS）
 */

const CONTENT_TYPE = {
  changeCipherSpec: 20,
  alert: 21,
  handshake: 22,
  applicationData: 23,
}

const HANDSHAKE_TYPE = {
  clientHello: 1,
  serverHello: 2,
  newSessionTicket: 4,
  encryptedExtensions: 8,
  certificate: 11,
  certificateVerify: 15,
  finished: 20,
  keyUpdate: 24,
}

const EXTENSION_TYPE = {
  serverName: 0,
  supportedGroups: 10,
  signatureAlgorithms: 13,
  alpn: 16,
  supportedVersions: 43,
  keyShare: 51,
  encryptedClientHello: 0xFE0D,
}

const GROUP_X25519 = 0x001D
const TLS13_VERSION = 0x0304
const ALERT_DESCRIPTION = {
  closeNotify: 0,
  unexpectedMessage: 10,
  badRecordMac: 20,
  handshakeFailure: 40,
  illegalParameter: 47,
  decodeError: 50,
  decryptError: 51,
  protocolVersion: 70,
  internalError: 80,
  missingExtension: 109,
  certificateUnobtainable: 111,
  certificateUnknown: 115,
  echRequired: 121,
}

// ServerHello.random 为这个固定值时表示 HelloRetryRequest（RFC 8446 §4.1.3）
const HELLO_RETRY_REQUEST_RANDOM = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex')

const CIPHER_SUITES = [
  { id: 0x1301, name: 'TLS_AES_128_GCM_SHA256', hash: 'sha256', cipher: 'aes-128-gcm', keyLength: 16, ivLength: 12 },
  { id: 0x1302, name: 'TLS_AES_256_GCM_SHA384', hash: 'sha384', cipher: 'aes-256-gcm', keyLength: 32, ivLength: 12 },
  { id: 0x1303, name: 'TLS_CHACHA20_POLY1305_SHA256', hash: 'sha256', cipher: 'chacha20-poly1305', keyLength: 32, ivLength: 12 },
]

const SIGNATURE_ALGORITHMS = [
  0x0403, // ecdsa_secp256r1_sha256
  0x0804, // rsa_pss_rsae_sha256
  0x0401, // rsa_pkcs1_sha256
  0x0503, // ecdsa_secp384r1_sha384
  0x0805, // rsa_pss_rsae_sha384
  0x0501, // rsa_pkcs1_sha384
  0x0807, // ed25519
]

const MAX_PLAINTEXT_LENGTH = 16384
const AEAD_TAG_LENGTH = 16

let rootCertificatesCache = null
function getRootCertificates () {
  if (rootCertificatesCache == null) {
    rootCertificatesCache = tls.rootCertificates.map(pem => new crypto.X509Certificate(pem))
  }
  return rootCertificatesCache
}

function readUInt24BE (buf, offset) {
  return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
}

function writeUInt24BE (value) {
  const buf = Buffer.alloc(3)
  buf[0] = (value >>> 16) & 0xFF
  buf[1] = (value >>> 8) & 0xFF
  buf[2] = value & 0xFF
  return buf
}

function u16 (value) {
  return hpke.i2osp2(value)
}

function u16List (values) {
  const buf = Buffer.alloc(values.length * 2)
  values.forEach((value, index) => buf.writeUInt16BE(value, index * 2))
  return Buffer.concat([u16(buf.length), buf])
}

function encodeServerName (servername) {
  const name = Buffer.from(servername)
  const entry = Buffer.concat([Buffer.from([0x00]), u16(name.length), name])
  return Buffer.concat([u16(entry.length), entry])
}

function encodeAlpn (protocols) {
  const list = Buffer.concat(protocols.map((protocol) => {
    const name = Buffer.from(protocol)
    return Buffer.concat([Buffer.from([name.length]), name])
  }))
  return Buffer.concat([u16(list.length), list])
}

function encodeKeyShare (publicKey) {
  const share = Buffer.concat([u16(GROUP_X25519), u16(publicKey.length), publicKey])
  return Buffer.concat([u16(share.length), share])
}

function encodeExtensions (extensions) {
  const list = Buffer.concat(extensions.map(extension => Buffer.concat([
    u16(extension.type),
    u16(extension.data.length),
    extension.data,
  ])))
  return Buffer.concat([u16(list.length), list])
}

function parseExtensions (buf) {
  const length = buf.readUInt16BE(0)
  const extensions = new Map()
  let offset = 2
  const end = Math.min(buf.length, 2 + length)
  while (offset + 4 <= end) {
    const type = buf.readUInt16BE(offset)
    const extLength = buf.readUInt16BE(offset + 2)
    offset += 4
    if (offset + extLength > end) {
      break
    }
    extensions.set(type, buf.subarray(offset, offset + extLength))
    offset += extLength
  }
  return extensions
}

/**
 * 构造 ClientHello（不含 4 字节握手头）
 */
function buildClientHello ({ random, sessionId, servername, publicKey, alpnProtocols, echExtensionData, cipherSuiteIds }) {
  const extensions = []
  if (servername) {
    extensions.push({ type: EXTENSION_TYPE.serverName, data: encodeServerName(servername) })
  }
  extensions.push({ type: EXTENSION_TYPE.supportedGroups, data: u16List([GROUP_X25519]) })
  extensions.push({ type: EXTENSION_TYPE.signatureAlgorithms, data: u16List(SIGNATURE_ALGORITHMS) })
  if (alpnProtocols && alpnProtocols.length > 0) {
    extensions.push({ type: EXTENSION_TYPE.alpn, data: encodeAlpn(alpnProtocols) })
  }
  extensions.push({ type: EXTENSION_TYPE.supportedVersions, data: Buffer.concat([Buffer.from([2]), u16(TLS13_VERSION)]) })
  extensions.push({ type: EXTENSION_TYPE.keyShare, data: encodeKeyShare(publicKey) })
  if (echExtensionData) {
    // RFC 9849 §6.1.1：encrypted_client_hello 必须在所有扩展之后
    extensions.push({ type: EXTENSION_TYPE.encryptedClientHello, data: echExtensionData })
  }

  const suites = Buffer.alloc(cipherSuiteIds.length * 2)
  cipherSuiteIds.forEach((id, index) => suites.writeUInt16BE(id, index * 2))

  return Buffer.concat([
    u16(0x0303), // legacy_version
    random,
    Buffer.from([sessionId.length]),
    sessionId,
    u16(suites.length),
    suites,
    Buffer.from([0x01, 0x00]), // legacy_compression_methods: null
    encodeExtensions(extensions),
  ])
}

function hashOf (hashName, data) {
  return crypto.createHash(hashName).update(data).digest()
}

function makeTrafficKeys (suite, secret) {
  const hashLen = hpke.hashLength(suite.hash)
  return {
    suite,
    secret,
    key: hpke.hkdfExpandLabel(suite.hash, secret, 'key', Buffer.alloc(0), suite.keyLength),
    iv: hpke.hkdfExpandLabel(suite.hash, secret, 'iv', Buffer.alloc(0), suite.ivLength),
    seq: 0,
    finishedLength: hashLen,
  }
}

function verifySignature ({ scheme, publicKey, data, signature }) {
  switch (scheme) {
    case 0x0403:
      return crypto.verify('sha256', data, publicKey, signature)
    case 0x0503:
      return crypto.verify('sha384', data, publicKey, signature)
    case 0x0603:
      return crypto.verify('sha512', data, publicKey, signature)
    case 0x0804:
      return crypto.verify('sha256', data, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature)
    case 0x0805:
      return crypto.verify('sha384', data, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature)
    case 0x0806:
      return crypto.verify('sha512', data, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature)
    case 0x0401:
      return crypto.verify('sha256', data, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, signature)
    case 0x0501:
      return crypto.verify('sha384', data, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, signature)
    case 0x0601:
      return crypto.verify('sha512', data, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, signature)
    case 0x0807:
    case 0x0808:
      return crypto.verify(null, data, publicKey, signature)
    default:
      throw new Error(`不支持的签名算法: 0x${scheme.toString(16)}`)
  }
}

/**
 * 证书链校验：presented 证书链 -> 受信任根证书（tls.rootCertificates）
 */
function toCertificate (item) {
  if (item instanceof crypto.X509Certificate) {
    return item
  }
  return new crypto.X509Certificate(item)
}

function exportPublicKey (cert) {
  try {
    return cert.publicKey.export({ type: 'spki', format: 'der' })
  } catch {
    return null
  }
}

/**
 * 是否为受信任的锚点证书
 *
 * 除了直接命中根证书外，还要处理「交叉签名根」：服务器下发的链可能终止于
 * 某个根的交叉签名版本（主体相同、公钥相同、但签发者是另一个根），
 * 此时只要信任库里存在同主体同公钥的根，就可以认为该链已可信。
 */
function isTrustAnchor (cert, anchors) {
  const spki = exportPublicKey(cert)
  return anchors.some((anchor) => {
    try {
      if (anchor.raw.equals(cert.raw)) {
        return true
      }
      if (spki != null && anchor.subject === cert.subject) {
        const anchorSpki = exportPublicKey(anchor)
        return anchorSpki != null && anchorSpki.equals(spki)
      }
    } catch {
      return false
    }
    return false
  })
}

/**
 * 查找签发者证书：优先按主体名字符串匹配，其次用 X509Certificate.checkIssued
 */
function findIssuer (cert, candidates) {
  const bySubject = candidates.find(candidate => candidate.subject === cert.issuer)
  if (bySubject != null) {
    return bySubject
  }
  return candidates.find((candidate) => {
    try {
      return cert.checkIssued(candidate)
    } catch {
      return false
    }
  })
}

/**
 * 证书链校验：presented 证书链 -> 受信任根证书（tls.rootCertificates）
 */
function verifyCertificateChain (certificates, servername, caCertificates) {
  if (certificates.length === 0) {
    throw new Error('服务器未提供证书')
  }
  const chain = certificates.map(der => new crypto.X509Certificate(der))
  const leaf = chain[0]
  const anchors = [...(caCertificates || []).map(toCertificate), ...getRootCertificates()]
  const candidates = [...chain.slice(1), ...anchors]
  const now = Date.now()

  const checkValidity = (cert) => {
    const from = Date.parse(cert.validFrom)
    const to = Date.parse(cert.validTo)
    if (!(now >= from && now <= to)) {
      throw new Error(`证书有效期无效: ${cert.subject} (${cert.validFrom} ~ ${cert.validTo})`)
    }
  }

  let current = leaf
  let trusted = false
  for (let depth = 0; depth < 10; depth++) {
    checkValidity(current)
    if (isTrustAnchor(current, anchors)) {
      trusted = true
      break
    }
    const issuer = findIssuer(current, candidates)
    if (issuer == null) {
      throw new Error(`无法找到证书颁发者: ${current.issuer}`)
    }
    let signatureValid = false
    try {
      signatureValid = current.verify(issuer.publicKey)
    } catch {
      signatureValid = false
    }
    if (!signatureValid) {
      throw new Error(`证书签名校验失败: ${current.subject}`)
    }
    current = issuer
  }

  if (!trusted) {
    throw new Error(`证书链层级过深或根证书不受信任: ${leaf.subject}`)
  }

  if (servername) {
    const error = tls.checkServerIdentity(servername, leaf.toLegacyObject())
    if (error != null) {
      throw new Error(`证书域名校验失败: ${error.message}`)
    }
  }

  return {
    leaf,
    chain,
  }
}

class Tls13Session extends EventEmitter {
  constructor (options = {}) {
    super()
    this.options = {
      servername: options.servername,
      alpnProtocols: options.alpnProtocols || ['http/1.1'],
      echConfig: options.echConfig || null,
      rejectUnauthorized: options.rejectUnauthorized !== false,
      ca: options.ca || null,
      timeout: options.timeout || 15000,
    }
    this.rawSocket = null
    this.rawBuffer = Buffer.alloc(0)
    this.handshakeBuffer = Buffer.alloc(0)
    this.transcript = []
    this.readKeys = null
    this.writeKeys = null
    this.clientAppSecret = null
    this.serverAppSecret = null
    this.suite = null
    this.echContext = null
    this.echAccepted = false
    this.echRejected = false
    this.echRetryConfigs = null
    this.echOffered = false
    this.serverCertificates = null
    this.authorized = false
    this.authorizationError = null
    this.peerCertificate = null
    this.alpnProtocol = null
    this.handshakeDone = false
    this.closed = false
    this.sentFinished = false
    this.receivedCloseNotify = false
    this.timer = null
    this.keyPair = hpke.generateX25519KeyPair()
  }

  async connect (rawSocket) {
    this.rawSocket = rawSocket
    rawSocket.on('data', chunk => this.onRawData(chunk))
    rawSocket.on('error', error => this.fail(error))
    rawSocket.on('close', () => {
      this.closed = true
      if (!this.handshakeDone) {
        this.fail(new Error('TLS 握手过程中连接被关闭'))
      } else {
        this.emit('end')
        this.emit('close')
      }
    })

    const promise = new Promise((resolve, reject) => {
      this.resolveHandshake = resolve
      this.rejectHandshake = reject
    })

    this.timer = setTimeout(() => {
      this.fail(new Error(`TLS 握手超时(${this.options.timeout}ms)`))
    }, this.options.timeout)
    if (this.timer.unref) {
      this.timer.unref()
    }

    try {
      this.sendClientHello()
    } catch (e) {
      this.fail(e)
    }

    return promise
  }

  fail (error) {
    if (this.failed) {
      return
    }
    this.failed = true
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
    if (this.rejectHandshake) {
      this.rejectHandshake(error)
    }
    if (this.rawSocket && !this.rawSocket.destroyed) {
      this.rawSocket.destroy()
    }
    if (this.listenerCount('error') > 0) {
      this.emit('error', error)
    }
  }

  isEchSession () {
    return this.echOffered
  }

  sendClientHello () {
    const { servername, alpnProtocols, echConfig } = this.options
    const cipherSuiteIds = CIPHER_SUITES.map(item => item.id)
    const publicKey = this.keyPair.publicKeyRaw
    this.innerRandom = crypto.randomBytes(32)
    this.outerRandom = crypto.randomBytes(32)

    let body
    if (echConfig) {
      // 内层 ClientHello：真实 SNI + inner 变体 ECH 扩展 + 空 legacy_session_id
      const innerBody = buildClientHello({
        random: this.innerRandom,
        sessionId: Buffer.alloc(0),
        servername,
        publicKey,
        alpnProtocols,
        cipherSuiteIds,
        echExtensionData: echUtil.INNER_EXTENSION_DATA,
      })
      const padding = echUtil.paddingLength(innerBody.length, servername, echConfig.maximumNameLength)
      const encodedInner = Buffer.concat([innerBody, Buffer.alloc(padding)])

      this.echContext = echUtil.createEchContext(echConfig)
      this.echOffered = true
      this.innerHelloMessage = Buffer.concat([
        Buffer.from([HANDSHAKE_TYPE.clientHello]),
        writeUInt24BE(innerBody.length),
        innerBody,
      ])

      // ClientHelloOuterAAD：payload 为全零占位（长度 = 密文长度）
      const payloadLength = encodedInner.length + AEAD_TAG_LENGTH
      const partialOuterBody = buildClientHello({
        random: this.outerRandom,
        sessionId: Buffer.alloc(0),
        servername: echConfig.publicName,
        publicKey,
        alpnProtocols,
        cipherSuiteIds,
        echExtensionData: echUtil.encodeOuterExtension(this.echContext, Buffer.alloc(payloadLength)),
      })
      const sealed = this.echContext.seal(partialOuterBody, encodedInner)
      if (sealed.length !== payloadLength) {
        throw new Error('ECH payload 长度不一致')
      }
      const outerBody = buildClientHello({
        random: this.outerRandom,
        sessionId: Buffer.alloc(0),
        servername: echConfig.publicName,
        publicKey,
        alpnProtocols,
        cipherSuiteIds,
        echExtensionData: echUtil.encodeOuterExtension(this.echContext, sealed),
      })
      this.outerHelloMessage = Buffer.concat([
        Buffer.from([HANDSHAKE_TYPE.clientHello]),
        writeUInt24BE(outerBody.length),
        outerBody,
      ])
      body = outerBody
    } else {
      body = buildClientHello({
        random: this.innerRandom,
        sessionId: crypto.randomBytes(32),
        servername,
        publicKey,
        alpnProtocols,
        cipherSuiteIds,
      })
    }

    this.outerHelloBody = body
    if (echConfig) {
      this.sendRecord(CONTENT_TYPE.handshake, this.outerHelloMessage, null)
      log.debug(`[TLS13] 已发送 ECH ClientHelloOuter: 目标 ${servername} ➜ public_name: ${echConfig.publicName}, ech 配置 ${echConfig.publicKey.length} 字节公钥`)
    } else {
      const message = Buffer.concat([
        Buffer.from([HANDSHAKE_TYPE.clientHello]),
        writeUInt24BE(body.length),
        body,
      ])
      this.sendRecord(CONTENT_TYPE.handshake, message, null)
    }
  }

  sendRecord (contentType, payload, keys) {
    if (!this.rawSocket || this.rawSocket.destroyed) {
      throw new Error('连接已关闭')
    }
    let record
    if (keys) {
      const inner = Buffer.concat([payload, Buffer.from([contentType])])
      const header = Buffer.alloc(5)
      header.writeUInt8(CONTENT_TYPE.applicationData, 0)
      header.writeUInt16BE(0x0303, 1)
      header.writeUInt16BE(inner.length + AEAD_TAG_LENGTH, 3)
      const ciphertext = hpke.aeadSeal({
        cipher: keys.suite.cipher,
        key: keys.key,
        iv: keys.iv,
        seq: keys.seq,
        aad: header,
        plaintext: inner,
      })
      keys.seq++
      record = Buffer.concat([header, ciphertext])
    } else {
      const header = Buffer.alloc(5)
      header.writeUInt8(contentType, 0)
      header.writeUInt16BE(0x0303, 1)
      header.writeUInt16BE(payload.length, 3)
      record = Buffer.concat([header, payload])
    }
    this.rawSocket.write(record)
  }

  sendHandshake (type, body, keys) {
    const message = Buffer.concat([Buffer.from([type]), writeUInt24BE(body.length), body])
    this.sendRecord(CONTENT_TYPE.handshake, message, keys)
    return message
  }

  onRawData (chunk) {
    if (this.closed) {
      return
    }
    this.rawBuffer = Buffer.concat([this.rawBuffer, chunk])
    while (this.rawBuffer.length >= 5) {
      const contentType = this.rawBuffer.readUInt8(0)
      const length = this.rawBuffer.readUInt16BE(3)
      if (this.rawBuffer.length < 5 + length) {
        return
      }
      const header = Buffer.from(this.rawBuffer.subarray(0, 5))
      const body = this.rawBuffer.subarray(5, 5 + length)
      this.rawBuffer = this.rawBuffer.subarray(5 + length)
      try {
        this.handleRecord(contentType, header, body)
      } catch (e) {
        this.fail(e)
        return
      }
      if (this.closed || this.failed) {
        return
      }
    }
  }

  handleRecord (contentType, header, body) {
    if (contentType === CONTENT_TYPE.changeCipherSpec) {
      return
    }
    if (contentType === CONTENT_TYPE.alert && !this.readKeys) {
      const description = body.length >= 2 ? body.readUInt8(1) : -1
      throw new Error(`TLS 握手失败，收到告警: ${description}`)
    }
    if (contentType === CONTENT_TYPE.handshake && !this.readKeys) {
      this.handleHandshakeBytes(body)
      return
    }
    if (contentType === CONTENT_TYPE.applicationData) {
      if (!this.readKeys) {
        throw new Error('在密钥协商完成前收到了加密记录')
      }
      const plaintext = hpke.aeadOpen({
        cipher: this.readKeys.suite.cipher,
        key: this.readKeys.key,
        iv: this.readKeys.iv,
        seq: this.readKeys.seq,
        aad: header,
        ciphertext: body,
      })
      this.readKeys.seq++
      let end = plaintext.length - 1
      while (end >= 0 && plaintext[end] === 0) {
        end--
      }
      if (end < 0) {
        throw new Error('TLS 记录内容为空')
      }
      const innerType = plaintext.readUInt8(end)
      const payload = plaintext.subarray(0, end)
      if (innerType === CONTENT_TYPE.handshake) {
        this.handleHandshakeBytes(payload)
      } else if (innerType === CONTENT_TYPE.alert) {
        this.handleAlert(payload)
      } else if (innerType === CONTENT_TYPE.applicationData) {
        this.emit('data', payload)
      }
      return
    }
    throw new Error(`不支持的 TLS 记录类型: ${contentType}`)
  }

  handleAlert (payload) {
    if (payload.length < 2) {
      return
    }
    const description = payload.readUInt8(1)
    if (description === ALERT_DESCRIPTION.closeNotify) {
      this.receivedCloseNotify = true
      this.emit('end')
      return
    }
    const error = new Error(`TLS 告警: ${description}`)
    error.alertDescription = description
    throw error
  }

  handleHandshakeBytes (bytes) {
    this.handshakeBuffer = Buffer.concat([this.handshakeBuffer, bytes])
    while (this.handshakeBuffer.length >= 4) {
      const type = this.handshakeBuffer.readUInt8(0)
      const length = readUInt24BE(this.handshakeBuffer, 1)
      if (this.handshakeBuffer.length < 4 + length) {
        return
      }
      const message = Buffer.from(this.handshakeBuffer.subarray(0, 4 + length))
      const body = this.handshakeBuffer.subarray(4, 4 + length)
      this.handshakeBuffer = this.handshakeBuffer.subarray(4 + length)
      this.handleHandshakeMessage(type, body, message)
      if (this.failed || this.closed) {
        return
      }
    }
  }

  handleHandshakeMessage (type, body, message) {
    switch (type) {
      case HANDSHAKE_TYPE.serverHello:
        this.handleServerHello(body, message)
        break
      case HANDSHAKE_TYPE.encryptedExtensions:
        this.handleEncryptedExtensions(body, message)
        break
      case HANDSHAKE_TYPE.certificate:
        this.handleCertificate(body, message)
        break
      case HANDSHAKE_TYPE.certificateVerify:
        this.handleCertificateVerify(body, message)
        break
      case HANDSHAKE_TYPE.finished:
        this.handleFinished(body, message)
        break
      case HANDSHAKE_TYPE.newSessionTicket:
        // 不做会话恢复，忽略
        break
      case HANDSHAKE_TYPE.keyUpdate:
        this.handleKeyUpdate(body)
        break
      default:
        throw new Error(`不支持的握手消息类型: ${type}`)
    }
  }

  handleServerHello (body, message) {
    const random = body.subarray(2, 34)
    if (random.equals(HELLO_RETRY_REQUEST_RANDOM)) {
      throw new Error('服务器要求 HelloRetryRequest，当前实现不支持，回退原生 TLS')
    }
    const sessionIdLength = body.readUInt8(34)
    let offset = 35 + sessionIdLength
    const cipherSuiteId = body.readUInt16BE(offset)
    offset += 2
    offset += 1 // legacy_compression_method
    const extensions = parseExtensions(body.subarray(offset))

    this.suite = CIPHER_SUITES.find(item => item.id === cipherSuiteId)
    if (!this.suite) {
      throw new Error(`服务器选择了不支持的密码套件: 0x${cipherSuiteId.toString(16)}`)
    }

    const supportedVersions = extensions.get(EXTENSION_TYPE.supportedVersions)
    if (!supportedVersions || supportedVersions.readUInt16BE(0) !== TLS13_VERSION) {
      throw new Error('服务器未协商 TLS 1.3')
    }

    const keyShare = extensions.get(EXTENSION_TYPE.keyShare)
    if (!keyShare) {
      throw new Error('服务器未返回 key_share')
    }
    const group = keyShare.readUInt16BE(0)
    const keyLength = keyShare.readUInt16BE(2)
    if (group !== GROUP_X25519) {
      throw new Error(`服务器选择了不支持的密钥交换组: 0x${group.toString(16)}`)
    }
    const serverKey = keyShare.subarray(4, 4 + keyLength)

    // ECH 接受确认（RFC 9849 §6.1.4 / §7.2），必须在把 ServerHello 加入 transcript 之前计算
    if (this.echOffered) {
      // ServerHello 结构：type(1) + length(3) + legacy_version(2) + random(32)，random 后 8 字节位于 30..38
      const zeroedMessage = Buffer.from(message)
      zeroedMessage.fill(0, 30, 38)
      const transcriptEchConf = hashOf(this.suite.hash, Buffer.concat([this.innerHelloMessage, zeroedMessage]))
      const expected = echUtil.computeAcceptConfirmation({
        hashName: this.suite.hash,
        innerRandom: this.innerRandom,
        transcriptHash: transcriptEchConf,
      })
      this.echAccepted = expected.equals(random.subarray(24))
      if (!this.echAccepted) {
        // RFC 9849 §6.1.6：ECH 被拒绝时不能立刻中断握手，
        // 需要继续完成握手以读取 EncryptedExtensions 里的 retry_configs，再决定重试或回退
        this.echRejected = true
        log.warn(`[TLS13] 服务器未确认 ECH，本次使用 ClientHelloOuter 继续握手以获取 retry_configs: ${this.options.servername}`)
      }
    }

    // 协商成功后 transcript 使用 ClientHelloInner（ECH 被接受）或实际发送的 ClientHelloOuter
    this.transcript = [this.echOffered && this.echAccepted
      ? this.innerHelloMessage
      : Buffer.concat([
          Buffer.from([HANDSHAKE_TYPE.clientHello]),
          writeUInt24BE(this.outerHelloBody.length),
          this.outerHelloBody,
        ])]
    this.transcript.push(message)

    const hashName = this.suite.hash
    const hashLen = hpke.hashLength(hashName)
    const sharedSecret = hpke.x25519SharedSecret(this.keyPair.privateKey, serverKey)
    const emptyHash = hashOf(hashName, Buffer.alloc(0))
    const earlySecret = hpke.hkdfExtract(hashName, Buffer.alloc(hashLen), Buffer.alloc(hashLen))
    const derivedSecret = hpke.deriveSecret(hashName, earlySecret, 'derived', emptyHash)
    const handshakeSecret = hpke.hkdfExtract(hashName, derivedSecret, sharedSecret)

    const transcriptHash = this.transcriptHash()
    this.handshakeSecret = handshakeSecret
    this.emptyHash = emptyHash
    const clientHsSecret = hpke.deriveSecret(hashName, handshakeSecret, 'c hs traffic', transcriptHash)
    const serverHsSecret = hpke.deriveSecret(hashName, handshakeSecret, 's hs traffic', transcriptHash)
    this.clientHsSecret = clientHsSecret
    this.serverHsSecret = serverHsSecret
    this.readKeys = makeTrafficKeys(this.suite, serverHsSecret)
    this.writeKeys = makeTrafficKeys(this.suite, clientHsSecret)
  }

  handleEncryptedExtensions (body, message) {
    const extensions = parseExtensions(body)
    this.transcript.push(message)

    const alpn = extensions.get(EXTENSION_TYPE.alpn)
    if (alpn) {
      const length = alpn.readUInt8(0)
      this.alpnProtocol = alpn.toString('utf8', 1, 1 + length)
    }

    const echExtension = extensions.get(EXTENSION_TYPE.encryptedClientHello)
    if (echExtension) {
      this.echRetryConfigs = echUtil.parseRetryConfigs(echExtension)
    }
  }

  handleCertificate (body, message) {
    const contextLength = body.readUInt8(0)
    let offset = 1 + contextLength
    const listLength = readUInt24BE(body, offset)
    offset += 3
    const end = Math.min(body.length, offset + listLength)
    const certificates = []
    while (offset + 3 <= end) {
      const certLength = readUInt24BE(body, offset)
      offset += 3
      if (offset + certLength > end) {
        break
      }
      certificates.push(Buffer.from(body.subarray(offset, offset + certLength)))
      offset += certLength
      if (offset + 2 <= end) {
        const extLength = body.readUInt16BE(offset)
        offset += 2 + extLength
      }
    }
    this.serverCertificates = certificates
    this.transcript.push(message)
  }

  handleCertificateVerify (body, message) {
    const scheme = body.readUInt16BE(0)
    const signatureLength = body.readUInt16BE(2)
    const signature = body.subarray(4, 4 + signatureLength)
    const leaf = this.serverCertificates && this.serverCertificates[0]
    if (!leaf) {
      throw new Error('服务器未提供证书，无法校验 CertificateVerify')
    }
    const certificate = new crypto.X509Certificate(leaf)
    const content = Buffer.concat([
      Buffer.alloc(64, 0x20),
      Buffer.from('TLS 1.3, server CertificateVerify'),
      Buffer.from([0x00]),
      this.transcriptHash(),
    ])
    if (!verifySignature({ scheme, publicKey: certificate.publicKey, data: content, signature })) {
      throw new Error('CertificateVerify 签名校验失败')
    }
    this.transcript.push(message)
  }

  handleFinished (body, message) {
    const serverFinishedKey = hpke.hkdfExpandLabel(this.suite.hash, this.serverHsSecret, 'finished', Buffer.alloc(0), hpke.hashLength(this.suite.hash))
    const expected = hpke.hmac(this.suite.hash, serverFinishedKey, this.transcriptHash())
    if (expected.length !== body.length || !crypto.timingSafeEqual(expected, body)) {
      throw new Error('服务器 Finished 校验失败')
    }
    this.transcript.push(message)

    if (this.echRejected) {
      // 服务器未接受 ECH：此时握手使用的是 ClientHelloOuter，
      // 证书只对 public_name 有效，不能视为源站已认证（RFC 9849 §6.1.6 / §6.1.7），
      // 因此不发送客户端 Finished、不发送任何应用数据，直接按 retry_configs 处理
      this.authorized = false
      this.authorizationError = new Error('服务器拒绝了 ECH，证书仅对 public_name 有效')
      const error = new Error('服务器拒绝了 ECH（ECH 未确认）')
      error.code = 'ECH_REJECTED'
      error.retryConfigs = this.echRetryConfigs || null
      if (this.echRetryConfigs) {
        log.warn(`[TLS13] 服务器下发了 ECH retry_configs（${this.echRetryConfigs.length} 字节），将使用新配置重试`)
      }
      throw error
    }

    // 校验证书链（在 Finished 校验之后，与 RFC 8446 的建议顺序相反但结果一致）
    this.authorized = false
    this.authorizationError = null
    try {
      verifyCertificateChain(this.serverCertificates || [], this.options.servername, this.options.ca)
      this.authorized = true
    } catch (e) {
      this.authorizationError = e
      if (this.options.rejectUnauthorized) {
        throw new Error(`证书校验失败: ${e.message}`)
      }
      log.warn(`[TLS13] 证书校验失败（已忽略）: ${this.options.servername} ${e.message}`)
    }
    if (this.serverCertificates && this.serverCertificates.length > 0) {
      const leaf = new crypto.X509Certificate(this.serverCertificates[0])
      this.peerCertificate = {
        subject: leaf.subject,
        issuer: leaf.issuer,
        valid_from: leaf.validFrom,
        valid_to: leaf.validTo,
        fingerprint256: leaf.fingerprint256,
        subjectaltname: leaf.subjectAltName,
        raw: leaf.raw,
      }
      if (this.authorized && this.options.servername) {
        const matched = leaf.checkHost(this.options.servername, { subject: 'default' })
        if (!matched) {
          this.authorized = false
          this.authorizationError = new Error(`证书与域名不匹配: ${this.options.servername}`)
          if (this.options.rejectUnauthorized) {
            throw new Error(`证书与域名不匹配: ${this.options.servername}`)
          }
        }
      }
    }

    // 发送客户端 Finished（使用握手密钥）
    const clientFinishedKey = hpke.hkdfExpandLabel(this.suite.hash, this.clientHsSecret, 'finished', Buffer.alloc(0), hpke.hashLength(this.suite.hash))
    const verifyData = hpke.hmac(this.suite.hash, clientFinishedKey, this.transcriptHash())
    this.sendHandshake(HANDSHAKE_TYPE.finished, verifyData, this.writeKeys)
    this.sentFinished = true

    // 导出应用密钥：客户端在发送 Finished 后切换，服务器在收到后切换
    const masterSecret = hpke.hkdfExtract(this.suite.hash, hpke.deriveSecret(this.suite.hash, this.handshakeSecret, 'derived', this.emptyHash), Buffer.alloc(hpke.hashLength(this.suite.hash)))
    const appTranscriptHash = this.transcriptHash()
    this.clientAppSecret = hpke.deriveSecret(this.suite.hash, masterSecret, 'c ap traffic', appTranscriptHash)
    this.serverAppSecret = hpke.deriveSecret(this.suite.hash, masterSecret, 's ap traffic', appTranscriptHash)
    this.readKeys = makeTrafficKeys(this.suite, this.serverAppSecret)
    this.writeKeys = makeTrafficKeys(this.suite, this.clientAppSecret)

    this.handshakeDone = true
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
    const info = {
      protocol: 'TLSv1.3',
      cipherSuite: this.suite.name,
      alpnProtocol: this.alpnProtocol,
      servername: this.options.servername,
      echAccepted: this.echAccepted,
      echUsed: this.echOffered,
      authorized: this.authorized,
      authorizationError: this.authorizationError ? this.authorizationError.message : null,
      peerCertificate: this.peerCertificate,
    }
    if (this.resolveHandshake) {
      this.resolveHandshake(info)
    }
    this.emit('secureConnect', info)
  }

  handleKeyUpdate (body) {
    const requestUpdate = body.length > 0 && body.readUInt8(0) === 1
    this.updateReadKeys()
    if (requestUpdate) {
      this.sendHandshake(HANDSHAKE_TYPE.keyUpdate, Buffer.from([0]), this.writeKeys)
      this.updateWriteKeys()
    }
  }

  updateReadKeys () {
    this.serverAppSecret = hpke.hkdfExpandLabel(this.suite.hash, this.serverAppSecret, 'traffic upd', Buffer.alloc(0), hpke.hashLength(this.suite.hash))
    this.readKeys = makeTrafficKeys(this.suite, this.serverAppSecret)
  }

  updateWriteKeys () {
    this.clientAppSecret = hpke.hkdfExpandLabel(this.suite.hash, this.clientAppSecret, 'traffic upd', Buffer.alloc(0), hpke.hashLength(this.suite.hash))
    this.writeKeys = makeTrafficKeys(this.suite, this.clientAppSecret)
  }

  transcriptHash () {
    return hashOf(this.suite.hash, Buffer.concat(this.transcript))
  }

  writeApp (data) {
    if (!this.handshakeDone) {
      throw new Error('TLS 握手尚未完成')
    }
    let offset = 0
    while (offset < data.length) {
      const chunk = data.subarray(offset, offset + MAX_PLAINTEXT_LENGTH)
      offset += chunk.length
      this.sendRecord(CONTENT_TYPE.applicationData, chunk, this.writeKeys)
    }
  }

  closeNotify () {
    if (this.closed || this.receivedCloseNotify) {
      return
    }
    try {
      this.sendRecord(CONTENT_TYPE.alert, Buffer.from([0x01, ALERT_DESCRIPTION.closeNotify]), this.writeKeys)
    } catch {
      // 连接可能已断开
    }
  }

  destroy () {
    this.closed = true
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
    if (this.rawSocket && !this.rawSocket.destroyed) {
      this.rawSocket.destroy()
    }
  }
}

module.exports = {
  Tls13Session,
  CIPHER_SUITES,
  SIGNATURE_ALGORITHMS,
  verifySignature,
  verifyCertificateChain,
}

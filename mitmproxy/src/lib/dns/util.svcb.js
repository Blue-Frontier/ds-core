/**
 * HTTPS(65) / SVCB(64) 记录的最小实现（RFC 9460），用于获取 DNS 下发的 ECH 参数（RFC 9848）。
 *
 * 为什么不用 `dns-packet`：
 * - 依赖的 `dns-packet@4.2.0` 的类型表中没有 SVCB(64)/HTTPS(65)，编码时 QTYPE 会退化成 0；
 * - 即使升级到 5.x，也依然没有 HTTPS/SVCB/ech 的支持（其类型表同样缺失）。
 * 因此这里自行实现「查询报文编码」与「响应报文解码」，只覆盖 ECH 场景所需的字段。
 */
const { Buffer } = require('node:buffer')

const TYPE_SVCB = 64
const TYPE_HTTPS = 65
const TYPE_CNAME = 5
const TYPE_OPT = 41
const CLASS_IN = 1

const FLAG_RECURSION_DESIRED = 0x0100
const FLAG_DNSSEC_OK = 0x8000

// SvcParamKey，参见 RFC 9460 §14.3.2 与 RFC 9460 §7
const SVC_PARAM_KEYS = {
  mandatory: 0,
  alpn: 1,
  no_default_alpn: 2,
  port: 3,
  ipv4hint: 4,
  ech: 5,
  ipv6hint: 6,
  dohpath: 7,
  ohttp: 8,
}

const SVC_PARAM_NAMES = {}
for (const name of Object.keys(SVC_PARAM_KEYS)) {
  SVC_PARAM_NAMES[SVC_PARAM_KEYS[name]] = name
}

// ECHConfig 的 KEM 编号，参见 draft-ietf-tls-esni / HPKE RFC 9180 §7.1
const KEM_NAMES = {
  0x0010: 'DHKEM(P-256, HKDF-SHA256)',
  0x0011: 'DHKEM(P-384, HKDF-SHA384)',
  0x0012: 'DHKEM(P-521, HKDF-SHA512)',
  0x0020: 'DHKEM(X25519, HKDF-SHA256)',
  0x0021: 'DHKEM(X448, HKDF-SHA512)',
}

function typeName (type) {
  if (type === TYPE_HTTPS) {
    return 'HTTPS'
  }
  if (type === TYPE_SVCB) {
    return 'SVCB'
  }
  if (type === TYPE_CNAME) {
    return 'CNAME'
  }
  if (type === TYPE_OPT) {
    return 'OPT'
  }
  return String(type)
}

/**
 * 是否为 SVCB/HTTPS 类型（支持 `HTTPS`、`SVCB` 字符串或 64/65 数字）
 */
function isSvcType (type) {
  return type === 'HTTPS' || type === 'SVCB' || type === TYPE_HTTPS || type === TYPE_SVCB
}

/**
 * 把类型转换为数字，用于构造查询报文
 */
function typeCode (type) {
  if (type === 'SVCB' || type === TYPE_SVCB) {
    return TYPE_SVCB
  }
  return TYPE_HTTPS
}

/**
 * 编码域名为 DNS 报文格式（不含压缩指针）
 */
function encodeName (name) {
  const labels = String(name).replace(/\.$/, '').split('.')
  const list = []
  for (const label of labels) {
    const labelBuf = Buffer.from(label, 'utf8')
    if (labelBuf.length === 0) {
      continue
    }
    if (labelBuf.length > 63) {
      throw new Error(`DNS域名中的标签过长(>63): ${label}`)
    }
    list.push(Buffer.from([labelBuf.length]), labelBuf)
  }
  list.push(Buffer.from([0]))
  return Buffer.concat(list)
}

/**
 * 构造一个 HTTPS(65) 或 SVCB(64) 的查询报文，并携带 EDNS0(OPT) 以声明 UDP 报文大小
 *
 * @param name 域名
 * @param options.type 查询类型，默认 HTTPS(65)
 * @param options.id 报文ID，默认随机
 * @param options.udpPayloadSize EDNS0 声明的UDP报文大小，默认 1232（避免被分片）
 * @param options.dnssecOk 是否设置 DO 位，默认 false
 * @returns {Buffer}
 */
function encodeQuery (name, options = {}) {
  const type = options.type || TYPE_HTTPS
  const id = options.id == null ? Math.floor(Math.random() * 0xFFFF) : options.id
  const udpPayloadSize = options.udpPayloadSize == null ? 1232 : options.udpPayloadSize
  const dnssecOk = options.dnssecOk === true

  const question = Buffer.concat([
    encodeName(name),
    (() => {
      const buf = Buffer.alloc(4)
      buf.writeUInt16BE(type, 0)
      buf.writeUInt16BE(CLASS_IN, 2)
      return buf
    })(),
  ])

  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(FLAG_RECURSION_DESIRED, 2)
  header.writeUInt16BE(1, 4) // qdcount
  header.writeUInt16BE(0, 6) // ancount
  header.writeUInt16BE(0, 8) // nscount
  header.writeUInt16BE(1, 10) // arcount: 1个OPT记录

  // EDNS0 OPT 记录：根域名 + type=41 + class=UDP报文大小 + ttl=扩展rcode/flags + rdlength=0
  const opt = Buffer.alloc(11)
  opt.writeUInt8(0, 0)
  opt.writeUInt16BE(TYPE_OPT, 1)
  opt.writeUInt16BE(udpPayloadSize, 3)
  opt.writeUInt32BE(dnssecOk ? FLAG_DNSSEC_OK : 0, 5)
  opt.writeUInt16BE(0, 9)

  return Buffer.concat([header, question, opt])
}

/**
 * 解码域名，支持压缩指针
 *
 * @returns {{name: string, offset: number}} offset 为「压缩指针之后」的下一个字节位置；无压缩指针时等于域名结束位置
 */
function decodeName (buf, offset) {
  const labels = []
  let pos = offset
  let nextOffset = -1
  let loops = 0

  while (true) {
    if (pos >= buf.length) {
      throw new Error(`DNS报文中域名超出边界, offset: ${pos}`)
    }

    const len = buf[pos]
    if (len === 0) {
      pos++
      break
    }

    if ((len & 0xC0) === 0xC0) {
      // 压缩指针：高2位为11，剩余14位为指向报文其它位置的偏移量
      if (pos + 1 >= buf.length) {
        throw new Error('DNS报文中的域名压缩指针不完整')
      }
      const pointer = ((len & 0x3F) << 8) | buf[pos + 1]
      if (nextOffset === -1) {
        nextOffset = pos + 2
      }
      if (++loops > 128) {
        throw new Error('DNS报文中的域名压缩指针出现循环')
      }
      pos = pointer
      continue
    }

    if ((len & 0xC0) !== 0) {
      throw new Error(`DNS报文中的域名使用了不支持的编码: 0x${len.toString(16)}`)
    }

    if (pos + 1 + len > buf.length) {
      throw new Error('DNS报文中的域名超出边界')
    }
    labels.push(buf.toString('utf8', pos + 1, pos + 1 + len))
    pos += 1 + len
  }

  return {
    name: labels.join('.'),
    offset: nextOffset === -1 ? pos : nextOffset,
  }
}

function decodeAlpn (buf) {
  const list = []
  let offset = 0
  while (offset < buf.length) {
    const len = buf[offset]
    offset++
    if (offset + len > buf.length) {
      break
    }
    list.push(buf.toString('utf8', offset, offset + len))
    offset += len
  }
  return list
}

function decodeIpv4Hint (buf) {
  const list = []
  for (let offset = 0; offset + 4 <= buf.length; offset += 4) {
    list.push(`${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`)
  }
  return list
}

function decodeIpv6Hint (buf) {
  const list = []
  for (let offset = 0; offset + 16 <= buf.length; offset += 16) {
    const groups = []
    for (let i = 0; i < 8; i++) {
      groups.push(buf.readUInt16BE(offset + i * 2).toString(16))
    }
    list.push(groups.join(':'))
  }
  return list
}

/**
 * 解码一个 SvcParam，返回值中 `ech` 为 ECHConfigList 的二进制内容
 */
function decodeSvcParam (key, buf) {
  const name = SVC_PARAM_NAMES[key] || `key${key}`
  const param = {
    key,
    name,
  }

  switch (key) {
    case SVC_PARAM_KEYS.mandatory: {
      const list = []
      for (let offset = 0; offset + 2 <= buf.length; offset += 2) {
        const key2 = buf.readUInt16BE(offset)
        list.push(SVC_PARAM_NAMES[key2] || `key${key2}`)
      }
      param.value = list
      break
    }
    case SVC_PARAM_KEYS.alpn:
      param.value = decodeAlpn(buf)
      break
    case SVC_PARAM_KEYS.no_default_alpn:
    case SVC_PARAM_KEYS.ohttp:
      param.value = true
      break
    case SVC_PARAM_KEYS.port:
      param.value = buf.length >= 2 ? buf.readUInt16BE(0) : undefined
      break
    case SVC_PARAM_KEYS.ipv4hint:
      param.value = decodeIpv4Hint(buf)
      break
    case SVC_PARAM_KEYS.ech:
      // ECHConfigList，二进制内容，展示时可base64编码
      param.value = Buffer.from(buf)
      param.base64 = buf.toString('base64')
      break
    case SVC_PARAM_KEYS.ipv6hint:
      param.value = decodeIpv6Hint(buf)
      break
    case SVC_PARAM_KEYS.dohpath:
      param.value = buf.toString('utf8')
      break
    default:
      param.value = Buffer.from(buf)
      break
  }

  return param
}

/**
 * 解码 SVCB/HTTPS 记录的 rdata
 *
 * @param buf 整个DNS响应报文（用于解析目标域名的压缩指针）
 * @param offset rdata 的起始位置
 * @param length rdata 的长度
 */
function decodeSvcRecord (buf, offset, length) {
  const end = offset + length
  const priority = buf.readUInt16BE(offset)
  const { name: target, offset: paramsOffset } = decodeName(buf, offset + 2)

  const params = []
  const paramMap = {}
  let pos = paramsOffset
  while (pos + 4 <= end) {
    const key = buf.readUInt16BE(pos)
    const len = buf.readUInt16BE(pos + 2)
    pos += 4
    if (pos + len > end) {
      break
    }
    const param = decodeSvcParam(key, buf.subarray(pos, pos + len))
    params.push(param)
    if (paramMap[param.name] == null) {
      paramMap[param.name] = param.value
    }
    pos += len
  }

  return {
    priority,
    target: target === '' ? '.' : target,
    params,
    paramMap,
    ech: paramMap.ech,
  }
}

/**
 * 解码 DNS 响应报文（仅解析问题区和各资源记录，够 ECH 场景使用）
 */
function parseResponse (buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) {
    throw new Error('DNS响应报文长度不足')
  }

  const id = buf.readUInt16BE(0)
  const flags = buf.readUInt16BE(2)
  const qdcount = buf.readUInt16BE(4)
  const ancount = buf.readUInt16BE(6)
  const nscount = buf.readUInt16BE(8)
  const arcount = buf.readUInt16BE(10)

  let offset = 12

  const questions = []
  for (let i = 0; i < qdcount; i++) {
    const { name, offset: next } = decodeName(buf, offset)
    offset = next
    const type = buf.readUInt16BE(offset)
    const klass = buf.readUInt16BE(offset + 2)
    offset += 4
    questions.push({ name, type: typeName(type), typeCode: type, class: klass })
  }

  const answers = []
  const total = ancount + nscount + arcount
  for (let i = 0; i < total; i++) {
    const { name, offset: next } = decodeName(buf, offset)
    offset = next
    const type = buf.readUInt16BE(offset)
    const klass = buf.readUInt16BE(offset + 2)
    const ttl = buf.readUInt32BE(offset + 4)
    const rdlength = buf.readUInt16BE(offset + 8)
    offset += 10

    const rdataOffset = offset
    offset += rdlength

    const record = {
      name,
      type: typeName(type),
      typeCode: type,
      ttl,
      class: klass,
    }

    if ((type === TYPE_HTTPS || type === TYPE_SVCB) && rdlength >= 3) {
      record.data = decodeSvcRecord(buf, rdataOffset, rdlength)
      record.raw = buf.subarray(rdataOffset, rdataOffset + rdlength)
    } else if (type === TYPE_CNAME && rdlength > 0) {
      record.data = decodeName(buf, rdataOffset).name
    } else {
      record.raw = buf.subarray(rdataOffset, rdataOffset + rdlength)
    }

    answers.push(record)
  }

  return {
    id,
    flags,
    rcode: flags & 0x0F,
    truncated: (flags & 0x0200) !== 0,
    questions,
    answers,
  }
}

/**
 * 解析 ECHConfigList（RFC 9848 / draft-ietf-tls-esni-24 §4）
 *
 * @param data base64字符串 或 Buffer
 */
function parseEchConfigList (data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data).trim(), 'base64')
  if (buf.length < 2) {
    return []
  }

  const listLength = buf.readUInt16BE(0)
  const configs = []
  let offset = 2
  const end = Math.min(buf.length, 2 + listLength)

  while (offset + 4 <= end) {
    const version = buf.readUInt16BE(offset)
    const length = buf.readUInt16BE(offset + 2)
    offset += 4

    if (length === 0 || offset + length > buf.length) {
      break
    }

    const configBuf = buf.subarray(offset, offset + length)
    offset += length

    const config = {
      version: `0x${version.toString(16).padStart(4, '0')}`,
      versionCode: version,
      length,
      raw: Buffer.from(configBuf),
    }

    try {
      let pos = 0
      config.configId = configBuf.readUInt8(pos)
      pos += 1

      config.kemId = configBuf.readUInt16BE(pos)
      config.kem = KEM_NAMES[config.kemId] || `unknown(0x${config.kemId.toString(16)})`
      pos += 2

      const publicKeyLen = configBuf.readUInt16BE(pos)
      pos += 2
      config.publicKey = configBuf.subarray(pos, pos + publicKeyLen)
      pos += publicKeyLen

      const cipherSuitesLen = configBuf.readUInt16BE(pos)
      pos += 2
      config.cipherSuites = []
      for (let i = 0; i + 2 <= cipherSuitesLen; i += 2) {
        config.cipherSuites.push(configBuf.readUInt16BE(pos + i))
      }
      pos += cipherSuitesLen

      config.maximumNameLength = configBuf.readUInt8(pos)
      pos += 1

      const publicNameLen = configBuf.readUInt8(pos)
      pos += 1
      config.publicName = configBuf.toString('utf8', pos, pos + publicNameLen)
      pos += publicNameLen

      if (pos + 2 <= configBuf.length) {
        config.extensionsLength = configBuf.readUInt16BE(pos)
      } else {
        config.extensionsLength = 0
      }
    } catch (e) {
      config.parseError = e.message
    }

    configs.push(config)
  }

  return configs
}

/**
 * 从 ECHConfigList 中挑选一个可用于 ECH 的配置（优先 X25519 密钥封装）
 */
function pickEchConfig (data) {
  const list = parseEchConfigList(data)
  if (list.length === 0) {
    return null
  }

  const usable = list.filter(item => item.publicKey && item.publicKey.length > 0 && item.publicName && item.publicName.length > 0)
  if (usable.length === 0) {
    return null
  }

  return usable.find(item => item.kemId === 0x0020) || usable[0]
}

/**
 * 解析 SVCB/HTTPS 记录的「展示格式」文本，例如：
 * `1 . alpn="h2" ipv4hint="162.159.135.79" ech="AEX+DQBB..." ipv6hint="2606:4700::1"`
 *
 * 用于 DoH 的 JSON 接口（`https://xxx/resolve?...&type=HTTPS`）返回的 data 字段
 *
 * @returns {{priority: number, target: string, params: Array, paramMap: object, ech: Buffer}}
 */
function parsePresentation (text) {
  const tokens = tokenize(String(text))
  const priority = Number.parseInt(tokens.shift())
  const target = tokens.shift() || '.'

  const params = []
  const paramMap = {}

  for (const token of tokens) {
    const index = token.indexOf('=')
    const key = index === -1 ? token : token.substring(0, index)
    const value = index === -1 ? undefined : token.substring(index + 1)

    const keyCode = SVC_PARAM_KEYS[key.replace(/-/g, '_')]
    const param = {
      key: keyCode == null ? -1 : keyCode,
      name: key,
    }

    if (value == null) {
      param.value = true
    } else if (key === 'ech') {
      param.value = Buffer.from(value, 'base64')
      param.base64 = value
    } else if (key === 'alpn' || key === 'ipv4hint' || key === 'ipv6hint' || key === 'mandatory') {
      param.value = value.split(',')
    } else if (key === 'port') {
      param.value = Number.parseInt(value)
    } else {
      param.value = value
    }

    params.push(param)
    if (paramMap[param.name] == null) {
      paramMap[param.name] = param.value
    }
  }

  return {
    priority: Number.isNaN(priority) ? 0 : priority,
    target,
    params,
    paramMap,
    ech: paramMap.ech,
  }
}

/**
 * 按空白切分展示格式文本，同时处理双引号与转义字符
 */
function tokenize (text) {
  const tokens = []
  let current = ''
  let inQuotes = false
  let hasToken = false

  for (let i = 0; i < text.length; i++) {
    const char = text[i]

    if (char === '\\' && inQuotes && i + 1 < text.length) {
      current += text[++i]
      continue
    }

    if (char === '"') {
      inQuotes = !inQuotes
      hasToken = true
      continue
    }

    if (!inQuotes && /\s/.test(char)) {
      if (hasToken || current.length > 0) {
        tokens.push(current)
        current = ''
        hasToken = false
      }
      continue
    }

    current += char
  }

  if (hasToken || current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

module.exports = {
  TYPE_HTTPS,
  TYPE_SVCB,
  TYPE_CNAME,
  TYPE_OPT,
  SVC_PARAM_KEYS,
  typeName,
  isSvcType,
  typeCode,
  encodeName,
  encodeQuery,
  decodeName,
  decodeSvcParam,
  decodeSvcRecord,
  parseResponse,
  parseEchConfigList,
  pickEchConfig,
  parsePresentation,
  tokenize,
}

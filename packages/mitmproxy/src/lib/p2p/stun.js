/**
 * 极简 STUN 客户端（RFC 5389 Binding）：探测本机公网地址，用于生成 ds-p2p 分享链接。
 * 使用公共 STUN 服务器，无需自建。
 */
const dgram = require('node:dgram')

// 公共 STUN（固定列表，不配置化）。miwifi 优先做公网地址；多个不同 STUN 用于识别对称 NAT/端口规律。
const DEFAULT_STUN = [
  { host: 'stun.miwifi.com', port: 3478 },
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun.cloudflare.com', port: 3478 },
]

function encodeStunRequest () {
  // Binding Request, 20-byte header, empty attributes
  const buf = Buffer.alloc(20)
  buf.writeUInt16BE(0x0001, 0) // type Binding Request
  buf.writeUInt16BE(0, 2) // length
  // magic cookie 0x2112A442
  buf.writeUInt32BE(0x2112A442, 4)
  // transaction id
  for (let i = 0; i < 12; i++) {
    buf[8 + i] = Math.floor(Math.random() * 256)
  }
  return buf
}

function parseMappedAddress (msg) {
  if (!msg || msg.length < 20) {
    return null
  }
  // 简单解析 XOR-MAPPED-ADDRESS (0x0020) 或 MAPPED-ADDRESS (0x0001)
  let offset = 20
  while (offset + 4 <= msg.length) {
    const type = msg.readUInt16BE(offset)
    const len = msg.readUInt16BE(offset + 2)
    const valueStart = offset + 4
    if (valueStart + len > msg.length) {
      break
    }
    if ((type === 0x0020 || type === 0x0001) && len >= 8) {
      const family = msg[valueStart + 1]
      const portXor = type === 0x0020 ? msg.readUInt16BE(valueStart + 2) ^ 0x2112 : msg.readUInt16BE(valueStart + 2)
      if (family === 0x01 && len >= 8) {
        const a = msg[valueStart + 4] ^ (type === 0x0020 ? 0x21 : 0)
        const b = msg[valueStart + 5] ^ (type === 0x0020 ? 0x12 : 0)
        const c = msg[valueStart + 6] ^ (type === 0x0020 ? 0xA4 : 0)
        const d = msg[valueStart + 7] ^ (type === 0x0020 ? 0x42 : 0)
        return { address: `${a}.${b}.${c}.${d}`, port: portXor }
      }
      if (family === 0x02 && len >= 20) {
        // IPv6 XOR-MAPPED，此处从略，返回 null
        return null
      }
    }
    offset = valueStart + len + ((4 - (len % 4)) % 4)
  }
  return null
}

function stunOnce (server, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4')
    const req = encodeStunRequest()
    let done = false
    const finish = (value) => {
      if (done) {
        return
      }
      done = true
      try {
        socket.close()
      } catch {
        // ignore
      }
      resolve(value)
    }
    const timer = setTimeout(() => finish(null), timeoutMs)
    socket.on('message', (msg) => {
      clearTimeout(timer)
      finish(parseMappedAddress(msg))
    })
    socket.on('error', () => {
      clearTimeout(timer)
      finish(null)
    })
    socket.send(req, server.port, server.host)
  })
}

/**
 * @returns {Promise<{address: string, port: number}|null>}
 */
async function getPublicAddress () {
  for (const server of DEFAULT_STUN) {
    const result = await stunOnce(server)
    if (result && result.address && !result.address.startsWith('0.')) {
      return result
    }
  }
  return null
}

module.exports = {
  getPublicAddress,
  stunOnce,
  DEFAULT_STUN,
}

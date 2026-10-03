/**
 * 由于组件 `dns-over-tls@0.0.9` 不支持 `rejectUnauthorized` 和 `timeout` 两个参数，所以将源码复制过来，并简化了代码。
 */
const dnsPacket = require('dns-packet')
const tls_1 = require('node:tls')
const { Buffer } = require('node:buffer')
const randi = require('random-int')
const svcbUtil = require('../util.svcb')

const TWO_BYTES = 2

function getDnsQuery ({ type, name, klass, id }) {
  return {
    id,
    type: 'query',
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ class: klass, name, type }],
  }
}

/**
 * 给DNS报文添加2字节长度头（DoT/DoH的TCP报文格式）
 */
function frame (buffer) {
  const lengthBuffer = Buffer.alloc(TWO_BYTES)
  lengthBuffer.writeUInt16BE(buffer.length)
  return Buffer.concat([lengthBuffer, buffer])
}

/**
 * @param options.queryBuffer 自定义查询报文（已带2字节长度头），用于查询 `dns-packet` 不支持的类型，如 HTTPS(65)
 * @param options.decode 自定义响应解码函数，入参为不带长度头的DNS报文
 */
function query ({ host, servername, type, name, klass, port, family, rejectUnauthorized, timeout, queryBuffer, decode }) {
  return new Promise((resolve, reject) => {
    if (!host || !servername || !name) {
      throw new Error('At least host, servername and name must be set.')
    }

    let response = Buffer.alloc(0)
    let packetLength = 0
    const dnsQuery = getDnsQuery({ id: randi(0x0, 0xFFFF), type, name, klass })
    const dnsQueryBuf = queryBuffer != null ? queryBuffer : dnsPacket.streamEncode(dnsQuery)
    const socket = tls_1.connect({ host, port, servername, family: Number.parseInt(family) === 6 ? 6 : 4, rejectUnauthorized, timeout })

    // 超时处理
    let isFinished = false
    let interval
    if (timeout > 0) {
      interval = setInterval(() => {
        if (!isFinished) {
          socket.destroy((...args) => {
            console.info('socket destory callback args:', args)
          })

          reject(new Error('DNS查询超时'))
        }
      }, timeout)
    }

    socket.on('secureConnect', () => socket.write(dnsQueryBuf))
    socket.on('data', (data) => {
      if (timeout) {
        isFinished = true
        clearInterval(interval)
      }

      try {
        if (response.length === 0) {
          packetLength = data.readUInt16BE(0)
          if (packetLength < 12) {
            reject(new Error('Below DNS minimum packet length (DNS Header is 12 bytes)'))
            return
          }
          response = Buffer.from(data)
        } else {
          response = Buffer.concat([response, data])
        }

        if (response.length >= packetLength + TWO_BYTES) {
          socket.destroy()
          if (decode != null) {
            resolve(decode(response.subarray(TWO_BYTES, TWO_BYTES + packetLength)))
          } else {
            resolve(dnsPacket.streamDecode(response))
          }
        }
      } catch (e) {
        socket.destroy()
        reject(e)
      }
    })
    socket.on('error', (err) => {
      if (timeout) {
        isFinished = true
        clearInterval(interval)
      }
      reject(err)
    })
  })
}

/**
 * 查询 HTTPS(65)/SVCB(64) 记录（`dns-packet` 不支持该类型，使用 `util.svcb` 自行编解码）
 */
function querySvcb ({ host, servername, name, type, port, family, rejectUnauthorized, timeout }) {
  return query({
    host,
    servername,
    name,
    port,
    family,
    rejectUnauthorized,
    timeout,
    queryBuffer: frame(svcbUtil.encodeQuery(name, { type: svcbUtil.typeCode(type) })),
    decode: buffer => svcbUtil.parseResponse(buffer),
  })
}

exports.query = query
exports.querySvcb = querySvcb
exports.default = { query, querySvcb }

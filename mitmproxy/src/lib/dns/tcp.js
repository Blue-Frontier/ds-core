const net = require('node:net')
const { Buffer } = require('node:buffer')
const dnsPacket = require('dns-packet')
const randi = require('random-int')
const svcbUtil = require('./util.svcb')
const BaseDNS = require('./base')

const defaultPort = 53 // TCP类型的DNS服务默认端口号

module.exports = class DNSOverTCP extends BaseDNS {
  constructor (dnsName, cacheSize, preSetIpList, dnsServer, dnsServerPort, dnsFamily) {
    super(dnsServer.replace(/\s+/, ''), dnsFamily, dnsName, 'TCP', cacheSize, preSetIpList)
    this.dnsServerPort = Number.parseInt(dnsServerPort) || defaultPort
    this.isIPv6 = dnsServer.includes(':') && dnsServer.includes('[') && dnsServer.includes(']')
  }

  /**
   * 查询 HTTPS(65)/SVCB(64) 记录，用于获取 DNS 下发的 ECH 参数
   * 说明：`dns-packet` 不支持该类型，所以使用 `util.svcb` 自行编解码
   */
  _svcbQueryPromise (hostname, type = 'HTTPS') {
    const timeout = 5000
    return new Promise((resolve, reject) => {
      const packet = svcbUtil.encodeQuery(hostname, { type: svcbUtil.typeCode(type) })

      let isOver = false
      let response = Buffer.alloc(0)
      let timeoutId = null
      let tcpClient = null

      const finish = (err, value) => {
        if (isOver) {
          return
        }
        isOver = true
        clearTimeout(timeoutId)
        if (tcpClient != null) {
          tcpClient.destroy()
        }
        if (err) {
          reject(err)
        } else {
          resolve(value)
        }
      }

      tcpClient = net.createConnection({
        host: this.dnsServer,
        port: this.dnsServerPort,
        family: this.dnsFamily,
      }, () => {
        // TCP DNS 报文前需添加 2 字节长度头
        const lengthBuffer = Buffer.alloc(2)
        lengthBuffer.writeUInt16BE(packet.length)
        tcpClient.write(Buffer.concat([lengthBuffer, packet]))
      })

      tcpClient.on('data', (data) => {
        response = Buffer.concat([response, data])
        if (response.length < 2) {
          return
        }
        const length = response.readUInt16BE(0)
        if (response.length < length + 2) {
          return // 报文还没收完，继续等待
        }

        try {
          const parsed = svcbUtil.parseResponse(response.subarray(2, 2 + length))
          finish(null, parsed)
        } catch (e) {
          finish(e)
        }
      })

      tcpClient.once('error', (err) => {
        finish(err)
      })

      timeoutId = setTimeout(() => {
        finish(new Error('DNS查询超时'))
      }, timeout)
    })
  }

  _dnsQueryPromise (hostname, type = 'A') {
    return new Promise((resolve, reject) => {
      // 构造 DNS 查询报文
      const packet = dnsPacket.encode({
        flags: dnsPacket.RECURSION_DESIRED,
        type: 'query',
        id: randi(0x0, 0xFFFF),
        questions: [{
          type,
          name: hostname,
        }],
      })

      // --- TCP 查询 ---
      const tcpClient = net.createConnection({
        host: this.dnsServer,
        port: this.dnsServerPort,
        family: this.dnsFamily,
      }, () => {
        // TCP DNS 报文前需添加 2 字节长度头
        const lengthBuffer = Buffer.alloc(2)
        lengthBuffer.writeUInt16BE(packet.length)
        tcpClient.write(Buffer.concat([lengthBuffer, packet]))
      })

      tcpClient.once('data', (data) => {
        const length = data.readUInt16BE(0)
        const response = dnsPacket.decode(data.subarray(2, 2 + length))
        resolve(response)
        tcpClient.end()
      })

      tcpClient.once('error', (err) => {
        reject(err)
        tcpClient.end()
      })
    })
  }
}

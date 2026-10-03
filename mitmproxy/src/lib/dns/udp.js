const dgram = require('node:dgram')
const dnsPacket = require('dns-packet')
const randi = require('random-int')
const svcbUtil = require('./util.svcb')
const BaseDNS = require('./base')

const defaultPort = 53 // UDP类型的DNS服务默认端口号

module.exports = class DNSOverUDP extends BaseDNS {
  constructor (dnsName, cacheSize, preSetIpList, dnsServer, dnsServerPort, dnsFamily) {
    super(dnsServer.replace(/\s+/, ''), dnsFamily, dnsName, 'UDP', cacheSize, preSetIpList)
    this.dnsServerPort = Number.parseInt(dnsServerPort) || defaultPort

    this.socketType = this.dnsFamily === 6 ? 'udp6' : 'udp4'
  }

  /**
   * 查询 HTTPS(65)/SVCB(64) 记录，用于获取 DNS 下发的 ECH 参数
   * 说明：`dns-packet` 不支持该类型，所以使用 `util.svcb` 自行编解码
   */
  _svcbQueryPromise (hostname, type = 'HTTPS') {
    return new Promise((resolve, reject) => {
      let isOver = false
      const timeout = 5000
      let timeoutId = null

      const packet = svcbUtil.encodeQuery(hostname, { type: svcbUtil.typeCode(type) })

      const udpClient = dgram.createSocket(this.socketType, (msg, _rinfo) => {
        if (isOver) {
          return
        }
        isOver = true
        clearTimeout(timeoutId)
        udpClient.close()

        try {
          const response = svcbUtil.parseResponse(msg)
          if (response.truncated) {
            reject(new Error('DNS响应被截断(TC)，该DNS服务不支持UDP方式查询HTTPS记录'))
            return
          }
          resolve(response)
        } catch (e) {
          reject(e)
        }
      })

      udpClient.send(packet, 0, packet.length, this.dnsServerPort, this.dnsServer, (err, _bytes) => {
        if (err) {
          isOver = true
          clearTimeout(timeoutId)
          udpClient.close()
          reject(err)
        }
      })

      timeoutId = setTimeout(() => {
        if (!isOver) {
          isOver = true
          udpClient.close()
          reject(new Error('DNS查询超时'))
        }
      }, timeout)
    })
  }

  _dnsQueryPromise (hostname, type = 'A') {
    return new Promise((resolve, reject) => {
      let isOver = false
      const timeout = 5000
      let timeoutId = null

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

      // 创建客户端
      const udpClient = dgram.createSocket(this.socketType, (msg, _rinfo) => {
        isOver = true
        clearTimeout(timeoutId)

        const response = dnsPacket.decode(msg)
        resolve(response)
        udpClient.close()
      })

      // 发送 UDP 查询
      udpClient.send(packet, 0, packet.length, this.dnsServerPort, this.dnsServer, (err, _bytes) => {
        if (err) {
          isOver = true
          clearTimeout(timeoutId)
          reject(err)
          udpClient.close()
        }
      })

      // 设置超时任务
      timeoutId = setTimeout(() => {
        if (!isOver) {
          reject(new Error('DNS查询超时'))
          udpClient.close()
        }
      }, timeout)
    })
  }
}

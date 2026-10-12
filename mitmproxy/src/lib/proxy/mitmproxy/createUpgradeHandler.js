const http = require('node:http')
const https = require('node:https')
const log = require('../../../utils/util.log.server')
const util = require('../common/util')

// copy from node-http-proxy.  ^_^

// create connectHandler function
module.exports = function createUpgradeHandler (serverSetting) {
  // return
  return function upgradeHandler (req, cltSocket, head, ssl) {
    const clientOptions = util.getOptionsFromRequest(req, ssl, null, serverSetting)
    if (ssl && clientOptions.hostname && !clientOptions.servername) {
      // TLS 握手需要带 SNI（与 createRequestHandler 的常规请求路径保持一致）；
      // 缺失 SNI 时上游会报 WRONG_VERSION_NUMBER 或证书不匹配，
      // 这正是此前 wss:// 升级失败的根因（server.log 中的 upgradeHandler error）。
      clientOptions.servername = clientOptions.hostname
    }
    const proxyReq = (ssl ? https : http).request(clientOptions)
    proxyReq.on('error', (e) => {
      log.error('upgradeHandler error:', e)
      if (!cltSocket.destroyed) {
        cltSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      }
    })
    proxyReq.on('response', (res) => {
      // 上游没有回 101 而是普通 HTTP 响应：把状态行+响应头透传给客户端，再关闭
      if (!res.upgrade) {
        const lines = ['HTTP/1.1 ' + (res.statusCode || 502) + ' ' + (res.statusMessage || 'Bad Gateway')]
        for (const key of Object.keys(res.headers)) {
          const value = res.headers[key]
          if (Array.isArray(value)) {
            for (const v of value) lines.push(key + ': ' + v)
          } else {
            lines.push(key + ': ' + value)
          }
        }
        cltSocket.write(lines.join('\r\n') + '\r\n\r\n')
        res.pipe(cltSocket)
      }
    })

    proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
      proxySocket.on('error', (e) => {
        log.error('upgrade error:', e)
      })

      cltSocket.on('error', (e) => {
        log.error('upgrade socket error:', e)
        proxySocket.end()
      })

      proxySocket.setTimeout(0)
      proxySocket.setNoDelay(true)

      proxySocket.setKeepAlive(true, 0)

      if (proxyHead && proxyHead.length) {
        proxySocket.unshift(proxyHead)
      }

      const responseLines = ['HTTP/1.1 ' + (proxyRes.statusCode || 101) + ' ' + (proxyRes.statusMessage || 'Switching Protocols')]
      for (const key of Object.keys(proxyRes.headers)) {
        const value = proxyRes.headers[key]
        if (Array.isArray(value)) {
          for (const v of value) responseLines.push(key + ': ' + v)
        } else {
          responseLines.push(key + ': ' + value)
        }
      }
      cltSocket.write(responseLines.join('\r\n') + '\r\n\r\n')

      proxySocket.pipe(cltSocket).pipe(proxySocket)
    })
    proxyReq.end()
  }
}

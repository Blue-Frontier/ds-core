const http = require('node:http')
const https = require('node:https')
const tls = require('node:tls')
const net = require('node:net')
const log = require('../../../utils/util.log.server')
const util = require('../common/util')
const DnsUtil = require('../../dns')
const dnsLookup = require('./dnsLookup')

// copy from node-http-proxy.  ^_^

// create upgradeHandler function
// serverSetting: server config (verifySsl etc.)
// externalProxy: external proxy (string or function(req, ssl) => string), 与 createRequestHandler 一致
// dnsConfig: 完整 DNS 配置（mapping/preSetIpList/providers/speedTest），用于升级路径的 DNS 优选
// createIntercepts: 拦截器工厂（context => interceptors[]），把 sni/verifyHost 等规则应用到升级路径
// 升级（WebSocket）请求不走常规 requestHandler，必须把 SNI 伪装 + DNS 优选补齐，
// 否则 intercepted 域名的 wss:// 升级会因为无 SNI 或 DNS 未优选而失败。
module.exports = function createUpgradeHandler (serverSetting, externalProxy, dnsConfig, createIntercepts) {
  return function upgradeHandler (req, cltSocket, head, ssl) {
    const clientOptions = util.getOptionsFromRequest(req, ssl, externalProxy, serverSetting)
    if (ssl && clientOptions.hostname && !clientOptions.servername) {
      // TLS 握手需要带 SNI（与 createRequestHandler 的常规请求路径保持一致）；
      // 缺失 SNI 时上游会报 WRONG_VERSION_NUMBER 或证书不匹配，
      // 这正是此前 wss:// 升级失败的根因（server.log 中的 upgradeHandler error）。
      clientOptions.servername = clientOptions.hostname
    }

    // 应用拦截器（sni/verifyHost/proxy 等）到升级路径
    if (createIntercepts) {
      try {
        const context = {
          rOptions: clientOptions,
          log,
          setting: serverSetting,
        }
        const interceptors = createIntercepts(context)
        if (interceptors && interceptors.length > 0) {
          // 升级请求没有真正的 res；给一个吸收 setHeader 的 stub，
          // 避免 sni/proxy 等拦截器在 res.setHeader 上报错。
          const noopRes = { setHeader: () => {}, getHeader: () => undefined, getHeaders: () => ({}) }
          for (const interceptor of interceptors) {
            if (interceptor && interceptor.requestIntercept) {
              // 包装后的拦截器签名是 (context, req, res, ssl, next)，interceptOpt/matched 由闭包提供
              interceptor.requestIntercept(context, req, noopRes, ssl, () => {})
            }
          }
        }
      } catch (e) {
        log.error('upgradeHandler intercept error:', e)
      }
    }

    // 证书校验：verifyHost 与常规请求路径一致（sni.js 拦截器会把 verifyHost 写到 rOptions 上）
    if (ssl && clientOptions.protocol === 'https:' && clientOptions.hostname) {
      const realHost = clientOptions.hostname
      if (clientOptions.servername == null) {
        clientOptions.servername = realHost
      }
      const verifyHost = (clientOptions.verifyHost != null && clientOptions.verifyHost !== '') ? clientOptions.verifyHost : realHost
      if (clientOptions.servername !== realHost || verifyHost !== realHost) {
        clientOptions.checkServerIdentity = (_host, cert) => tls.checkServerIdentity(verifyHost, cert)
      }
    }

    // DNS 优选：intercepted 域名的自定义 DNS 映射同样作用于升级路径
    if (clientOptions.hostname && dnsConfig && dnsConfig.dnsMap && !net.isIP(clientOptions.hostname)) {
      // hostname 是纯域名（非 IP），需要 DNS 解析
      const isDnsIntercept = {}
      const dnsAndFamily = DnsUtil.getDNSAndFamily(dnsConfig, clientOptions.hostname)
      if (dnsAndFamily) {
        const fallbackDnsList = DnsUtil.getFallbackDnsList(dnsConfig, dnsAndFamily.dns)
        clientOptions.lookup = dnsLookup.createLookupFunc(null, dnsAndFamily, 'upgrade',
          'upgrade ' + clientOptions.hostname + ':' + clientOptions.port, clientOptions.port, isDnsIntercept, { fallbackDnsList })
        if (dnsAndFamily.family === 6) {
          clientOptions.family = 6
        }
      } else {
        clientOptions.lookup = dnsLookup.createDefaultLookupFunc(null, 'upgrade', clientOptions.hostname + ':' + clientOptions.port, DnsUtil.getFallbackDnsList(dnsConfig, null))
      }
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

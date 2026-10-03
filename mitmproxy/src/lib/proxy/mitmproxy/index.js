const http = require('node:http')
const log = require('../../../utils/util.log.server')
const speedTest = require('../../speed/index.js')
const trafficMonitor = require('../../traffic/TrafficMonitor')
const { startProcessResolver } = require('../../traffic/processResolver')
const config = require('../common/config')
const tlsUtils = require('../tls/tlsUtils')
const createConnectHandler = require('./createConnectHandler')
const createFakeServerCenter = require('./createFakeServerCenter')
const createRequestHandler = require('./createRequestHandler')
const createUpgradeHandler = require('./createUpgradeHandler')

// 进程解析器清理函数（createProxy 时写入，close 时调用，避免重复 start 泄漏 interval）
let stopProcessResolver = null

module.exports = {
  createProxy ({
    host = config.defaultHost,
    port = config.defaultPort,
    maxLength = config.defaultMaxLength,
    caCertPath,
    caKeyPath,
    sslConnectInterceptor,
    createIntercepts,
    middlewares = [],
    externalProxy,
    dnsConfig,
    setting,
    compatibleConfig,
  }, callback) {
    // Don't reject unauthorized
    // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    log.info(`CA Cert read in: ${caCertPath}`)
    log.info(`CA private key read in: ${caKeyPath}`)
    if (!caCertPath) {
      caCertPath = config.getDefaultCACertPath()
    }
    if (!caKeyPath) {
      caKeyPath = config.getDefaultCAKeyPath()
    }
    const rs = this.createCA({ caCertPath, caKeyPath })
    if (rs.create) {
      log.info(`CA Cert saved in: ${caCertPath}`)
      log.info(`CA private key saved in: ${caKeyPath}`)
    }

    port = ~~port
    const speedTestConfig = dnsConfig.speedTest
    if (speedTestConfig) {
      // 将完整 dnsConfig 传给测速器，由测速器按域名动态选择 DNS：
      // 预设IP > DNS设置(mapping) > IP测速勾选的 dnsProviders
      speedTest.initSpeedTest({ ...speedTestConfig, dnsConfig })
    }

    const rawRequestHandler = createRequestHandler(
      createIntercepts,
      middlewares,
      externalProxy,
      dnsConfig,
      setting,
      compatibleConfig,
    )

    // 所有 HTTP 请求（含 MITM 解密后的 HTTPS 请求）都会经过这里，统一做流量统计
    const requestHandler = (req, res, ssl) => {
      trafficMonitor.attachRequest(req, res)
      rawRequestHandler(req, res, ssl)
    }

    const upgradeHandler = createUpgradeHandler(setting)

    const fakeServersCenter = createFakeServerCenter({
      maxLength,
      caCertPath,
      caKeyPath,
      requestHandler,
      upgradeHandler,
    })

    const connectHandler = createConnectHandler(
      sslConnectInterceptor,
      middlewares,
      fakeServersCenter,
      dnsConfig,
      compatibleConfig,
    )

    // 单端口：HTTP 代理（绝对 URL）与 HTTPS CONNECT 共用同一端口
    // 协议由请求上下文判定，不再用端口区分
    const printDebugLog = process.env.NODE_ENV === 'development' && false

    // 从请求上下文判定协议：绝对 http://=HTTP；CONNECT/相对路径=HTTPS
    const getSslFromRequest = (req) => {
      const url = req.url || ''
      return !url.startsWith('http:')
    }

    const serverListen = (server, port, host) => {
      server.listen(port, host, () => {
        log.info(`dev-sidecar启动代理端口: ${host}:${port}（HTTP+HTTPS 共用）`)
        server.on('request', (req, res) => {
          const ssl = getSslFromRequest(req)
          if (printDebugLog) {
            log.debug(`【server request, ssl: ${ssl}】`, req.url)
          }
          requestHandler(req, res, ssl)
        })
        // CONNECT = TLS 隧道
        server.on('connect', (req, cltSocket, head) => {
          const ssl = true
          if (printDebugLog) {
            log.debug(`【server connect, ssl: ${ssl}】`, req.url)
          }
          connectHandler(req, cltSocket, head, ssl)
        })
        // TODO: handler WebSocket
        server.on('upgrade', (req, cltSocket, head) => {
          const ssl = getSslFromRequest(req)
          if (printDebugLog) {
            log.debug(`【server upgrade, ssl: ${ssl}】`, req.url)
          } else {
            log.info(`【server upgrade, ssl: ${ssl}】`, req.url)
          }
          upgradeHandler(req, cltSocket, head, ssl)
        })
        server.on('error', (err) => {
          log.error('【server error】', err)
        })
        server.on('clientError', (err, cltSocket) => {
          log.error('【server clientError】', err)
          cltSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
        })

        if (callback) {
          callback(server, port, host, true)
        }
      })
    }

    const server = new http.Server()

    // 单端口：HTTP 代理与 HTTPS CONNECT 共用
    serverListen(server, port, host)

    // 启动流量统计与进程解析
    trafficMonitor.start([port])
    if (stopProcessResolver) {
      stopProcessResolver()
    }
    stopProcessResolver = startProcessResolver(trafficMonitor)

    return [server]
  },
  createCA (caPaths) {
    return tlsUtils.initCA(caPaths)
  },
  stopProcessResolver () {
    if (stopProcessResolver) {
      stopProcessResolver()
      stopProcessResolver = null
    }
  },
}

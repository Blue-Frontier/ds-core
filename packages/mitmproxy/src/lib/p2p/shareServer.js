/**
 * L1 共享节点（境内 hop）：
 * - 默认 TLS 上的 HTTP 代理（CONNECT / 绝对 URL）+ Proxy-Authorization token
 * - 不做 REALITY/伪装；出墙仍由 DS 原有加速路径负责
 */
const http = require('node:http')
const https = require('node:https')
const net = require('node:net')
const tls = require('node:tls')
const log = require('../../utils/util.log.server')
const link = require('./link')
const { generateSelfSignedCert } = require('./cert')

function parseBasicToken (req, token) {
  if (!token) {
    return true
  }
  const header = req.headers['proxy-authorization'] || req.headers.authorization || ''
  const m = String(header).match(/^Basic\s+(.+)$/i)
  if (!m) {
    return false
  }
  try {
    const decoded = Buffer.from(m[1], 'base64').toString('utf8')
    const user = decoded.split(':')[0]
    return user === token || decoded === token || decoded === `${token}:`
  } catch {
    return false
  }
}

function authFailed (socket, res) {
  const body = 'Proxy authentication required (ds-p2p)'
  if (res) {
    res.writeHead(407, {
      'Proxy-Authenticate': 'Basic realm="ds-p2p"',
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
    })
    res.end(body)
    return
  }
  socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="ds-p2p"\r\nConnection: close\r\n\r\n')
  socket.destroy()
}

function handleRequest (token) {
  return (req, res) => {
    if (!parseBasicToken(req, token)) {
      authFailed(null, res)
      return
    }
    let target
    try {
      target = new URL(req.url)
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('Bad request')
      return
    }
    const isHttps = target.protocol === 'https:'
    const port = target.port || (isHttps ? 443 : 80)
    const opts = {
      hostname: target.hostname,
      port,
      method: req.method,
      path: target.pathname + target.search,
      headers: { ...req.headers, host: target.host },
    }
    const mod = isHttps ? require('node:https') : http
    const upstream = mod.request(opts, (upRes) => {
      res.writeHead(upRes.statusCode || 502, upRes.headers)
      upRes.pipe(res)
    })
    upstream.on('error', (e) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' })
      }
      res.end(`Bad gateway: ${e.message}`)
    })
    req.pipe(upstream)
  }
}

function handleConnect (token) {
  return (req, clientSocket, head) => {
    if (!parseBasicToken(req, token)) {
      authFailed(clientSocket)
      return
    }
    const [hostname, portStr] = String(req.url).split(':')
    const port = Number(portStr) || 443
    const serverSocket = net.connect(port, hostname, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: ds-p2p\r\n\r\n')
      if (head && head.length) {
        serverSocket.write(head)
      }
      serverSocket.pipe(clientSocket)
      clientSocket.pipe(serverSocket)
    })
    serverSocket.on('error', () => {
      clientSocket.destroy()
    })
    clientSocket.on('error', () => {
      serverSocket.destroy()
    })
  }
}

class ShareServer {
  /**
   * @param {object} options
   * @param {number} [options.port]
   * @param {string} [options.host]
   * @param {string} [options.token]
   * @param {string} [options.name]
   * @param {boolean} [options.tls=true] 默认 TLS；false 仅供本机调试
   * @param {string} [options.key] PEM
   * @param {string} [options.cert] PEM
   */
  constructor (options = {}) {
    this.port = options.port || 31288
    this.host = options.host || '0.0.0.0'
    this.token = options.token || ''
    this.name = options.name || ''
    this.useTls = options.tls !== false
    this.tlsKey = options.key
    this.tlsCert = options.cert
    this.server = null
    this.upnpStop = null
    this.fingerprint = null
  }

  buildShareLink (publicHost) {
    const host = publicHost
      || (this.host && this.host !== '0.0.0.0' && this.host !== '::' ? this.host : '')
    return link.formatLink({
      token: this.token,
      host,
      port: this.port,
      name: this.name,
    })
  }

  async start () {
    if (this.server) {
      return { port: this.port, host: this.host, tls: this.useTls }
    }
    const onRequest = handleRequest(this.token)
    const onConnect = handleConnect(this.token)

    if (this.useTls) {
      let key = this.tlsKey
      let cert = this.tlsCert
      if (!key || !cert) {
        const generated = generateSelfSignedCert(this.name || 'ds-p2p')
        key = generated.key
        cert = generated.cert
      }
      this.server = https.createServer({
        key,
        cert,
        minVersion: 'TLSv1.2',
        // 境内 hop 自签：客户端需允许自签或跳过校验
        rejectUnauthorized: false,
      }, onRequest)
      this.server.on('connect', onConnect)
    } else {
      this.server = http.createServer(onRequest)
      this.server.on('connect', onConnect)
    }

    await new Promise((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(this.port, this.host, () => {
        this.server.removeListener('error', reject)
        log.info(`[p2p] 共享代理已监听 ${this.host}:${this.port} (tls=${this.useTls})`)
        resolve()
      })
    })
    return { port: this.port, host: this.host, tls: this.useTls }
  }

  async stop () {
    if (this.upnpStop) {
      try {
        await this.upnpStop()
      } catch {
        // ignore
      }
      this.upnpStop = null
    }
    if (!this.server) {
      return
    }
    await new Promise((resolve) => {
      this.server.close(() => resolve())
      this.server = null
    })
    log.info('[p2p] 共享代理已停止')
  }

  getLink (publicHost) {
    return this.buildShareLink(publicHost)
  }
}

module.exports = {
  ShareServer,
  parseBasicToken,
}

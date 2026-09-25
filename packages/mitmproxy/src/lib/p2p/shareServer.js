/**
 * L1 共享节点：TLS+CONNECT，按客户端身份扣配额、限流
 */
const http = require('node:http')
const net = require('node:net')
const https = require('node:https')
const log = require('../../utils/util.log.server')
const link = require('./link')
const { generateSelfSignedCert } = require('./cert')
const identity = require('./identity')
const quota = require('./quota')
const cardMod = require('./card')

const GB = 1024 * 1024 * 1024

function parseBasicToken (req, token) {
  const header = req.headers['proxy-authorization'] || req.headers.authorization || ''
  const m = String(header).match(/^Basic\s+(.+)$/i)
  let authUser = null
  if (m) {
    try {
      const decoded = Buffer.from(m[1], 'base64').toString('utf8')
      authUser = decoded.split(':')[0]
    } catch {
      // ignore
    }
  }
  if (!token) {
    return { ok: true, clientId: clientIdFrom(req, authUser) }
  }
  if (!m) {
    return { ok: false }
  }
  try {
    const decoded = Buffer.from(m[1], 'base64').toString('utf8')
    const user = decoded.split(':')[0]
    const ok = user === token || decoded === token || decoded === `${token}:`
    return { ok, clientId: clientIdFrom(req, ok ? user : authUser) }
  } catch {
    return { ok: false }
  }
}

function clientIdFrom (req, authUser) {
  const headerId = req.headers['x-ds-node-id']
  if (headerId) {
    return String(headerId)
  }
  // Basic username 若不是 token，可当作 clientId
  return authUser && authUser.length >= 16 ? authUser : 'anonymous'
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

function handleControl (token) {
  return async (req, res) => {
    const url = String(req.url || '')
    const isInfo = /\/_ds\/p2p\/info(\?|$)/.test(url)
    const isRedeem = /\/_ds\/p2p\/redeem(\?|$)/.test(url)
    if (!isInfo && !isRedeem) {
      return false
    }
    const auth = parseBasicToken(req, token)
    if (!auth.ok) {
      authFailed(null, res)
      return true
    }
    const me = await identity.ensureIdentity()
    if (isInfo) {
      const q = auth.clientId && auth.clientId !== 'anonymous' ? quota.getQuota(auth.clientId) : null
      const body = JSON.stringify({
        nodeId: me.nodeId,
        protocol: 'ds-p2p',
        quota: q,
        availableGb: q ? q.availableGb : null,
      })
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
      res.end(body)
      return true
    }
    const chunks = []
    req.on('data', d => chunks.push(d))
    await new Promise(resolve => req.on('end', resolve))
    try {
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
      const clientNodeId = String(input.clientNodeId || auth.clientId || '')
      const card = String(input.card || '')
      const vr = await cardMod.verifyCard(card)
      if (!vr.ok) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, reason: vr.reason }))
        return true
      }
      if (!quota.markCardUsed(vr.payload.id)) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: false, reason: 'already used' }))
        return true
      }
      if (clientNodeId && clientNodeId !== 'anonymous') {
        quota.addQuota(clientNodeId, vr.payload.gb)
      }
      const q = clientNodeId && clientNodeId !== 'anonymous' ? quota.getQuota(clientNodeId) : null
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: true, quota: q, availableGb: q ? q.availableGb : null, gb: vr.payload.gb }))
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, reason: e.message }))
    }
    return true
  }
}

function handleRequest (token) {
  const control = handleControl(token)
  return async (req, res) => {
    if (await control(req, res)) {
      return
    }
    const auth = parseBasicToken(req, token)
    if (!auth.ok) {
      authFailed(null, res)
      return
    }
    if (!allowClient(auth.clientId)) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('Quota exceeded')
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
      upRes.on('data', (chunk) => accountBytes(auth.clientId, chunk.length))
      upRes.pipe(res)
    })
    upstream.on('error', (e) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' })
      }
      res.end(`Bad gateway: ${e.message}`)
    })
    req.on('data', (chunk) => accountBytes(auth.clientId, chunk.length))
    req.pipe(upstream)
  }
}

function accountBytes (clientId, n) {
  if (!clientId || clientId === 'anonymous' || !n) {
    return
  }
  const q = quota.getQuota(clientId)
  if (q.totalGb <= 0) {
    return
  }
  quota.addUsage(clientId, n / GB)
}

function allowClient (clientId) {
  if (!clientId || clientId === 'anonymous') {
    // 未带身份：允许（兼容本机调试）；若要强制配额可改为 false
    return true
  }
  const q = quota.getQuota(clientId)
  // 无任何充值记录时不拦；有记录且用尽才拦
  if (q.totalGb <= 0) {
    return true
  }
  return q.availableGb > 0
}

function handleConnect (token) {
  return (req, clientSocket, head) => {
    const auth = parseBasicToken(req, token)
    if (!auth.ok) {
      authFailed(clientSocket)
      return
    }
    if (!allowClient(auth.clientId)) {
      clientSocket.write('HTTP/1.1 403 Quota Exceeded\r\nConnection: close\r\n\r\n')
      clientSocket.destroy()
      return
    }
    const [hostname, portStr] = String(req.url).split(':')
    const port = Number(portStr) || 443
    const serverSocket = net.connect(port, hostname, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: ds-p2p\r\n\r\n')
      if (head && head.length) {
        serverSocket.write(head)
        accountBytes(auth.clientId, head.length)
      }
      serverSocket.pipe(clientSocket)
      clientSocket.pipe(serverSocket)
    })
    serverSocket.on('data', (chunk) => accountBytes(auth.clientId, chunk.length))
    clientSocket.on('data', (chunk) => accountBytes(auth.clientId, chunk.length))
    serverSocket.on('error', () => {
      clientSocket.destroy()
    })
    clientSocket.on('error', () => {
      serverSocket.destroy()
    })
  }
}

class ShareServer {
  constructor (options = {}) {
    this.port = options.port || 31288
    this.host = options.host || '0.0.0.0'
    this.token = options.token || ''
    this.name = options.name || ''
    this.tlsKey = options.key
    this.tlsCert = options.cert
    this.server = null
    this.upnpStop = null
    this.nodeId = ''
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
    // 每次启动检测并确保全局身份存在（私钥进 SecretStore）
    const me = await identity.ensureIdentity()
    this.nodeId = me.nodeId

    if (this.server) {
      return { port: this.port, host: this.host, nodeId: this.nodeId }
    }
    const onRequest = handleRequest(this.token)
    const onConnect = handleConnect(this.token)

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
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      rejectUnauthorized: false,
    }, onRequest)
    this.server.on('connect', onConnect)

    await new Promise((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(this.port, this.host, () => {
        this.server.removeListener('error', reject)
        log.info(`[p2p] 共享代理已监听 ${this.host}:${this.port} (TLS1.3+CONNECT) node=${this.nodeId}`)
        resolve()
      })
    })
    return { port: this.port, host: this.host, nodeId: this.nodeId }
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
  allowClient,
}

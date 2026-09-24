/**
 * 以 ds-p2p 节点为上游：TLS 上的 HTTP CONNECT。
 * 境内 hop 使用自签证书（rejectUnauthorized: false）。
 */
const net = require('node:net')
const tls = require('node:tls')

function basicAuthHeader (token) {
  if (!token) {
    return undefined
  }
  const raw = `${token}:`
  return `Basic ${Buffer.from(raw, 'utf8').toString('base64')}`
}

/**
 * 连到 peer 并为 host:port 建立 CONNECT 隧道。
 * @param {object} peer { host, port, token, tls? }
 * @param {string} targetHost
 * @param {number} targetPort
 * @returns {Promise<net.Socket|tls.TLSSocket>}
 */
function connectViaPeer (peer, targetHost, targetPort, options = {}) {
  const timeoutMs = options.timeoutMs || 8000
  return new Promise((resolve, reject) => {
    const useTls = peer.tls !== false
    const onReady = (socket) => {
      const auth = basicAuthHeader(peer.token)
      const headers = [
        `CONNECT ${targetHost}:${targetPort} HTTP/1.1`,
        `Host: ${targetHost}:${targetPort}`,
        auth ? `Proxy-Authorization: ${auth}` : null,
        'Proxy-Agent: ds-p2p',
        'Connection: keep-alive',
        '',
        '',
      ].filter((line) => line !== null).join('\r\n')

      let buf = Buffer.alloc(0)
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk])
        const idx = buf.indexOf('\r\n\r\n')
        if (idx < 0) {
          return
        }
        cleanup()
        const head = buf.subarray(0, idx).toString('utf8')
        const statusLine = head.split('\r\n')[0] || ''
        if (!/^HTTP\/1\.[01] 200/.test(statusLine)) {
          socket.destroy()
          reject(new Error(`peer CONNECT failed: ${statusLine || 'no response'}`))
          return
        }
        const rest = buf.subarray(idx + 4)
        if (rest.length && socket.unshift) {
          socket.unshift(rest)
        }
        resolve(socket)
      }
      const onErr = (err) => {
        cleanup()
        socket.destroy()
        reject(err)
      }
      const onTimeout = () => {
        cleanup()
        socket.destroy()
        reject(new Error('peer connect timeout'))
      }
      function cleanup () {
        socket.removeListener('data', onData)
        socket.removeListener('error', onErr)
        socket.removeListener('timeout', onTimeout)
        if (options.timeoutMs !== 0) {
          socket.setTimeout(0)
        }
      }
      socket.on('data', onData)
      socket.on('error', onErr)
      socket.setTimeout(timeoutMs, onTimeout)
      socket.write(headers)
    }

    const netOpts = {
      host: peer.host,
      port: peer.port || 31288,
      timeout: timeoutMs,
    }
    if (!useTls) {
      const sock = net.connect(netOpts, () => onReady(sock))
      sock.on('error', reject)
      return
    }
    const sock = tls.connect({
      host: peer.host,
      port: peer.port || 31288,
      // 境内自签 peer
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
      // 可选伪装 ALPN；节点间非 HTTPS 语义时保持空/自定义即可
      ALPNProtocols: options.ALPNProtocols || ['http/1.1'],
    }, () => onReady(sock))
    sock.setTimeout(timeoutMs)
    sock.on('error', reject)
    sock.on('timeout', () => {
      sock.destroy()
      reject(new Error('peer TLS timeout'))
    })
  })
}

/**
 * 从 peer 列表里选第一个可用的隧道到 targetHost:targetPort
 */
async function connectViaAnyPeer (peers, targetHost, targetPort, options = {}) {
  const errors = []
  for (const peer of peers || []) {
    try {
      const socket = await connectViaPeer(peer, targetHost, targetPort, options)
      return { socket, peer }
    } catch (e) {
      errors.push(`${peer.host}:${peer.port}: ${e.message}`)
    }
  }
  throw new Error(`no ds-p2p peer available for ${targetHost}:${targetPort}: ${errors.join('; ')}`)
}

module.exports = {
  connectViaPeer,
  connectViaAnyPeer,
  basicAuthHeader,
}

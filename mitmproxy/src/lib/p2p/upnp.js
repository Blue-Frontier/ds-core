/**
 * 可选 UPnP IGD 端口映射（L1）。纯 Node SSDP + SOAP，无第三方依赖。
 * 失败时静默返回 null（路由器不支持/未开启 UPnP 时属正常）。
 */
const dgram = require('node:dgram')
const http = require('node:http')
const { Buffer } = require('node:buffer')
const log = require('../../utils/util.log.server')

const SSDP_ADDR = '239.255.255.250'
const SSDP_PORT = 1900

function soapRequest (controlUrl, serviceType, action, args) {
  const props = Object.entries(args)
    .map(([k, v]) => `<${k}>${v}</${k}>`)
    .join('')
  const body = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:${action} xmlns:u="${serviceType}">${props}</u:${action}>
  </s:Body>
</s:Envelope>`
  return { body, headers: {
    'Content-Type': 'text/xml; charset="utf-8"',
    'Content-Length': Buffer.byteLength(body),
    SOAPAction: `"${serviceType}#${action}"`,
  } }
}

function httpPost (url, headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const req = http.request({
      hostname: u.hostname,
      port: u.port || 80,
      path: u.pathname + u.search,
      method: 'POST',
      headers,
      timeout: 3000,
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.on('error', reject)
    req.on('timeout', () => {
      req.destroy(new Error('upnp timeout'))
    })
    req.end(body)
  })
}

function discoverGateway (timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4')
    const msg = Buffer.from([
      'M-SEARCH * HTTP/1.1',
      `HOST: ${SSDP_ADDR}:${SSDP_PORT}`,
      'MAN: "ssdp:discover"',
      'MX: 2',
      'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1',
      '',
      '',
    ].join('\r\n'))
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
    socket.on('message', (rinfo) => {
      // 用 LOCATION 头简化：从整包解析
      clearTimeout(timer)
      finish({ rinfo })
    })
    socket.on('error', () => {
      clearTimeout(timer)
      finish(null)
    })
    // 更完整解析放在外部 message 监听
    socket.removeAllListeners('message')
    socket.on('message', (msg) => {
      const text = msg.toString('utf8')
      const loc = /LOCATION:\s*(.+)/i.exec(text)
      if (loc) {
        clearTimeout(timer)
        finish({ location: loc[1].trim(), rinfo })
      }
    })
    socket.bind(() => {
      try {
        socket.setBroadcast(true)
      } catch {
        // ignore
      }
      socket.send(msg, SSDP_PORT, SSDP_ADDR)
    })
  })
}

/**
 * 添加端口映射：externalPort -> localPort
 * @returns {Promise<{stop: Function, externalHost?: string}|null>}
 */
async function mapPort ({ internalPort, externalPort = internalPort, description = 'dev-sidecar' }) {
  const found = await discoverGateway()
  if (!found || !found.location) {
    log.info('[p2p] UPnP：未发现网关，跳过端口映射')
    return null
  }
  // 为简化，假定控制 URL 为 location 同主机的 /upnp/control/WANIPConn1（常见 IGD）
  // 完整实现需解析设备描述 XML；失败则返回 null
  try {
    const loc = new URL(found.location)
    const controlUrl = `${loc.origin}/upnp/control/WANIPConn1`
    const serviceType = 'urn:schemas-upnp-org:service:WANIPConnection:1'
    const args = {
      NewRemoteHost: '',
      NewExternalPort: String(externalPort),
      NewProtocol: 'TCP',
      NewInternalPort: String(internalPort),
      NewInternalClient: await guessLocalIp(),
      NewEnabled: '1',
      NewPortMappingDescription: description,
      NewLeaseDuration: '0',
    }
    const { body, headers } = soapRequest(controlUrl, serviceType, 'AddPortMapping', args)
    await httpPost(controlUrl, headers, body)
    log.info(`[p2p] UPnP 映射成功: tcp/${externalPort} -> ${internalPort} @ ${loc.hostname}`)
    return {
      externalHost: loc.hostname,
      stop: async () => {
        try {
          const del = soapRequest(controlUrl, serviceType, 'DeletePortMapping', {
            NewRemoteHost: '',
            NewExternalPort: String(externalPort),
            NewProtocol: 'TCP',
          })
          await httpPost(controlUrl, del.headers, del.body)
        } catch {
          // ignore
        }
      },
    }
  } catch (e) {
    log.warn('[p2p] UPnP 映射失败:', e.message)
    return null
  }
}

function guessLocalIp () {
  return new Promise((resolve) => {
    const { createConnection } = require('node:net')
    const s = createConnection({ host: '8.8.8.8', port: 80 })
    s.on('connect', () => {
      const ip = s.localAddress
      s.destroy()
      resolve(ip)
    })
    s.on('error', () => resolve('127.0.0.1'))
  })
}

module.exports = {
  mapPort,
  discoverGateway,
}

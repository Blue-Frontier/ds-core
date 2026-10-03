const assert = require('node:assert')
const http = require('node:http')
const https = require('node:https')
const { ShareServer } = require('../src/lib/p2p/shareServer')
const { connectViaPeer } = require('../src/lib/p2p/upstream')
const { generateSelfSignedCert } = require('../src/lib/p2p/cert')

async function listen (server, port = 0) {
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', resolve)
  })
  return server.address().port
}

async function main () {
  // echo target
  const target = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' })
    res.end(`ok:${req.url}`)
  })
  const targetPort = await listen(target)

  const certPem = generateSelfSignedCert('test-peer')
  const share = new ShareServer({
    host: '127.0.0.1',
    port: 0,
    token: 'secret',
    tls: true,
    key: certPem.key,
    cert: certPem.cert,
  })
  await share.start()
  // get actual port
  const sharePort = share.server.address().port

  const socket = await connectViaPeer(
    { host: '127.0.0.1', port: sharePort, token: 'secret', tls: true },
    '127.0.0.1',
    targetPort,
  )
  assert.ok(socket, 'tunnel socket')

  const body = await new Promise((resolve, reject) => {
    const req = http.request({
      createConnection: () => socket,
      host: '127.0.0.1',
      port: targetPort,
      path: '/hello',
      method: 'GET',
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    })
    req.on('error', reject)
    req.end()
  })
  assert.strictEqual(body, 'ok:/hello')

  // wrong token should fail
  let failed = false
  try {
    await connectViaPeer(
      { host: '127.0.0.1', port: sharePort, token: 'wrong', tls: true },
      '127.0.0.1',
      targetPort,
      { timeoutMs: 2000 },
    )
  } catch {
    failed = true
  }
  assert.strictEqual(failed, true, 'bad token must fail')

  await share.stop()
  target.close()
  console.log('ds-p2p TLS CONNECT test passed')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})

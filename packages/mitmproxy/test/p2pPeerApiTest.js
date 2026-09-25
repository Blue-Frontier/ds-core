const assert = require('node:assert')
const { ShareServer } = require('../src/lib/p2p/shareServer')
const { getPeerInfo, redeemCardOnPeer } = require('../src/lib/p2p/upstream')
const { issueCard } = require('../src/lib/p2p/card')
const { getIdentity } = require('../src/lib/p2p/identity')
const { generateSelfSignedCert } = require('../src/lib/p2p/cert')

async function main () {
  const certPem = generateSelfSignedCert('peer')
  const share = new ShareServer({
    host: '127.0.0.1',
    port: 0,
    token: 'secret',
    key: certPem.key,
    cert: certPem.cert,
  })
  await share.start()
  const port = share.server.address().port
  const peer = { host: '127.0.0.1', port, token: 'secret' }

  const info = await getPeerInfo(peer)
  assert.strictEqual(info.status, 200)
  assert.ok(info.body.nodeId, 'nodeId')
  assert.strictEqual(info.body.nodeId, getIdentity().nodeId)

  const card = await issueCard({ gb: 5, ttlDays: 1 })
  const me = getIdentity()
  const r = await redeemCardOnPeer(peer, card, me.nodeId)
  assert.strictEqual(r.status, 200)
  assert.strictEqual(r.body.ok, true)
  assert.ok(r.body.quota && r.body.quota.availableGb >= 5, JSON.stringify(r.body))

  const r2 = await redeemCardOnPeer(peer, card, me.nodeId)
  assert.strictEqual(r2.body.ok, false)

  await share.stop()
  console.log('peer info/redeem test passed')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})

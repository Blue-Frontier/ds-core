/* global describe, it */

const assert = require('node:assert/strict')
const { ShareServer } = require('../src/lib/p2p/shareServer')
const { getPeerInfo, redeemCardOnPeer } = require('../src/lib/p2p/upstream')
const { issueCard } = require('../src/lib/p2p/card')
const { getIdentity } = require('../src/lib/p2p/identity')
const { generateSelfSignedCert } = require('../src/lib/p2p/cert')

describe('p2p 对端接口', () => {
  it('查询节点信息并兑换卡密，重复兑换被拒绝', async () => {
    const certPem = generateSelfSignedCert('peer')
    const share = new ShareServer({
      host: '127.0.0.1',
      port: 0,
      token: 'secret',
      key: certPem.key,
      cert: certPem.cert,
    })
    await share.start()
    try {
      const port = share.server.address().port
      const peer = { host: '127.0.0.1', port, token: 'secret' }

      const info = await getPeerInfo(peer)
      assert.equal(info.status, 200)
      assert.ok(info.body.nodeId, 'nodeId')
      assert.equal(info.body.nodeId, getIdentity().nodeId)

      const card = await issueCard({ gb: 5, ttlDays: 1 })
      const me = getIdentity()
      const r = await redeemCardOnPeer(peer, card, me.nodeId)
      assert.equal(r.status, 200)
      assert.equal(r.body.ok, true)
      assert.ok(r.body.quota && r.body.quota.availableGb >= 5, JSON.stringify(r.body))

      const r2 = await redeemCardOnPeer(peer, card, me.nodeId)
      assert.equal(r2.body.ok, false, '同一张卡不能兑换两次')
    } finally {
      await share.stop()
    }
  })
})

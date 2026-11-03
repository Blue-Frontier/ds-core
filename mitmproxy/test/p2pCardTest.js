/* global describe, it */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { issueCard, verifyCard, redeemCard, parseCard } = require('../src/lib/p2p/card')

describe('p2p 卡密', () => {
  it('签发、验签、核销、拒绝重放与过期', async () => {
    const card = await issueCard({ gb: 10, ttlDays: 1 })
    assert.ok(card.startsWith('ds-card://'), card)
    assert.ok(parseCard(card))

    const v = await verifyCard(card)
    assert.equal(v.ok, true, v.reason)
    assert.equal(v.payload.gb, 10)

    const store = path.join(os.tmpdir(), `p2p-cards-test-${Date.now()}.json`)
    try {
      const r1 = await redeemCard(card, { storePath: store })
      assert.equal(r1.ok, true, r1.reason)
      const r2 = await redeemCard(card, { storePath: store })
      assert.equal(r2.ok, false)
      assert.equal(r2.reason, 'already used')
    } finally {
      fs.rmSync(store, { force: true })
    }

    const expired = await issueCard({ gb: 1, expireAt: Math.floor(Date.now() / 1000) - 10 })
    assert.equal((await verifyCard(expired)).ok, false)
    assert.equal((await verifyCard('ds-card://xx.yy')).ok, false)
  })
})

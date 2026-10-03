const assert = require('node:assert')
const path = require('node:path')
const os = require('node:os')
const { issueCard, verifyCard, redeemCard, parseCard } = require('../src/lib/p2p/card')

async function main () {
  const card = await issueCard({ gb: 10, ttlDays: 1 })
  assert.ok(card.startsWith('ds-card://'), card)
  assert.ok(parseCard(card))

  const v = await verifyCard(card)
  assert.strictEqual(v.ok, true, v.reason)
  assert.strictEqual(v.payload.gb, 10)

  const store = path.join(os.tmpdir(), `p2p-cards-test-${Date.now()}.json`)
  const r1 = await redeemCard(card, { storePath: store })
  assert.strictEqual(r1.ok, true, r1.reason)
  const r2 = await redeemCard(card, { storePath: store })
  assert.strictEqual(r2.ok, false)
  assert.strictEqual(r2.reason, 'already used')

  const expired = await issueCard({ gb: 1, expireAt: Math.floor(Date.now() / 1000) - 10 })
  assert.strictEqual((await verifyCard(expired)).ok, false)

  assert.strictEqual((await verifyCard('ds-card://xx.yy')).ok, false)
  console.log('card tests passed')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})

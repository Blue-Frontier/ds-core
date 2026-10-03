const assert = require('node:assert')
const { formatLink, parseLink, parsePeerList } = require('../src/lib/p2p/link')

const a = formatLink({ token: 'abc', host: '1.2.3.4', port: 31288, name: '家宽' })
const b = formatLink({ token: 'abc', host: '1.2.3.4', port: 31288, name: '家宽' })
assert.notStrictEqual(a, b)
assert.ok(a.startsWith('ds-p2p://') && !a.includes('o.'), a)
assert.ok(!a.includes('abc') && !a.includes('1.2.3.4'))
assert.deepStrictEqual(parseLink(a), { token: 'abc', host: '1.2.3.4', port: 31288, name: '家宽' })

const t1 = formatLink({ token: 'tokA', host: '1.2.3.4', port: 31288 })
const t2 = formatLink({ token: 'tokB', host: '1.2.3.4', port: 31288 })
assert.notStrictEqual(t1, t2)
assert.deepStrictEqual(parseLink(t1), { token: 'tokA', host: '1.2.3.4', port: 31288 })
assert.deepStrictEqual(parseLink(t2), { token: 'tokB', host: '1.2.3.4', port: 31288 })

const hostLink = formatLink({ token: 't', host: 'example.com', port: 2000 })
assert.deepStrictEqual(parseLink(hostLink), { token: 't', host: 'example.com', port: 2000 })

const list = parsePeerList(`# c\n${a}\n${t1}\n`)
assert.strictEqual(list.length, 2)

assert.strictEqual(parseLink('ds-p2p://'), null)
assert.strictEqual(parseLink('not-a-link'), null)
console.log('ds-p2p link tests passed')

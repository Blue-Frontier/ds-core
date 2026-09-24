const assert = require('node:assert')
const { formatLink, parseLink, parsePeerList } = require('../src/lib/p2p/link')

const full = formatLink({ token: 'abc', host: '1.2.3.4', port: 31288, name: '家宽' })
assert.strictEqual(full, 'ds-p2p://abc@1.2.3.4:31288#%E5%AE%B6%E5%AE%BD')

const n1 = parseLink(full)
assert.deepStrictEqual(n1, { token: 'abc', host: '1.2.3.4', port: 31288, name: '家宽' })

const n2 = parseLink('ds-p2p://example.com:2000')
assert.deepStrictEqual(n2, { host: 'example.com', port: 2000 })

const n3 = parseLink('10.0.0.2:31288#lan')
assert.deepStrictEqual(n3, { host: '10.0.0.2', port: 31288, name: 'lan' })

const list = parsePeerList(`
# comment
ds-p2p://a@1.1.1.1:1#x
ds-p2p://2.2.2.2:2
`)
assert.strictEqual(list.length, 2)

assert.strictEqual(parseLink('ds-p2p://'), null)
console.log('ds-p2p link tests passed')

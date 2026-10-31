/* global describe, it */

const assert = require('node:assert/strict')
const { redactText } = require('../src/utils/util.redact.js')

describe('redactText credentials', () => {
  it('masks JSON-style credentials (running.json / logs)', () => {
    const text = JSON.stringify({
      plugin: { overwall: { password: 'qwza111' } },
      share: { token: 'bbb222', peers: [{ host: 'a.example', port: 1, token: 'ccc333' }] },
      headers: { authorization: 'Bearer ddd444', cookie: 'sid=eee555' },
    }, null, 2)

    const out = redactText(text)
    for (const leaked of ['qwza111', 'bbb222', 'ccc333', 'ddd444', 'eee555']) {
      assert.equal(out.includes(leaked), false, `${leaked} 应被打码`)
    }
    assert.match(out, /"password": "\*\*\*"/)
  })

  it('masks dashed credential keys (e.g. cf-access-client-secret)', () => {
    const out = redactText('{"cf-access-client-secret": "fff666"}')
    assert.equal(out.includes('fff666'), false)
    assert.ok(out.includes('"cf-access-client-secret": "***"'))
  })

  it('masks key=value style credentials', () => {
    const out = redactText('password: qwza111 token=bbb222')
    assert.equal(out.includes('qwza111'), false)
    assert.equal(out.includes('bbb222'), false)
  })

  it('keeps urls readable as host only', () => {
    const out = redactText('https://example.com/path?token=fff666')
    assert.equal(out.includes('fff666'), false)
    assert.ok(out.includes('example.com'))
  })
})

const assert = require('node:assert')
const { defaultConfig } = require('../src/config/index.js')

// eslint-disable-next-line no-undef
describe('ech domains escaping', () => {
  // eslint-disable-next-line no-undef
  it('X（Twitter）的 ECH 正则不会误命中 okx.com 等相似域名', () => {
    const domains = defaultConfig.server.dns.ech.domains
    const rule = domains.find(d => d.startsWith('^(.+'))
    assert.ok(rule, '默认配置里应存在 X 的 ECH 正则')

    const re = new RegExp(rule)
    assert.strictEqual(re.test('x.com'), true)
    assert.strictEqual(re.test('www.x.com'), true)
    assert.strictEqual(re.test('okx.com'), false, 'okx.com 不是 X 的域名')
    assert.strictEqual(re.test('www.okx.com'), false, 'www.okx.com 不是 X 的域名')
  })

  // eslint-disable-next-line no-undef
  it('preSetIpDomains 使用同一份正确转义', () => {
    const list = defaultConfig.server.dns.ech.preSetIpDomains
    const rule = list.find(d => d.startsWith('^(.+'))
    assert.ok(rule, '默认配置里应存在 X 的 ECH 预置 IP 规则')
    assert.strictEqual(new RegExp(rule).test('www.okx.com'), false)
    assert.strictEqual(new RegExp(rule).test('www.x.com'), true)
  })
})

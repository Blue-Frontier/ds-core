const assert = require('node:assert')
const { buildRemoteConfigFetchRules } = require('../src/config/remote-config-rule.js')

// eslint-disable-next-line no-undef
describe('remote config fetch rule', () => {
  const remoteConfig = { enabled: true, url: 'https://rc.example.com/remote_config.json5' }

  // eslint-disable-next-line no-undef
  it('sni 与目标域名不同时显式关闭校验（SNI 诱饵会让证书对不上）', () => {
    const result = buildRemoteConfigFetchRules({
      remoteConfig,
      providers: {},
      patch: { sni: 'baidu.com', dns: null, preSetIpList: null },
    })
    const rule = result.intercepts['rc.example.com']['.*']
    assert.strictEqual(rule.sni, 'baidu.com')
    assert.strictEqual(rule.unVerifySsl, true)
  })

  // eslint-disable-next-line no-undef
  it('sni 与目标域名相同时不需要关闭校验', () => {
    const result = buildRemoteConfigFetchRules({
      remoteConfig,
      providers: {},
      patch: { sni: 'rc.example.com', dns: null, preSetIpList: null },
    })
    const rule = result.intercepts['rc.example.com']['.*']
    assert.strictEqual(rule.unVerifySsl, undefined)
  })

  // eslint-disable-next-line no-undef
  it('默认不改写 SNI 时不生成 intercept', () => {
    const result = buildRemoteConfigFetchRules({
      remoteConfig,
      providers: {},
      patch: { sni: null, dns: null, preSetIpList: null },
    })
    assert.strictEqual(result.intercepts['rc.example.com'], undefined)
  })
})

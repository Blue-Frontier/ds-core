const assert = require('node:assert')
const { applyRemoteConfigUrlFix } = require('../src/config/index.js')
const { isPlainHttpUrl, toHttpsUrl, applyRemoteConfigUrlHttps } = require('../src/config/remote-config-url.js')

// eslint-disable-next-line no-undef
describe('remote config url', () => {
  // eslint-disable-next-line no-undef
  it('isPlainHttpUrl', () => {
    assert.strictEqual(isPlainHttpUrl('http://a.com/rc.json5'), true)
    assert.strictEqual(isPlainHttpUrl('HTTP://a.com/rc.json5'), true)
    assert.strictEqual(isPlainHttpUrl('  http://a.com/rc.json5'), true)
    assert.strictEqual(isPlainHttpUrl('https://a.com/rc.json5'), false)
    assert.strictEqual(isPlainHttpUrl(''), false)
    assert.strictEqual(isPlainHttpUrl(undefined), false)
  })

  // eslint-disable-next-line no-undef
  it('toHttpsUrl: 仅改写裸 HTTP，其余原样返回', () => {
    assert.strictEqual(toHttpsUrl('http://a.com/rc.json5'), 'https://a.com/rc.json5')
    assert.strictEqual(toHttpsUrl('  http://a.com/rc.json5'), 'https://a.com/rc.json5')
    assert.strictEqual(toHttpsUrl('https://a.com/rc.json5'), 'https://a.com/rc.json5')
    assert.strictEqual(toHttpsUrl(''), '')
    assert.strictEqual(toHttpsUrl(undefined), undefined)
  })

  // eslint-disable-next-line no-undef
  it('applyRemoteConfigUrlHttps: 共享与个人地址都被改写为 HTTPS', () => {
    const config = { app: { remoteConfig: { url: 'http://a.com/rc.json5', personalUrl: 'http://b.com/rc.json5' } } }
    applyRemoteConfigUrlHttps(config)
    assert.strictEqual(config.app.remoteConfig.url, 'https://a.com/rc.json5')
    assert.strictEqual(config.app.remoteConfig.personalUrl, 'https://b.com/rc.json5')

    // 幂等
    applyRemoteConfigUrlHttps(config)
    assert.strictEqual(config.app.remoteConfig.url, 'https://a.com/rc.json5')
  })

  // eslint-disable-next-line no-undef
  it('applyRemoteConfigUrlFix: 历史废弃地址纠正为官方地址', () => {
    const config = {
      app: {
        remoteConfig: {
          url: 'https://gitee.com/docmirror/dev-sidecar/raw/master/packages/core/src/config/remote_config.json5',
        },
      },
    }
    applyRemoteConfigUrlFix(config)
    assert.strictEqual(config.app.remoteConfig.url, 'https://ds-official-config.bestar.de5.net/remote_config.json5')
  })

  // eslint-disable-next-line no-undef
  it('applyRemoteConfigUrlFix: 无 remoteConfig 时不报错', () => {
    assert.deepStrictEqual(applyRemoteConfigUrlFix({}), {})
    assert.strictEqual(applyRemoteConfigUrlFix({ app: {} }).app.remoteConfig, undefined)
  })
})

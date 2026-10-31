/* global describe, before, after, it */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const configLoader = require('../src/config/local-config-loader.js')
const mergeApi = require('../src/merge.js')

describe('local config null deletion markers', () => {
  let home
  let previousUserProfile

  before(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'ds-core-config-'))
    previousUserProfile = process.env.USERPROFILE
    process.env.USERPROFILE = home
  })

  after(() => {
    if (previousUserProfile === undefined) {
      delete process.env.USERPROFILE
    } else {
      process.env.USERPROFILE = previousUserProfile
    }
    fs.rmSync(home, { recursive: true, force: true })
  })

  function load (userConfig, defaultDomains) {
    const defaultConfig = { proxy: { excludeIpList: defaultDomains } }
    return configLoader.getConfigFromFiles(userConfig, defaultConfig).proxy.excludeIpList
  }

  it('removes one default excluded domain after reload', () => {
    assert.deepStrictEqual(load({ proxy: { excludeIpList: { 'default.example': null } } }, { 'default.example': true }), {})
  })

  it('removes all default excluded domains when the list is cleared', () => {
    assert.deepStrictEqual(load({ proxy: { excludeIpList: { 'first.example': null, 'second.example': null } } }, { 'first.example': true, 'second.example': true }), {})
  })

  it('allows overriding a default excluded domain value', () => {
    assert.deepStrictEqual(load({ proxy: { excludeIpList: { 'default.example': false } } }, { 'default.example': true }), { 'default.example': false })
  })

  it('removes a custom domain added by the user', () => {
    const diff = mergeApi.doDiff(
      { proxy: { excludeIpList: { 'default.example': true, 'custom.example': true } } },
      { proxy: { excludeIpList: { 'default.example': true } } },
    )
    assert.deepStrictEqual(load(diff, { 'default.example': true, 'custom.example': true }), { 'default.example': true })
  })

  it('lets a remote null remove a lower-priority default item', () => {
    fs.writeFileSync(configLoader.getRemoteConfigPath(), '{ proxy: { excludeIpList: { "remote.example": null } } }')
    assert.deepStrictEqual(load(null, { 'remote.example': true }), {})
  })
})

describe('xget overlay cloudflare access headers', () => {
  function xgetConfig (setting) {
    return { plugin: { xget: { enabled: true, setting } } }
  }

  function walkRules (overlay, visit) {
    const intercepts = overlay.server.intercepts
    for (const host of Object.keys(intercepts)) {
      const pathRules = intercepts[host]
      for (const pathRegex of Object.keys(pathRules)) {
        visit(pathRules[pathRegex])
      }
    }
  }

  it('injects cf access headers into every rule when both tokens are set', () => {
    const overlay = configLoader.getXgetOverlay(xgetConfig({
      instanceUrl: 'https://xget.example.com',
      cfAccessClientId: ' client-id ',
      cfAccessClientSecret: ' secret ',
    }))
    let ruleCount = 0
    walkRules(overlay, (rule) => {
      assert.equal(rule.requestReplace.headers['cf-access-client-id'], 'client-id')
      assert.equal(rule.requestReplace.headers['cf-access-client-secret'], 'secret')
      ruleCount++
    })
    assert.ok(ruleCount > 0, '覆盖层应包含规则')
  })

  it('leaves rules untouched when tokens are missing or half-filled', () => {
    const settings = [
      { instanceUrl: 'https://xget.example.com' },
      { instanceUrl: 'https://xget.example.com', cfAccessClientId: 'only-id' },
      { instanceUrl: 'https://xget.example.com', cfAccessClientSecret: 'only-secret' },
    ]
    for (const setting of settings) {
      const overlay = configLoader.getXgetOverlay(xgetConfig(setting))
      walkRules(overlay, (rule) => {
        assert.equal(rule.requestReplace, undefined)
      })
    }
  })

  it('returns null when the plugin is disabled or the instance url is empty', () => {
    assert.equal(configLoader.getXgetOverlay({ plugin: { xget: { enabled: false, setting: { instanceUrl: 'https://xget.example.com' } } } }), null)
    assert.equal(configLoader.getXgetOverlay(xgetConfig({ instanceUrl: ' ' })), null)
  })
})

describe('remote config version selection', () => {
  let home
  let previousUserProfile

  before(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'ds-core-versions-'))
    previousUserProfile = process.env.USERPROFILE
    process.env.USERPROFILE = home
  })

  after(() => {
    if (previousUserProfile === undefined) {
      delete process.env.USERPROFILE
    } else {
      process.env.USERPROFILE = previousUserProfile
    }
    fs.rmSync(home, { recursive: true, force: true })
  })

  it('lists live and historical versions for both remote layers', () => {
    fs.writeFileSync(configLoader.getRemoteConfigPath(), '{ app: { metaInfo: { id: "shared", version: "2" } } }')
    fs.writeFileSync(configLoader.getRemoteConfigPath('_personal'), '{ app: { metaInfo: { id: "personal", version: "3" } } }')
    configLoader.saveRemoteConfigVersion('{ app: { metaInfo: { id: "shared", version: "1" } } }', '', '100')
    configLoader.saveRemoteConfigVersion('{ app: { metaInfo: { id: "personal", version: "2" } } }', '_personal', '200')

    assert.deepStrictEqual(configLoader.getRemoteConfigVersions(''), [
      { version: '', id: 'shared', label: '2', latest: true, selected: true },
      { version: '100', id: 'shared', label: '1', selected: false },
    ])
    assert.deepStrictEqual(configLoader.getRemoteConfigVersions('_personal'), [
      { version: '', id: 'personal', label: '3', latest: true, selected: true },
      { version: '200', id: 'personal', label: '2', selected: false },
    ])
  })

  it('selects an existing history entry and falls back to live when cleared', () => {
    fs.writeFileSync(configLoader.getRemoteConfigPath(), '{ app: { metaInfo: { id: "shared", version: "2" } } }')
    configLoader.saveRemoteConfigVersion('{ app: { metaInfo: { id: "shared", version: "1" } } }', '', '100')
    configLoader.setRemoteSelection('', '100')

    assert.equal(configLoader.getRemoteConfig().app.metaInfo.version, '1')
    assert.equal(configLoader.getRemoteConfigVersions('')[1].selected, true)

    configLoader.setRemoteSelection('', '')
    assert.equal(configLoader.getRemoteConfig().app.metaInfo.version, '2')
    assert.equal(configLoader.getRemoteConfigVersions('')[0].selected, true)
  })
})

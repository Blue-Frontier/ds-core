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

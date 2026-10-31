/* global describe, it, afterEach */

const assert = require('node:assert/strict')
const { createSecretVault, resolvedSnapshot, ENV_KEY, ACCOUNT_OVERWALL, ACCOUNT_SHARE } = require('../src/utils/util.secret-vault')

function fakeStore () {
  const data = new Map()
  return {
    data,
    async getSecret (name) {
      return data.has(name) ? data.get(name) : null
    },
    async setSecret (name, value) {
      data.set(name, value)
      return { backend: 'fake' }
    },
    async deleteSecret (name) {
      return data.delete(name)
    },
    async hasSecret (name) {
      return data.has(name)
    },
  }
}

function fakeConfig (initial) {
  const cfg = JSON.parse(JSON.stringify(initial))
  const updates = []
  return {
    cfg,
    updates,
    get: () => cfg,
    update: async (part) => {
      updates.push(part)
    },
  }
}

describe('secret vault', () => {
  afterEach(() => {
    delete process.env[ENV_KEY]
  })

  it('round-trips accounts and deletes empty ones', async () => {
    const store = fakeStore()
    const vault = createSecretVault(store)

    await vault.writeAccount(ACCOUNT_OVERWALL, { 'a.example': 'pw-1' })
    assert.deepEqual(await vault.readAccount(ACCOUNT_OVERWALL), { 'a.example': 'pw-1' })

    await vault.writeAccount(ACCOUNT_OVERWALL, {})
    assert.deepEqual(await vault.readAccount(ACCOUNT_OVERWALL), {})
    assert.equal(store.data.has(ACCOUNT_OVERWALL), false)
  })

  it('migrates legacy plaintext into the vault and clears config', async () => {
    const store = fakeStore()
    const vault = createSecretVault(store)
    const config = fakeConfig({
      plugin: {
        overwall: { server: { 'ow.example': { id: 1, port: 443, path: '/x', password: 'ow-secret' } } },
        share: {
          setting: {
            token: 'my-node-token',
            peers: [{ host: '1.2.3.4', port: 31288, tls: true, token: 'peer-token', uri: 'ds-p2p://peer-token@1.2.3.4:31288' }],
          },
        },
      },
    })

    const migrated = await vault.migrate(config)
    assert.equal(migrated, true)

    const overwall = await vault.readAccount(ACCOUNT_OVERWALL)
    assert.equal(overwall['ow.example'], 'ow-secret')
    assert.equal(config.cfg.plugin.overwall.server['ow.example'].password, '')

    const share = await vault.readAccount(ACCOUNT_SHARE)
    assert.equal(share.token, 'my-node-token')
    assert.equal(share.peers['1.2.3.4:31288'], 'peer-token')
    assert.equal(config.cfg.plugin.share.setting.token, '')
    const peer = config.cfg.plugin.share.setting.peers[0]
    assert.equal(peer.token, '')
    assert.equal(peer.uri, '', '原始链接里带令牌，必须清掉')
    assert.equal(peer.host, '1.2.3.4')

    // 幂等：再跑一次不应再迁移
    assert.equal(await vault.migrate(config), false)
  })

  it('exposes a readable snapshot for the proxy child process', async () => {
    const store = fakeStore()
    const vault = createSecretVault(store)
    await vault.writeAccount(ACCOUNT_OVERWALL, { 'ow.example': 'pw-2' })

    const env = await vault.prepareEnv()
    assert.equal(typeof env[ENV_KEY], 'string')
    assert.equal(process.env[ENV_KEY], env[ENV_KEY])
    assert.deepEqual(resolvedSnapshot().overwall, { 'ow.example': 'pw-2' })
  })

  it('treats broken or missing snapshots as empty', () => {
    delete process.env[ENV_KEY]
    assert.deepEqual(resolvedSnapshot(), {})
    process.env[ENV_KEY] = '{not json'
    assert.deepEqual(resolvedSnapshot(), {})
  })
})

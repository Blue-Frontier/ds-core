/* global describe, it, afterEach */

const assert = require('node:assert/strict')
const childProcess = require('node:child_process')
const os = require('node:os')
const path = require('node:path')

/**
 * server.start() 的凭据链路回归：A24 那次崩溃是「把模块命名空间当 vault 实例用」，
 * 依赖被 typeof 守卫吞掉后迁移与快照注入会静默消失，单测必须能看见这件事。
 * 这里用假 SecretStore + 假 fork 跑 start()，不读真实配置、不动系统密钥库。
 */

const STUBBED = {
  configApi: require.resolve('../src/config-api'),
  secretStore: require.resolve('../src/utils/util.secret-store'),
  secretVault: require.resolve('../src/utils/util.secret-vault'),
  caStore: require.resolve('../src/utils/util.ca-store'),
  fsPrivate: require.resolve('../src/utils/util.fs-private'),
  fetchRules: require.resolve('../src/config/remote-config-rule'),
  json: require.resolve('@blue-frontier/mitmproxy/src/json'),
  server: require.resolve('../src/modules/server'),
}

function stubModule (id, exports) {
  const saved = require.cache[id]
  require.cache[id] = { id, filename: id, loaded: true, exports }
  return () => {
    if (saved) {
      require.cache[id] = saved
    } else {
      delete require.cache[id]
    }
  }
}

function fakeStore (data = new Map()) {
  return {
    getSecret: async name => (data.has(name) ? data.get(name) : null),
    setSecret: async (name, value) => {
      data.set(name, value)
      return { backend: 'fake' }
    },
    deleteSecret: async name => data.delete(name),
  }
}

describe('server.start 凭据链路', () => {
  const restores = []
  afterEach(() => {
    while (restores.length) {
      restores.pop()()
    }
    delete process.env.DS_SECRET_MAP
  })

  it('迁移旧明文并把 DS_SECRET_MAP 注入代理子进程', async () => {
    // 夹具值只在这里定义一次，断言引用同一常量，避免两处字面量写歪
    const OW_PASSWORD = 'ow-fixture'
    const SHARE_TOKEN = 'share-fixture'
    const storeData = new Map()
    const config = {
      server: {
        port: 31181,
        setting: {
          userBasePath: path.join(os.tmpdir(), 'ds-server-start-test'),
          rootCaFile: { certPath: 'ca.crt', keyPath: 'ca.key.pem' },
        },
        intercept: {},
        intercepts: {},
        dns: { mapping: {} },
        preSetIpList: {},
      },
      plugin: {
        overwall: { server: { 'ow.example': { password: OW_PASSWORD } } },
        share: { setting: { token: SHARE_TOKEN, peers: [] } },
      },
    }
    const updates = []

    let forkedEnv
    const child = { pid: 4242, connected: false, killed: false, exitCode: null, on () {}, send () {}, kill () {} }
    const realFork = childProcess.fork
    childProcess.fork = (modulePath, args, options) => {
      forkedEnv = options && options.env
      return child
    }
    restores.push(() => {
      childProcess.fork = realFork
    })

    restores.push(stubModule(STUBBED.configApi, {
      get: () => config,
      update: async (part) => {
        updates.push(part)
      },
    }))
    restores.push(stubModule(STUBBED.secretStore, fakeStore(storeData)))
    restores.push(stubModule(STUBBED.secretVault, undefined)) // 让 util.secret-vault 重新加载，绑定假 store
    restores.push(stubModule(STUBBED.server, undefined)) // 让 server/index.js 重新加载，绑定上述桩
    restores.push(stubModule(STUBBED.caStore, { prepareCa: async () => ({}), CA_KEY_ENV: 'DS_CA_KEY_PEM' }))
    restores.push(stubModule(STUBBED.fsPrivate, { writeFilePrivate: () => {} }))
    restores.push(stubModule(STUBBED.fetchRules, {
      buildRemoteConfigFetchRules: () => ({ providers: {}, intercepts: {}, dnsMapping: {}, preSetIpList: {}, applied: [] }),
    }))
    restores.push(stubModule(STUBBED.json, { stringify: () => '{}' }))
    delete require.cache[STUBBED.secretVault]
    delete require.cache[STUBBED.server]

    const server = require(STUBBED.server)
    const started = await server.start({ mitmproxyPath: 'mitmproxy.js', plugins: {} })

    assert.equal(started.port, 31181)
    assert.equal(config.plugin.overwall.server['ow.example'].password, '', '明文口令必须从配置里清空')
    assert.equal(config.plugin.share.setting.token, '', '明文令牌必须从配置里清空')
    assert.deepEqual(updates.map(u => Object.keys(u.plugin)[0]).sort(), ['overwall', 'share'])

    const snapshot = JSON.parse(forkedEnv.DS_SECRET_MAP)
    assert.equal(snapshot.overwall['ow.example'], OW_PASSWORD, '口令必须通过快照交给代理子进程')
    assert.equal(snapshot.share.token, SHARE_TOKEN)
    assert.equal(storeData.has('overwall-servers'), true, '口令必须落进密钥库')
  })
})

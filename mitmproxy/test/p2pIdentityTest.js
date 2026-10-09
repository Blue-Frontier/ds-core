// 回归测试：p2p identity 的 getIdentity() 缓存竞态
//
// 场景：机器上已有身份文件（私钥只存在 SecretStore 中，identity.json 里只有 privateKeyStored），
// 此时 loadOrCreateIdentity() 返回的记录不带 privateKey。若在 ensureIdentity() 的 await
// 间隙中有并发访问，旧实现的 getIdentity()（判断条件 cached && cached.privateKey）会丢弃
// 在途记录并重建缓存，导致后续 getPrivateKeyObject() 读到的记录不是被填充过的那一个，
// 报 “identity private key not loaded; call ensureIdentity() first”。
// 并发调用 ensureIdentity() 时，私钥缺失还会各自生成新身份，造成公钥/nodeId 漂移。
//
// 身份文件路径与 SecretStore 后端都是进程级全局状态，因此用子进程 + 临时 HOME +
// 强制 file-aes 后端做隔离，避免污染同进程内其他测试。
const assert = require('node:assert')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execFile } = require('node:child_process')
const { promisify } = require('node:util')

const execFileAsync = promisify(execFile)

const MITMPROXY_ROOT = path.resolve(__dirname, '..')
const IDENTITY_MODULE = path.join(MITMPROXY_ROOT, 'src/lib/p2p/identity.js')
const SECRET_STORE_MODULE = '@blue-frontier/dev-sidecar/src/utils/util.secret-store'

// 子进程内执行：预置“已有身份”状态，然后在冷缓存下制造并发
const CHILD_SCRIPT = `
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

async function main () {
  const secretStore = require(${JSON.stringify(SECRET_STORE_MODULE)})
  secretStore.backend = 'file-aes' // 强制文件后端，配合临时 HOME 实现隔离

  // 预置身份：私钥只写进 SecretStore，identity.json 中不含 privateKey
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
  const privB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
  const pubDer = publicKey.export({ type: 'spki', format: 'der' })
  await secretStore.setSecret('p2p-identity-private-key', privB64)

  const dir = path.resolve(process.env.HOME, './.dev-sidecar')
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'p2p-identity.json'), JSON.stringify({
    nodeId: crypto.createHash('sha256').update(pubDer).digest('base64url'),
    createdAt: new Date().toISOString(),
    publicKey: pubDer.toString('base64'),
    privateKeyStored: true,
  }, null, 2) + '\\n', { mode: 0o600 })

  // 冷缓存下并发：ensureIdentity() 进入 await 间隙后，另一路立即读取
  const identity = require(${JSON.stringify(IDENTITY_MODULE)})
  const pending = identity.ensureIdentity()
  identity.getPublicKeyObject() // 旧实现会在此丢弃在途记录、重建缓存
  await pending
  identity.getPrivateKeyObject() // 旧实现抛 “identity private key not loaded”
}

main()
  .then(() => console.log('p2p identity race test passed'))
  .catch((e) => { console.error(e.message); process.exit(1) })
`

/* eslint-disable no-undef -- describe/it 来自 mocha 运行器，eslint 未配置 mocha 全局变量 */
describe('p2p identity 并发初始化（缓存竞态）', function () {
  this.timeout(60000)

  it('并发访问不得使 ensureIdentity 填充的记录与缓存脱钩', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ds-identity-test-'))
    try {
      const { stdout } = await execFileAsync(process.execPath, ['-e', CHILD_SCRIPT], {
        cwd: MITMPROXY_ROOT,
        env: {
          ...process.env,
          // userBase() 优先取 USERPROFILE，两个都指向临时目录才能隔离
          HOME: home,
          USERPROFILE: home,
          DS_SECRET_PASSWORD: 'ds-identity-test-passphrase',
        },
      })
      assert.match(stdout, /p2p identity race test passed/)
    } finally {
      fs.rmSync(home, { recursive: true, force: true })
    }
  })
})

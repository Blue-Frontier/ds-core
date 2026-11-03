/* global describe, it */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execFile } = require('node:child_process')
const { promisify } = require('node:util')

const execFileAsync = promisify(execFile)

const MITMPROXY_ROOT = path.resolve(__dirname, '..')
const IDENTITY_MODULE = path.join(MITMPROXY_ROOT, 'src/lib/p2p/identity.js')
const CARD_MODULE = path.join(MITMPROXY_ROOT, 'src/lib/p2p/card.js')
const SECRET_STORE_MODULE = '@blue-frontier/dev-sidecar/src/utils/util.secret-store'

// 子进程内执行：先正常建立身份，再把密钥库里的私钥换成另一把（模拟后端切换后两边不是一对），
// 重新加载模块模拟下一次启动，验证公钥/nodeId 会按密钥库私钥修复、卡密验签恢复正常
const CHILD_SCRIPT = `
const crypto = require('node:crypto')

async function main () {
  const secretStore = require(${JSON.stringify(SECRET_STORE_MODULE)})
  secretStore.backend = 'file-aes' // 强制文件后端，配合临时 HOME 隔离
  const identityPath = require.resolve(${JSON.stringify(IDENTITY_MODULE)})

  let identity = require(identityPath)
  await identity.ensureIdentity()
  const beforePublic = identity.getIdentity().publicKey

  // 换掉密钥库里的私钥
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  const privB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
  const pubDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
  await secretStore.setSecret(identity.SECRET_ACCOUNT, privB64)

  // 模拟下一次启动：冷缓存重新加载身份模块
  delete require.cache[identityPath]
  identity = require(identityPath)
  const rec = await identity.ensureIdentity()

  if (rec.publicKey === beforePublic) {
    throw new Error('公钥没有按密钥库私钥修复')
  }
  if (rec.publicKey !== pubDer.toString('base64')) {
    throw new Error('公钥不是密钥库私钥对应的那一把')
  }
  if (rec.nodeId !== identity.nodeIdFromPublicKey(pubDer)) {
    throw new Error('nodeId 没有跟着公钥一起修复')
  }

  const { issueCard, verifyCard } = require(${JSON.stringify(CARD_MODULE)})
  const verified = await verifyCard(await issueCard({ gb: 1, ttlDays: 1 }))
  if (!verified.ok) {
    throw new Error('修复后卡密验签仍失败: ' + verified.reason)
  }
}

main()
  .then(() => console.log('p2p identity repair test passed'))
  .catch((e) => { console.error(e.message); process.exit(1) })
`

describe('p2p identity 公钥与密钥库私钥不一致时自愈', () => {
  it('按密钥库私钥重建公钥与 nodeId，卡密验签恢复', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ds-identity-repair-'))
    try {
      const { stdout } = await execFileAsync(process.execPath, ['-e', CHILD_SCRIPT], {
        cwd: MITMPROXY_ROOT,
        env: {
          ...process.env,
          HOME: home,
          USERPROFILE: home,
          DS_SECRET_PASSWORD: 'ds-repair-fixture-pass',
        },
      })
      assert.match(stdout, /p2p identity repair test passed/)
    } finally {
      fs.rmSync(home, { recursive: true, force: true })
    }
  })
})

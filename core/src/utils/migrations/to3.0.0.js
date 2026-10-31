/**
 * ─────────────────────────────────────────────────────────────
 *  Migration:  2.2.0  →  3.0.0
 *  Name:       secrets-to-secret-store
 *  Id:         v3.0.0
 *
 *  此文件只服务「迁到 3.0.0」这一件事。
 *  日后新增迁移请新建 `v3.x.y` / `v4.0.0` 模块，勿在此叠逻辑。
 *  幂等：可重复执行。
 * ─────────────────────────────────────────────────────────────
 */
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const secretStore = require('../util.secret-store')

/** 本迁移目标版本；写入 config.app.migratedTo */
const MIGRATION_TARGET = '3.0.0'
const MIGRATION_ID = 'to3.0.0'

function userBase () {
  const home = process.env.USERPROFILE || process.env.HOME || os.homedir()
  return path.resolve(home, './.dev-sidecar')
}

// —— v3.0.0 账户名（与 2.2.0 明文文件一一对应）——
const ACCOUNT_CA_PEM = 'system-ca-private-key'
const ACCOUNT_P2P_ID_KEY = 'p2p-identity-private-key'

function caPemPaths () {
  return [
    path.join(userBase(), 'dev-sidecar.ca.key.pem'),
    path.join(userBase(), 'dev-sidecar.ca.key.pem.moved'),
  ].filter((p) => p.endsWith('.pem'))
}

/**
 * v3.0.0 step 1: CA 私钥 pem → SecretStore，删除明文
 */
/**
 * v3.0.0 step 1: CA 私钥备份进 SecretStore，明文文件**保留**并收紧权限
 *
 * 不删除的原因：代理子进程的 initCA() 需要这两个文件；删掉后它会把
 * 「文件不存在」当成首次运行，直接换发一张新 CA，用户已安装的根证书随即失效，
 * 浏览器表现为间歇性的证书错误。证书也一并备份，文件丢失时能恢复同一 CA。
 */
async function migrateTo300_caPrivateKey () {
  const step = `${MIGRATION_ID}:ca-key`
  const keyPath = path.join(userBase(), 'dev-sidecar.ca.key.pem')
  const certPath = path.join(userBase(), 'dev-sidecar.ca.crt')
  let action = 'none'

  for (const p of caPemPaths()) {
    try {
      const pem = fs.readFileSync(p, 'utf8')
      if (!pem || !/PRIVATE/i.test(pem)) {
        continue
      }
      await secretStore.setSecret(ACCOUNT_CA_PEM, pem)
      action = 'stored'
      if (p === keyPath && process.platform !== 'win32') {
        try {
          fs.chmodSync(p, 0o600)
        } catch { /* 权限收紧失败不影响使用 */ }
      }
    } catch { /* 文件不存在，跳过 */ }
  }

  try {
    if (fs.existsSync(certPath)) {
      const certPem = fs.readFileSync(certPath, 'utf8')
      if (certPem && certPem.includes('BEGIN CERTIFICATE')) {
        await secretStore.setSecret('system-ca-cert', certPem)
      }
    }
  } catch { /* 证书读取失败不影响私钥备份 */ }

  // 旧版本遗留的 .pem.moved 备份仍清掉
  try {
    const moved = path.join(userBase(), 'dev-sidecar.ca.key.pem.moved')
    if (fs.existsSync(moved)) {
      fs.unlinkSync(moved)
    }
  } catch { /* ignore */ }

  return { step, action }
}

/**
 * v3.0.0 step 2: p2p 身份私钥 → SecretStore；json 去掉 privateKey
 */
async function migrateTo300_identityPrivateKey () {
  const step = `${MIGRATION_ID}:identity-key`
  const file = path.join(userBase(), 'p2p-identity.json')
  const legacyNodeKey = path.join(userBase(), 'p2p-node.key.json')
  if (!fs.existsSync(file)) {
    return { step, action: 'none' }
  }
  let record
  try {
    record = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return { step, action: 'error', reason: 'bad json' }
  }

  let migrated = false
  if (record.privateKey) {
    await secretStore.setSecret(ACCOUNT_P2P_ID_KEY, record.privateKey)
    migrated = true
  } else if (!record.privateKeyStored && fs.existsSync(legacyNodeKey)) {
    try {
      const old = JSON.parse(fs.readFileSync(legacyNodeKey, 'utf8'))
      if (old && old.privateKey) {
        await secretStore.setSecret(ACCOUNT_P2P_ID_KEY, old.privateKey)
        if (old.publicKey && !record.publicKey) {
          record.publicKey = old.publicKey
        }
        migrated = true
        fs.unlinkSync(legacyNodeKey)
      }
    } catch { /* ignore */ }
  }

  if (migrated || record.privateKeyStored) {
    delete record.privateKey
    record.privateKeyStored = true
    // 标记本条目已由 v3.0.0 处理，便于与未来迁移区分
    record.secretsSchema = record.secretsSchema || MIGRATION_TARGET
    fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
    return { step, action: migrated ? 'migrated' : 'already' }
  }
  return { step, action: 'none' }
}

/**
 * 执行 2.2.0 → 3.0.0 全部步骤（幂等）
 * @returns {Promise<{migration: string, target: string, backend: string, results: Array}>}
 */
async function runMigration_to3_0_0 () {
  const backend = secretStore.detectBackend()
  const results = [
    await migrateTo300_caPrivateKey(),
    await migrateTo300_identityPrivateKey(),
  ]
  if (await secretStore.hasSecret(ACCOUNT_P2P_ID_KEY)) {
    const legacy = path.join(userBase(), 'p2p-node.key.json')
    try {
      if (fs.existsSync(legacy)) {
        fs.unlinkSync(legacy)
      }
    } catch { /* ignore */ }
  }
  return {
    migration: MIGRATION_ID,
    target: MIGRATION_TARGET,
    backend,
    results,
    secretDir: path.join(userBase(), 'secrets'),
  }
}

module.exports = {
  MIGRATION_ID,
  MIGRATION_TARGET,
  runMigration_to3_0_0,
  // 兼容旧调用名（可删）
  runSecurityMigration: runMigration_to3_0_0,
}

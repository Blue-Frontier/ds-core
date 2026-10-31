/**
 * 插件凭据仓库：把口令/令牌存进 SecretStore（keytar 优先，回退本机 AES-GCM 文件），
 * 启动代理时以「一次性快照」的形式通过环境变量交给代理子进程，
 * 使 config.json / running.json 里不再出现明文。
 *
 * 账号与结构：
 *   overwall-servers  { "<domain>": "<password>" }
 *   share-secrets     { "token": "<节点令牌>", "peers": { "<host>:<port>": "<token>" } }
 *
 * 与 Xget 的 CF Access 令牌同一套思路：规则里只留占位符，真实值不落盘。
 */
const defaultStore = require('./util.secret-store')

// 子进程环境变量名（值为 JSON 快照）
const ENV_KEY = 'DS_SECRET_MAP'
const ACCOUNT_OVERWALL = 'overwall-servers'
const ACCOUNT_SHARE = 'share-secrets'

function parseJson (raw) {
  if (!raw) {
    return {}
  }
  try {
    const value = JSON.parse(raw)
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
  } catch {
    return {}
  }
}

/**
 * @param store SecretStore 实例（测试时可注入假实现）
 */
function createSecretVault (store = defaultStore) {
  async function readAccount (name) {
    return parseJson(await store.getSecret(name))
  }

  async function writeAccount (name, value) {
    if (!value || Object.keys(value).length === 0) {
      await store.deleteSecret(name)
      return
    }
    await store.setSecret(name, JSON.stringify(value))
  }

  async function readAll () {
    const [overwall, share] = await Promise.all([
      readAccount(ACCOUNT_OVERWALL),
      readAccount(ACCOUNT_SHARE),
    ])
    return { overwall, share }
  }

  /**
   * 把旧版明文配置迁进 SecretStore 并从配置里清掉。幂等。
   * @returns {Promise<boolean>} 是否发生了迁移
   */
  async function migrate (config) {
    const all = config.get() || {}
    let migrated = false

    // 增强功能（overwall）各服务器口令
    const overwall = (all.plugin && all.plugin.overwall) || {}
    const servers = overwall.server || {}
    const overwallMap = await readAccount(ACCOUNT_OVERWALL)
    for (const domain of Object.keys(servers)) {
      const item = servers[domain]
      const password = item && typeof item.password === 'string' ? item.password.trim() : ''
      if (!password) {
        continue
      }
      overwallMap[domain] = password
      item.password = ''
      migrated = true
    }
    if (migrated) {
      await writeAccount(ACCOUNT_OVERWALL, overwallMap)
      await config.update({ plugin: { overwall: { server: servers } } })
    }

    // P2P 节点分享：本节点令牌 + 各对端令牌
    const share = (all.plugin && all.plugin.share) || {}
    const setting = share.setting || {}
    const shareMap = await readAccount(ACCOUNT_SHARE)
    let shareMigrated = false
    if (typeof setting.token === 'string' && setting.token.trim()) {
      shareMap.token = setting.token.trim()
      setting.token = ''
      shareMigrated = true
    }
    const peers = Array.isArray(setting.peers) ? setting.peers : []
    for (const peer of peers) {
      if (!peer || typeof peer.token !== 'string' || !peer.token) {
        continue
      }
      shareMap.peers = shareMap.peers || {}
      shareMap.peers[`${peer.host}:${peer.port}`] = peer.token
      peer.token = ''
      // 原始 ds-p2p 链接里带着令牌，一并清掉（界面回落到 host:port）
      peer.uri = ''
      shareMigrated = true
    }
    if (shareMigrated) {
      await writeAccount(ACCOUNT_SHARE, shareMap)
      await config.update({ plugin: { share: { setting } } })
    }

    return migrated || shareMigrated
  }

  /** 生成子进程快照，同时同步到本进程环境（core 侧读同一份） */
  async function prepareEnv () {
    const snapshot = JSON.stringify(await readAll())
    process.env[ENV_KEY] = snapshot
    return { [ENV_KEY]: snapshot }
  }

  return {
    readAccount,
    writeAccount,
    readAll,
    migrate,
    prepareEnv,
  }
}

/** 进程内同步读取快照（代理子进程与 core 都用它） */
function resolvedSnapshot () {
  return parseJson(process.env[ENV_KEY])
}

module.exports = {
  ENV_KEY,
  ACCOUNT_OVERWALL,
  ACCOUNT_SHARE,
  createSecretVault,
  resolvedSnapshot,
  vault: createSecretVault(),
}

/**
 * 本机节点身份密钥（以后签卡密/许可用），不参与分享链接加解密。
 * 首次使用生成 Ed25519，存到 ~/.dev-sidecar/p2p-node.key.json（仅私钥，权限尽量收紧）。
 */
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const crypto = require('node:crypto')

function getUserBasePath () {
  const home = process.env.USERPROFILE || process.env.HOME || os.homedir()
  return path.resolve(home, './.dev-sidecar')
}

function nodeKeyPath () {
  return path.join(getUserBasePath(), 'p2p-node.key.json')
}

function loadOrCreateNodeKey () {
  const file = nodeKeyPath()
  if (fs.existsSync(file)) {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (raw && raw.privateKey && raw.publicKey) {
      return raw
    }
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  const record = {
    createdAt: new Date().toISOString(),
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  }
  fs.mkdirSync(getUserBasePath(), { recursive: true })
  fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
  return record
}

module.exports = {
  loadOrCreateNodeKey,
  nodeKeyPath,
}

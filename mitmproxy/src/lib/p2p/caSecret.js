/**
 * 系统 CA 私钥：SecretStore 优先；兼容磁盘上遗留的 dev-sidecar.ca.key.pem
 */
const fs = require("node:fs")
const secretStore = require("@blue-frontier/dev-sidecar/src/utils/util.secret-store")

const CA_ACCOUNT = "system-ca-private-key"

async function ensureCaPrivateKey (keyPath) {
  const stored = await secretStore.getSecret(CA_ACCOUNT)
  if (stored) {
    return stored
  }
  if (keyPath && fs.existsSync(keyPath)) {
    const pem = fs.readFileSync(keyPath, "utf8")
    await secretStore.setSecret(CA_ACCOUNT, pem)
    try {
      fs.writeFileSync(keyPath + ".moved", "private key moved to SecretStore\n", "utf8")
    } catch {
      // ignore
    }
    return pem
  }
  return null
}

async function saveCaPrivateKey (pem, keyPath) {
  await secretStore.setSecret(CA_ACCOUNT, pem)
  // 供仍读文件的旧逻辑使用时，可继续写 pem；安全起见只写 marker
  if (keyPath) {
    try {
      fs.writeFileSync(keyPath, pem, { encoding: "utf8", mode: 0o600 })
    } catch {
      // ignore
    }
  }
  return true
}

module.exports = {
  CA_ACCOUNT,
  ensureCaPrivateKey,
  saveCaPrivateKey,
}

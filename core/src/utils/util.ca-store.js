/**
 * CA 文件兜底。
 *
 * 背景：CA 私钥一旦被清理（例如「密钥迁移」把它收进系统密钥库后删掉了明文文件），
 * `tlsUtils.initCA()` 会认为证书不存在，直接**换发一张新的 CA**。
 * 新 CA 和用户已安装的根证书不是同一个，代理签出的证书立刻全部失效，
 * 浏览器就表现为「证书有问题」。
 *
 * 所以在启动代理之前，先把缺失的 CA 文件从系统密钥库恢复出来，保持 CA 身份不变。
 */
const fs = require('node:fs')
const path = require('node:path')
const defaultStore = require('./util.secret-store')
const log = require('./util.log.core')
const { writeFilePrivate } = require('./util.fs-private')

const ACCOUNT_CA_KEY = 'system-ca-private-key'
const ACCOUNT_CA_CERT = 'system-ca-cert'

/**
 * @param {{ certPath: string, keyPath: string, store?: object }} options
 * @returns {Promise<{ restored: boolean, items: string[] }>} 是否发生了恢复，以及恢复了哪几项
 */
async function ensureCaFiles ({ certPath, keyPath, store = defaultStore }) {
  const missing = []
  if (!fs.existsSync(certPath)) {
    missing.push('cert')
  }
  if (!fs.existsSync(keyPath)) {
    missing.push('key')
  }
  if (missing.length === 0) {
    return { restored: false, items: [] }
  }

  const items = []
  try {
    if (missing.includes('cert')) {
      const certPem = await store.getSecret(ACCOUNT_CA_CERT)
      if (certPem) {
        fs.mkdirSync(path.dirname(certPath), { recursive: true })
        writeFilePrivate(certPath, certPem)
        items.push('cert')
      }
    }
    if (missing.includes('key')) {
      const keyPem = await store.getSecret(ACCOUNT_CA_KEY)
      if (keyPem) {
        fs.mkdirSync(path.dirname(keyPath), { recursive: true })
        writeFilePrivate(keyPath, keyPem)
        items.push('key')
      }
    }
  } catch (e) {
    log.warn('从系统密钥库恢复 CA 文件失败:', e)
  }

  if (items.length > 0) {
    log.info('已从系统密钥库恢复 CA 文件，沿用原 CA 身份:', items.join(','))
  }
  return { restored: items.length > 0, items }
}

module.exports = {
  ACCOUNT_CA_CERT,
  ACCOUNT_CA_KEY,
  ensureCaFiles,
}

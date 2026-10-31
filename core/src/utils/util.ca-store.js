/**
 * CA 准备：保持 CA 身份稳定，同时不让私钥明文落盘。
 *
 * 背景：CA 私钥一旦被清理（「密钥迁移」把它收进系统密钥库后删掉了明文文件），
 * `tlsUtils.initCA()` 会认为证书不存在，直接**换发一张新的 CA**；
 * 新 CA 和用户已安装的根证书不是同一个，代理签出的证书立刻全部失效。
 *
 * 做法：
 *   - 证书是公开的，缺失时从密钥库恢复到磁盘（用户还要拿它装根证书）；
 *   - 私钥只留在密钥库里，通过环境变量 `DS_CA_KEY_PEM` 交给代理子进程，
 *     磁盘上遗留的同名明文（内容与密钥库一致）会被删掉。
 */
const fs = require('node:fs')
const path = require('node:path')
const defaultStore = require('./util.secret-store')
const log = require('./util.log.core')
const { writeFilePrivate } = require('./util.fs-private')

const ACCOUNT_CA_KEY = 'system-ca-private-key'
const ACCOUNT_CA_CERT = 'system-ca-cert'
// 代理子进程读取 CA 私钥的环境变量
const CA_KEY_ENV = 'DS_CA_KEY_PEM'

/**
 * @param {{ certPath: string, keyPath: string, store?: object }} options
 * @returns {Promise<{ keyPem: string | null, restoredCert: boolean, removedPlaintext: boolean }>}
 *   keyPem 非空时由调用方注入子进程环境；restoredCert 表示证书是否从密钥库补回；
 *   removedPlaintext 表示是否删掉了与密钥库一致的明文私钥文件
 */
async function prepareCa ({ certPath, keyPath, store = defaultStore }) {
  let keyPem = null
  let restoredCert = false
  let removedPlaintext = false

  try {
    if (!fs.existsSync(certPath)) {
      const certPem = await store.getSecret(ACCOUNT_CA_CERT)
      if (certPem) {
        fs.mkdirSync(path.dirname(certPath), { recursive: true })
        writeFilePrivate(certPath, certPem)
        restoredCert = true
        log.info('已从系统密钥库恢复 CA 证书文件')
      }
    }

    const storedKey = await store.getSecret(ACCOUNT_CA_KEY)
    if (storedKey) {
      const fileKey = fs.existsSync(keyPath) ? fs.readFileSync(keyPath, 'utf8') : null
      if (fileKey == null) {
        // 明文已删：直接用密钥库里的私钥
        keyPem = storedKey
      } else if (fileKey.trim() === String(storedKey).trim()) {
        // 同一张 CA 的明文备份：删掉，避免私钥留在磁盘上
        try {
          fs.unlinkSync(keyPath)
          removedPlaintext = true
          log.info('已删除 CA 私钥明文，改用系统密钥库中的副本')
        } catch (e) {
          log.warn('删除 CA 私钥明文失败（继续用密钥库副本）:', e)
        }
        keyPem = storedKey
      } else {
        // 磁盘上与密钥库里不是同一张 CA：保持现状，交给 initCA 判断，避免误换 CA
        log.warn('磁盘上的 CA 私钥与系统密钥库中的不一致，本次沿用磁盘文件')
      }
    }
  } catch (e) {
    log.warn('准备 CA 文件失败（将回落到磁盘文件）:', e)
  }

  return { keyPem, restoredCert, removedPlaintext }
}

module.exports = {
  ACCOUNT_CA_CERT,
  ACCOUNT_CA_KEY,
  CA_KEY_ENV,
  prepareCa,
}

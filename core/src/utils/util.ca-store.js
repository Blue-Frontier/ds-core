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
const { createCaPems } = require('@blue-frontier/mitmproxy/src/lib/proxy/tls/ca-cert')
const { caName } = require('@blue-frontier/mitmproxy/src/lib/proxy/common/config')

const ACCOUNT_CA_KEY = 'system-ca-private-key'
const ACCOUNT_CA_CERT = 'system-ca-cert'
// 代理子进程读取 CA 私钥的环境变量
const CA_KEY_ENV = 'DS_CA_KEY_PEM'
// 正在进行的 ensureCaFiles 任务（按证书路径去重）
const ensureTasks = new Map()

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

/**
 * 保证 CA 文件可用（界面「安装证书」在代理启动之前调用，不必等代理跑起来）。
 *
 * 取舍顺序是「优先保住用户已安装的那张根证书」：
 *   - 证书与私钥都在：什么都不做；
 *   - 缺的那一半在系统密钥库里有：恢复，不换发；
 *   - 磁盘和密钥库都没有 CA：生成一张新的，私钥只进密钥库，证书落盘供安装；
 *   - 证书在、私钥彻底丢了：报错，不静默换发（换发会让已安装的根证书立刻失效）。
 *
 * @returns {Promise<{ created: boolean, restored: boolean, certPath: string, keyPath: string }>} created 表示新生成了 CA，restored 表示从密钥库补回了证书
 */
async function ensureCaFiles (options) {
  // 并发调用（比如界面连点两下）必须共用同一次生成：两次 RSA 生成会得到两张 CA，
  // 而磁盘上的证书和密钥库里的私钥一旦来自不同次生成，代理签出的证书就会全部失效
  const running = ensureTasks.get(options.certPath)
  if (running) {
    return running
  }
  const task = doEnsureCaFiles(options).finally(() => {
    ensureTasks.delete(options.certPath)
  })
  ensureTasks.set(options.certPath, task)
  return task
}

async function doEnsureCaFiles ({ certPath, keyPath, store = defaultStore }) {
  const prep = await prepareCa({ certPath, keyPath, store })
  const keyFileExists = fs.existsSync(keyPath)
  const keyPem = prep.keyPem || (keyFileExists ? fs.readFileSync(keyPath, 'utf8') : null)

  if (fs.existsSync(certPath)) {
    if (!keyPem) {
      throw new Error('根证书私钥丢失（磁盘和系统密钥库都没有），无法继续使用现有根证书；请重新生成 CA 并重新安装根证书')
    }
    return {
      created: false,
      restored: prep.restoredCert,
      certPath,
      keyPath,
    }
  }

  // 证书与私钥都没有：首次使用，生成一张新 CA
  const pems = createCaPems(caName)
  writeFilePrivate(certPath, pems.certPem)

  let stored = false
  try {
    await store.setSecret(ACCOUNT_CA_CERT, pems.certPem)
    await store.setSecret(ACCOUNT_CA_KEY, pems.keyPem)
    stored = true
  } catch (e) {
    log.warn('CA 写入系统密钥库失败，改为写入磁盘私钥文件:', e)
  }
  if (!stored) {
    writeFilePrivate(keyPath, pems.keyPem)
  }

  log.info('已生成新的根证书:', certPath, stored ? '（私钥只保存在系统密钥库）' : '（私钥写入磁盘）')
  return {
    created: true,
    restored: false,
    certPath,
    keyPath,
  }
}

module.exports = {
  ACCOUNT_CA_CERT,
  ACCOUNT_CA_KEY,
  CA_KEY_ENV,
  prepareCa,
  ensureCaFiles,
}

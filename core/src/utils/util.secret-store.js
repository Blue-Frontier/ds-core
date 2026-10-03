/**
 * SecretStore：OS 密钥库（keytar）优先，不可用时回退到口令加密文件。
 *
 * keytar: service = 'dev-sidecar', account = <name>
 * 文件回退: ~/.dev-sidecar/secrets/<name>.json
 *   { v, kdf: 'scrypt', salt, iv, ct }  ct = AES-256-GCM(secret)
 *
 * 口令来源（文件回退时）：
 *   1) process.env.DS_SECRET_PASSWORD
 *   2) ~/.dev-sidecar/.secret-pass（0600；不存在则生成随机口令）
 */
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')
const crypto = require('node:crypto')

const SERVICE = 'dev-sidecar'

function userBase () {
  const home = process.env.USERPROFILE || process.env.HOME || os.homedir()
  return path.resolve(home, './.dev-sidecar')
}

function secretsDir () {
  return path.join(userBase(), 'secrets')
}

function passphraseFile () {
  return path.join(userBase(), '.secret-pass')
}

function loadKeytar () {
  try {
    return require('keytar')
  } catch {
    return null
  }
}

function loadOrCreatePassphrase () {
  if (process.env.DS_SECRET_PASSWORD) {
    return process.env.DS_SECRET_PASSWORD
  }
  const file = passphraseFile()
  if (fs.existsSync(file)) {
    return fs.readFileSync(file, 'utf8').trim()
  }
  const pass = crypto.randomBytes(24).toString('base64url')
  fs.mkdirSync(userBase(), { recursive: true })
  fs.writeFileSync(file, `${pass}\n`, { encoding: 'utf8', mode: 0o600 })
  return pass
}

function encryptWithPass (plaintext, pass) {
  const salt = crypto.randomBytes(16)
  const iv = crypto.randomBytes(12)
  const key = crypto.scryptSync(pass, salt, 32, { N: 16384, r: 8, p: 1 })
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()])
  const tag = cipher.getAuthTag()
  return {
    v: 1,
    kdf: 'scrypt',
    salt: salt.toString('base64url'),
    iv: iv.toString('base64url'),
    tag: tag.toString('base64url'),
    ct: ct.toString('base64url'),
  }
}

function decryptWithPass (record, pass) {
  const salt = Buffer.from(record.salt, 'base64url')
  const iv = Buffer.from(record.iv, 'base64url')
  const tag = Buffer.from(record.tag, 'base64url')
  const ct = Buffer.from(record.ct, 'base64url')
  const key = crypto.scryptSync(pass, salt, 32, { N: 16384, r: 8, p: 1 })
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')
}

function filePathFor (name) {
  return path.join(secretsDir(), `${name}.json`)
}

const secretStore = {
  /** 'keytar' | 'file-aes' */
  backend: null,

  detectBackend () {
    if (this.backend) {
      return this.backend
    }
    this.backend = loadKeytar() ? 'keytar' : 'file-aes'
    return this.backend
  },

  async setSecret (name, value) {
    const backend = this.detectBackend()
    if (backend === 'keytar') {
      const keytar = loadKeytar()
      await keytar.setPassword(SERVICE, name, value)
      return { backend }
    }
    const record = encryptWithPass(value, loadOrCreatePassphrase())
    fs.mkdirSync(secretsDir(), { recursive: true })
    fs.writeFileSync(filePathFor(name), `${JSON.stringify(record, null, 2)}\n`, 'utf8')
    return { backend }
  },

  async getSecret (name) {
    const backend = this.detectBackend()
    if (backend === 'keytar') {
      const keytar = loadKeytar()
      return keytar.getPassword(SERVICE, name)
    }
    const file = filePathFor(name)
    if (!fs.existsSync(file)) {
      return null
    }
    const record = JSON.parse(fs.readFileSync(file, 'utf8'))
    return decryptWithPass(record, loadOrCreatePassphrase())
  },

  async deleteSecret (name) {
    const backend = this.detectBackend()
    if (backend === 'keytar') {
      const keytar = loadKeytar()
      return keytar.deletePassword(SERVICE, name)
    }
    const file = filePathFor(name)
    if (fs.existsSync(file)) {
      fs.unlinkSync(file)
      return true
    }
    return false
  },

  async hasSecret (name) {
    const v = await this.getSecret(name)
    return v != null && v !== ''
  },
}

module.exports = secretStore

/* global describe, it */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { ACCOUNT_CA_CERT, ACCOUNT_CA_KEY, prepareCa, ensureCaFiles } = require('../src/utils/util.ca-store.js')

function tmpDir () {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ds-ca-test-'))
}

function fakeStore (data = {}) {
  return {
    async getSecret (name) {
      return data[name] || null
    },
    async setSecret (name, value) {
      data[name] = value
    },
    async deleteSecret (name) {
      delete data[name]
    },
    async hasSecret (name) {
      return !!data[name]
    },
  }
}

function paths () {
  const dir = tmpDir()
  return {
    dir,
    certPath: path.join(dir, 'dev-sidecar.ca.crt'),
    keyPath: path.join(dir, 'dev-sidecar.ca.key.pem'),
  }
}

describe('prepareCa', () => {
  it('hands the key to the caller without writing it to disk', async () => {
    const { certPath, keyPath } = paths()
    const store = fakeStore({ [ACCOUNT_CA_CERT]: 'CERT-PEM', [ACCOUNT_CA_KEY]: 'KEY-PEM' })

    const ret = await prepareCa({ certPath, keyPath, store })
    assert.equal(ret.keyPem, 'KEY-PEM')
    assert.equal(ret.restoredCert, true)
    assert.equal(fs.readFileSync(certPath, 'utf8'), 'CERT-PEM', '证书是公开的，缺失时恢复')
    assert.equal(fs.existsSync(keyPath), false, '私钥不得写回磁盘')
  })

  it('removes a leftover plaintext key that matches the keychain copy', async () => {
    const { certPath, keyPath } = paths()
    fs.writeFileSync(certPath, 'CERT-PEM')
    fs.writeFileSync(keyPath, 'KEY-PEM\n')
    const store = fakeStore({ [ACCOUNT_CA_CERT]: 'CERT-PEM', [ACCOUNT_CA_KEY]: 'KEY-PEM' })

    const ret = await prepareCa({ certPath, keyPath, store })
    assert.equal(ret.keyPem, 'KEY-PEM')
    assert.equal(ret.removedPlaintext, true)
    assert.equal(fs.existsSync(keyPath), false)
  })

  it('keeps the disk key when it is a different CA than the keychain copy', async () => {
    const { certPath, keyPath } = paths()
    fs.writeFileSync(certPath, 'CERT-PEM')
    fs.writeFileSync(keyPath, 'OTHER-KEY')
    const store = fakeStore({ [ACCOUNT_CA_CERT]: 'CERT-PEM', [ACCOUNT_CA_KEY]: 'KEY-PEM' })

    const ret = await prepareCa({ certPath, keyPath, store })
    assert.equal(ret.keyPem, null, '不注入环境变量，沿用磁盘上的 CA')
    assert.equal(fs.readFileSync(keyPath, 'utf8'), 'OTHER-KEY')
  })

  it('does nothing when the keychain has no CA key', async () => {
    const { certPath, keyPath } = paths()

    const ret = await prepareCa({ certPath, keyPath, store: fakeStore() })
    assert.equal(ret.keyPem, null)
    assert.equal(ret.restoredCert, false)
    assert.equal(fs.existsSync(keyPath), false)
  })
})

describe('ensureCaFiles', () => {
  it('generates a CA on first use, keeping the private key out of the disk', async () => {
    const { certPath, keyPath } = paths()
    const data = {}
    const store = fakeStore(data)

    const ret = await ensureCaFiles({ certPath, keyPath, store })
    assert.equal(ret.created, true)
    assert.equal(ret.certPath, certPath)

    const certPem = fs.readFileSync(certPath, 'utf8')
    assert.match(certPem, /^-----BEGIN CERTIFICATE-----/, '证书要落盘供用户安装')
    assert.doesNotMatch(certPem, /PRIVATE KEY/, '证书文件里不能混进私钥')
    assert.equal(fs.existsSync(keyPath), false, '私钥只进系统密钥库，不落盘')
    assert.equal(data[ACCOUNT_CA_CERT], certPem)
    assert.match(data[ACCOUNT_CA_KEY], /^-----BEGIN RSA PRIVATE KEY-----/)

    // 幂等：再调一次不换发
    const again = await ensureCaFiles({ certPath, keyPath, store })
    assert.equal(again.created, false)
    assert.equal(fs.readFileSync(certPath, 'utf8'), certPem)
  })

  it('restores the same CA from the keychain instead of rotating it', async () => {
    const { certPath, keyPath } = paths()
    const store = fakeStore({ [ACCOUNT_CA_CERT]: 'CERT-PEM', [ACCOUNT_CA_KEY]: 'KEY-PEM' })

    const ret = await ensureCaFiles({ certPath, keyPath, store })
    assert.equal(ret.created, false)
    assert.equal(ret.restored, true)
    assert.equal(fs.readFileSync(certPath, 'utf8'), 'CERT-PEM')
    assert.equal(fs.existsSync(keyPath), false)
    assert.equal(await store.getSecret(ACCOUNT_CA_CERT), 'CERT-PEM', '密钥库里的证书不能被换掉')
    assert.equal(await store.getSecret(ACCOUNT_CA_KEY), 'KEY-PEM', '密钥库里的私钥不能被换掉')
  })

  it('leaves an existing CA untouched', async () => {
    const { certPath, keyPath } = paths()
    fs.writeFileSync(certPath, 'CERT-PEM')
    fs.writeFileSync(keyPath, 'KEY-PEM')
    const store = fakeStore()

    const ret = await ensureCaFiles({ certPath, keyPath, store })
    assert.equal(ret.created, false)
    assert.equal(fs.readFileSync(certPath, 'utf8'), 'CERT-PEM')
    assert.equal(fs.readFileSync(keyPath, 'utf8'), 'KEY-PEM')
  })

  it('refuses to rotate when the certificate exists but its key is gone', async () => {
    const { certPath, keyPath } = paths()
    fs.writeFileSync(certPath, 'CERT-PEM')
    const store = fakeStore()

    await assert.rejects(
      () => ensureCaFiles({ certPath, keyPath, store }),
      /根证书私钥丢失/,
      '私钥丢了也不能换发，否则已安装的根证书会立刻失效',
    )
    assert.equal(fs.readFileSync(certPath, 'utf8'), 'CERT-PEM', '不能动现有证书')
  })

  it('shares one generation between concurrent calls', async () => {
    const { certPath, keyPath } = paths()
    const data = {}
    const store = fakeStore(data)

    const [a, b] = await Promise.all([
      ensureCaFiles({ certPath, keyPath, store }),
      ensureCaFiles({ certPath, keyPath, store }),
    ])
    assert.equal(a, b, '并发调用应共用同一个任务，否则会生成两张 CA')
    assert.equal(fs.readFileSync(certPath, 'utf8'), data[ACCOUNT_CA_CERT], '磁盘证书与密钥库必须同源')
  })
})

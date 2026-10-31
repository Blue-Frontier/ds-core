/* global describe, it */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { ACCOUNT_CA_CERT, ACCOUNT_CA_KEY, prepareCa } = require('../src/utils/util.ca-store.js')

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

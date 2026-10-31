/* global describe, it */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { ACCOUNT_CA_CERT, ACCOUNT_CA_KEY, ensureCaFiles } = require('../src/utils/util.ca-store.js')

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

describe('ensureCaFiles', () => {
  it('restores missing CA files from the secret store', async () => {
    const dir = tmpDir()
    const certPath = path.join(dir, 'dev-sidecar.ca.crt')
    const keyPath = path.join(dir, 'dev-sidecar.ca.key.pem')
    const store = fakeStore({ [ACCOUNT_CA_CERT]: 'CERT-PEM', [ACCOUNT_CA_KEY]: 'KEY-PEM' })

    const ret = await ensureCaFiles({ certPath, keyPath, store })
    assert.equal(ret.restored, true)
    assert.deepEqual(ret.items.sort(), ['cert', 'key'])
    assert.equal(fs.readFileSync(certPath, 'utf8'), 'CERT-PEM')
    assert.equal(fs.readFileSync(keyPath, 'utf8'), 'KEY-PEM')
  })

  it('keeps existing files untouched', async () => {
    const dir = tmpDir()
    const certPath = path.join(dir, 'dev-sidecar.ca.crt')
    const keyPath = path.join(dir, 'dev-sidecar.ca.key.pem')
    fs.writeFileSync(certPath, 'LOCAL-CERT')
    fs.writeFileSync(keyPath, 'LOCAL-KEY')
    const store = fakeStore({ [ACCOUNT_CA_CERT]: 'OTHER', [ACCOUNT_CA_KEY]: 'OTHER' })

    const ret = await ensureCaFiles({ certPath, keyPath, store })
    assert.equal(ret.restored, false)
    assert.equal(fs.readFileSync(certPath, 'utf8'), 'LOCAL-CERT')
    assert.equal(fs.readFileSync(keyPath, 'utf8'), 'LOCAL-KEY')
  })

  it('does nothing when the secret store has no CA', async () => {
    const dir = tmpDir()
    const certPath = path.join(dir, 'dev-sidecar.ca.crt')
    const keyPath = path.join(dir, 'dev-sidecar.ca.key.pem')

    const ret = await ensureCaFiles({ certPath, keyPath, store: fakeStore() })
    assert.equal(ret.restored, false)
    assert.equal(fs.existsSync(certPath), false)
    assert.equal(fs.existsSync(keyPath), false)
  })
})

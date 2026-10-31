const fs = require('node:fs')
const forge = require('node-forge')
const log = require('../../../utils/util.log.server')
const FakeServersCenter = require('../tls/FakeServersCenter')

module.exports = function createFakeServerCenter ({
  maxLength,
  caCertPath,
  caKeyPath,
  requestHandler,
  upgradeHandler,
}) {
  let caCert
  let caKey
  // 私钥优先取系统密钥库注入的环境变量：磁盘上不保留明文
  const envKeyPem = process.env.DS_CA_KEY_PEM
  try {
    fs.accessSync(caCertPath, fs.F_OK)
    const caCertPem = fs.readFileSync(caCertPath)
    caCert = forge.pki.certificateFromPem(caCertPem)
    if (envKeyPem) {
      caKey = forge.pki.privateKeyFromPem(envKeyPem)
    } else {
      fs.accessSync(caKeyPath, fs.F_OK)
      caKey = forge.pki.privateKeyFromPem(fs.readFileSync(caKeyPath))
    }
  } catch (e) {
    log.error('Can not find `CA certificate` or `CA key`:', e)
    process.exit(1)
  }

  return new FakeServersCenter({
    caCert,
    caKey,
    maxLength,
    requestHandler,
    upgradeHandler,
  })
}

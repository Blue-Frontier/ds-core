/**
 * 根证书（CA）生成：代理子进程首次启动、以及界面「按需生成根证书」共用这套实现，
 * 避免两边各写一份导致证书属性漂移。
 *
 * 属性固定为：自签名、basicConstraints(cA)、keyUsage(keyCertSign)、SHA256。
 * 这张证书会被用户装进系统/浏览器信任库，所以任何改动都要同步提示重新安装根证书。
 */
const forge = require('node-forge')

const pki = forge.pki

function createCA (CN) {
  const keys = pki.rsa.generateKeyPair(2048)
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = `${Date.now()}`
  cert.validity.notBefore = new Date(Date.now() - (60 * 60 * 1000))
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 20)
  const attrs = [{
    name: 'commonName',
    value: CN,
  }, {
    name: 'countryName',
    value: 'CN',
  }, {
    shortName: 'ST',
    value: 'GuangDong',
  }, {
    name: 'localityName',
    value: 'ShenZhen',
  }, {
    name: 'organizationName',
    value: 'dev-sidecar',
  }, {
    shortName: 'OU',
    value: 'https://github.com/docmirror/dev-sidecar',
  }]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: true,
  }, {
    name: 'keyUsage',
    critical: true,
    keyCertSign: true,
  }, {
    name: 'subjectKeyIdentifier',
  }])

  // self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create())

  return {
    key: keys.privateKey,
    cert,
  }
}

/** 生成 CA 并直接给出 PEM 文本（调用方不需要依赖 node-forge） */
function createCaPems (CN) {
  const { cert, key } = createCA(CN)
  return {
    certPem: pki.certificateToPem(cert),
    keyPem: pki.privateKeyToPem(key),
  }
}

module.exports = {
  createCA,
  createCaPems,
}

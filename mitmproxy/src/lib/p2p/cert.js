/**
 * 节点间 TLS 用自签证书（境内 hop、无域名场景）。
 * 仅用于 ds-p2p 隧道，不对外充当「像真站」。
 */
const forge = require('node-forge')

/**
 * @returns {{key: string, cert: string}} PEM
 */
function generateSelfSignedCert (commonName = 'ds-p2p') {
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = `01${Date.now().toString(16)}`
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000)
  cert.validity.notAfter = new Date(Date.now() + 3 * 365 * 24 * 3600 * 1000)
  const attrs = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'ds-p2p' },
  ]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
  ])
  cert.sign(keys.privateKey, forge.md.sha256.create())
  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  }
}

module.exports = {
  generateSelfSignedCert,
}

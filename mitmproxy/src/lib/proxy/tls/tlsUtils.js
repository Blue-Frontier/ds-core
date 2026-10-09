const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const { promisify } = require('node:util')
const _ = require('lodash')
const forge = require('node-forge')
const log = require('../../../utils/util.log.server')
const config = require('../common/config')

const utils = exports
const pki = forge.pki

const _generateKeyPair = promisify(crypto.generateKeyPair)

/**
 * 使用 Node.js 原生 crypto 模块异步生成 RSA 密钥对（在 libuv 线程池中运行，不阻塞事件循环），
 * 并将结果转换为 node-forge 格式。
 */
async function generateForgeRsaKeyPair () {
  const { privateKey } = await _generateKeyPair('rsa', { modulusLength: 2048 })
  const privateKeyDer = privateKey.export({ type: 'pkcs1', format: 'der' })
  const forgePrivateKey = pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(privateKeyDer)))
  const forgePublicKey = pki.rsa.setPublicKey(forgePrivateKey.n, forgePrivateKey.e)
  return { privateKey: forgePrivateKey, publicKey: forgePublicKey }
}

// const os = require('os')
// let username = 'dev-sidecar'
// try {
//   const user = os.userInfo()
//   username = user.username
// } catch (e) {
//   log.info('get userinfo error', e)
// }

utils.createCA = function (CN) {
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

/**
 * 构造完整的 authorityKeyIdentifier（含签发者 SKI）。
 * 仅写 { name: 'authorityKeyIdentifier' } 会得到空 SEQUENCE (30 00)，
 * Python 3.13+ VERIFY_X509_STRICT / openssl -x509_strict 会报 Missing Authority Key Identifier。
 */
function getAuthorityKeyIdentifierExt (caCert) {
  let keyId = null
  try {
    if (caCert.generateSubjectKeyIdentifier) {
      const gen = caCert.generateSubjectKeyIdentifier()
      if (gen && typeof gen.getBytes === 'function') {
        keyId = gen.getBytes()
      }
    }
    if (!keyId) {
      const skiExt = caCert.getExtension && caCert.getExtension('subjectKeyIdentifier')
      if (skiExt && skiExt.subjectKeyIdentifier) {
        let ski = skiExt.subjectKeyIdentifier
        if (typeof ski === 'string' && /^[0-9a-f]+$/i.test(ski) && ski.length % 2 === 0) {
          // forge 扩展里可能是 hex 字符串，需转为二进制再进 DER
          ski = Buffer.from(ski, 'hex').toString('binary')
        } else if (ski && typeof ski.getBytes === 'function') {
          ski = ski.getBytes()
        }
        keyId = typeof ski === 'string' ? ski : null
      }
    }
  } catch {
    keyId = null
  }
  return {
    name: 'authorityKeyIdentifier',
    keyIdentifier: keyId || true,
  }
}

utils.covertNodeCertToForgeCert = function (originCertificate) {
  const obj = forge.asn1.fromDer(originCertificate.raw.toString('binary'))
  return forge.pki.certificateFromAsn1(obj)
}

utils.createFakeCertificateByDomain = async function (caKey, caCert, domain, mappingHostNames) {
  // 作用域名
  const altNames = []
  mappingHostNames.forEach((mappingHostName) => {
    altNames.push({
      type: 2, // 1=电子邮箱、2=DNS名称
      value: mappingHostName,
    })
  })

  const keys = await generateForgeRsaKeyPair()
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey

  cert.serialNumber = `${Date.now()}`
  cert.validity.notBefore = new Date()
  cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 1)
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1)
  const attrs = [{
    name: 'commonName',
    value: domain,
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

  cert.setIssuer(caCert.subject.attributes)
  cert.setSubject(attrs)

  // RFC 5280：AKI 必须带 keyIdentifier（签发者 SKI），否则 strict 客户端会拒
  // （Python 3.13+ VERIFY_X509_STRICT / openssl -x509_strict）
  const aki = getAuthorityKeyIdentifierExt(caCert)

  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: false,
  },
  // {
  //   name: 'keyUsage',
  //   critical: true,
  //   digitalSignature: true,
  //   contentCommitment: true,
  //   keyEncipherment: true,
  //   dataEncipherment: true,
  //   keyAgreement: true,
  //   keyCertSign: true,
  //   cRLSign: true,
  //   encipherOnly: true,
  //   decipherOnly: true
  // },
  {
    name: 'subjectAltName',
    altNames,
  }, {
    name: 'subjectKeyIdentifier',
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  }, aki])
  cert.sign(caKey, forge.md.sha256.create())

  return {
    key: keys.privateKey,
    cert,
  }
}

utils.createFakeCertificateByCA = async function (caKey, caCert, originCertificate) {
  const certificate = utils.covertNodeCertToForgeCert(originCertificate)

  const keys = await generateForgeRsaKeyPair()
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey

  cert.serialNumber = certificate.serialNumber
  cert.validity.notBefore = new Date()
  cert.validity.notBefore.setFullYear(cert.validity.notBefore.getFullYear() - 1)
  cert.validity.notAfter = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1)

  cert.setSubject(certificate.subject.attributes)
  cert.setIssuer(caCert.subject.attributes)

  certificate.subjectaltname && (cert.subjectaltname = certificate.subjectaltname)

  const subjectAltName = _.find(certificate.extensions, { name: 'subjectAltName' })
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: false,
  }, {
    name: 'keyUsage',
    critical: true,
    digitalSignature: true,
    contentCommitment: true,
    keyEncipherment: true,
    dataEncipherment: true,
    keyAgreement: true,
    keyCertSign: true,
    cRLSign: true,
    encipherOnly: true,
    decipherOnly: true,
  }, {
    name: 'subjectAltName',
    altNames: subjectAltName.altNames,
  }, {
    name: 'subjectKeyIdentifier',
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  }, getAuthorityKeyIdentifierExt(caCert)])
  cert.sign(caKey, forge.md.sha256.create())

  return {
    key: keys.privateKey,
    cert,
  }
}

utils.isBrowserRequest = function (userAgent) {
  return /Mozilla/i.test(userAgent)
}

//
//  /^[^.]+\.a\.com$/.test('c.a.com')
//
const mappingHostNameRegexpCache = {}
utils.isMappingHostName = function (DNSName, hostname) {
  if (DNSName === hostname) {
    return true
  }

  let regexp = mappingHostNameRegexpCache[DNSName]
  if (!regexp) {
    const regStr = `^${DNSName.replace(/\./g, '\\.').replace(/\*/g, '[^.]+')}$`
    regexp = mappingHostNameRegexpCache[DNSName] = new RegExp(regStr)
  }
  return regexp.test(hostname)
}

utils.getMappingHostNamesFromCert = function (cert) {
  let mappingHostNames = []
  mappingHostNames.push(cert.subject.getField('CN') ? cert.subject.getField('CN').value : '')
  const altNames = cert.getExtension('subjectAltName') ? cert.getExtension('subjectAltName').altNames : []
  mappingHostNames = mappingHostNames.concat(_.map(altNames, 'value'))
  return mappingHostNames
}

// sync
utils.initCA = function ({ caCertPath, caKeyPath }) {
  try {
    fs.accessSync(caCertPath, fs.F_OK)
    fs.accessSync(caKeyPath, fs.F_OK)

    // has exist
    return {
      caCertPath,
      caKeyPath,
      create: false,
    }
  } catch (e0) {
    log.info('证书文件不存在，重新生成:', e0)

    try {
      const caObj = utils.createCA(config.caName)

      const caCert = caObj.cert
      const cakey = caObj.key

      const certPem = pki.certificateToPem(caCert)
      const keyPem = pki.privateKeyToPem(cakey)
      fs.mkdirSync(path.dirname(caCertPath), { recursive: true })
      fs.writeFileSync(caCertPath, certPem)
      fs.writeFileSync(caKeyPath, keyPem)
      log.info('生成证书文件成功，共2个文件:', caCertPath, caKeyPath)
    } catch (e) {
      log.error('生成证书文件失败:', caCertPath, caKeyPath, ', error:', e)
      throw e
    }
  }
  return {
    caCertPath,
    caKeyPath,
    create: true,
  }
}

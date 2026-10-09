// 回归测试：issue #712 —— 动态签发的叶子证书必须带非空 authorityKeyIdentifier
//
// 背景：仅写 { name: 'authorityKeyIdentifier' } 会让 node-forge 生成空 SEQUENCE（DER 30 00），
// 违反 RFC 5280 §4.2.1.1（keyIdentifier 必须存在）。开启严格校验的客户端会直接拒绝该证书：
//   - Python 3.13+ ssl.create_default_context() 默认启用 VERIFY_X509_STRICT
//     → CERTIFICATE_VERIFY_FAILED: Missing Authority Key Identifier
//   - openssl verify -x509_strict → error 85 at 0 depth lookup
// 受影响的是所有走本代理的 Python 程序（requests / pip / urllib 等）。
//
// 修复在 ../src/lib/proxy/tls/tlsUtils.js 的 getAuthorityKeyIdentifierExt()：
// 从签发 CA 派生 SKI 并填入 keyIdentifier。本测试锁死该行为，避免回归。
/* eslint-disable no-undef -- describe/it/before 来自 mocha 运行器，eslint 未配置 mocha 全局变量 */
const assert = require('node:assert')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execFileSync } = require('node:child_process')
const forge = require('node-forge')
const tlsUtils = require('../src/lib/proxy/tls/tlsUtils')

const CA_NAME = 'DevSidecar - This certificate is generated locally'

// AKI 的正确性分三层校验：不是空 SEQUENCE、含 keyIdentifier 项、字节等于签发 CA 的 SKI
function assertAkiMatchesCa (leafCert, caCert, label) {
  const ext = leafCert.getExtension('authorityKeyIdentifier')
  assert.ok(ext, `${label}: 叶子证书缺少 authorityKeyIdentifier 扩展`)

  // 1) 字节级：#712 的症状就是 AKI 为 30 00（空 SEQUENCE）
  const akiDerHex = Buffer.from(forge.asn1.toDer(ext.value).getBytes(), 'binary').toString('hex')
  assert.notStrictEqual(akiDerHex, '3000', `${label}: AKI 是空 SEQUENCE（#712 回归）`)

  // 2) 结构级：SEQUENCE 内必须有 KeyIdentifier，且为 context-specific [0]
  assert.strictEqual(ext.value.value.length, 1, `${label}: AKI 内应含且仅含 keyIdentifier 项`)
  assert.strictEqual(ext.value.value[0].tagClass, 128, `${label}: keyIdentifier 应为 context-specific [0]`)

  // 3) 语义级：keyIdentifier 必须等于签发 CA 的 subjectKeyIdentifier（SHA-1，20 字节）
  const akiKeyId = Buffer.from(ext.keyIdentifier, 'binary')
  const caSki = Buffer.from(caCert.generateSubjectKeyIdentifier().getBytes(), 'binary')
  assert.strictEqual(akiKeyId.length, 20, `${label}: keyIdentifier 应为 20 字节 SHA-1`)
  assert.strictEqual(akiKeyId.toString('hex'), caSki.toString('hex'), `${label}: AKI 与 CA 的 SKI 不一致`)

  return akiKeyId
}

// 用 issue #712 给出的 openssl 命令交叉验证。
// 只针对 AKI 相关错误断言，避免因其他严格项（如叶子证书缺 keyUsage）产生与环境相关的假失败。
function verifyWithOpensslStrict (caCert, leafCert) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ds-aki-test-'))
  try {
    const caPath = path.join(dir, 'ca.crt')
    const leafPath = path.join(dir, 'leaf.pem')
    fs.writeFileSync(caPath, forge.pki.certificateToPem(caCert))
    fs.writeFileSync(leafPath, forge.pki.certificateToPem(leafCert))

    let output = ''
    try {
      execFileSync('openssl', ['verify', '-x509_strict', '-CAfile', caPath, leafPath], { stdio: 'pipe' })
      return { skipped: false, strictOk: true, output: '' }
    } catch (e) {
      if (e.code === 'ENOENT') {
        return { skipped: true, strictOk: false, output: '' }
      }
      output = `${e.stdout || ''}${e.stderr || ''}`
    }
    return { skipped: false, strictOk: false, output: output.trim() }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
}

describe('tlsUtils 动态签发叶子证书的 authorityKeyIdentifier（issue #712）', function () {
  // CA 与叶子证书均为 RSA-2048，生成耗时较长，放宽 mocha 默认 2s 超时
  this.timeout(60000)

  let caCert
  let caKey

  before(() => {
    const caObj = tlsUtils.createCA(CA_NAME)
    caCert = caObj.cert
    caKey = caObj.key
  })

  it('CA 应能派生 subjectKeyIdentifier（AKI 的来源）', () => {
    assert.strictEqual(typeof caCert.generateSubjectKeyIdentifier, 'function', 'CA 证书应能派生 subjectKeyIdentifier')
  })

  it('createFakeCertificateByDomain 签发的叶子证书 AKI 合规', async () => {
    const leaf = await tlsUtils.createFakeCertificateByDomain(
      caKey,
      caCert,
      'github.com',
      ['github.com', '*.github.com'],
    )
    const akiKeyId = assertAkiMatchesCa(leaf.cert, caCert, 'createFakeCertificateByDomain')
    console.log('叶子 AKI  :', akiKeyId.toString('hex'))
  })

  it('createFakeCertificateByCA 签发的叶子证书 AKI 合规', async () => {
    // 该路径以源站证书为模板，需一份带 subjectAltName 的“源站证书”，
    // 这里用上一路径生成的叶子证书充当，只取其 raw DER
    const origin = await tlsUtils.createFakeCertificateByDomain(
      caKey,
      caCert,
      'github.com',
      ['github.com', '*.github.com'],
    )
    const originRaw = Buffer.from(
      forge.asn1.toDer(forge.pki.certificateToAsn1(origin.cert)).getBytes(),
      'binary',
    )
    const leaf = await tlsUtils.createFakeCertificateByCA(caKey, caCert, { raw: originRaw })
    const akiKeyId = assertAkiMatchesCa(leaf.cert, caCert, 'createFakeCertificateByCA')
    console.log('叶子 AKI(按源站证书签发):', akiKeyId.toString('hex'))
  })

  it('openssl verify -x509_strict 不报 AKI 相关错误', async () => {
    const leaf = await tlsUtils.createFakeCertificateByDomain(
      caKey,
      caCert,
      'github.com',
      ['github.com', '*.github.com'],
    )
    const result = verifyWithOpensslStrict(caCert, leaf.cert)

    if (result.skipped) {
      console.log('未找到 openssl，跳过 -x509_strict 外部校验')
      return
    }
    if (result.strictOk) {
      console.log('openssl verify -x509_strict: OK')
      return
    }

    assert.ok(!/Missing Authority Key Identifier/i.test(result.output), `openssl -x509_strict 报 AKI 缺失（#712 回归）: ${result.output}`)
    assert.ok(!/error 85 at 0 depth/.test(result.output), `openssl -x509_strict 报 error 85（#712 回归）: ${result.output}`)
    // 其余严格项未通过不视为 AKI 回归，仅提示（叶子证书目前未带 keyUsage）
    console.log(`openssl verify -x509_strict 未完全通过（非 AKI 原因）: ${result.output}`)
  })
})

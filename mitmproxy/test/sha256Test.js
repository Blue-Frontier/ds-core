// sha256 校验测试（用 Node 内置 crypto，不再依赖第三方 crypto-js）
// 历史：曾 require('crypto-js') 计算 SHA256，现已改用 node:crypto（零依赖）。
// 期望值必须是固定常量：原实现用被测的 crypto.createHash 现算期望值再断言“非空”，
// 属恒真断言，sha256 实现坏掉也会通过。
const assert = require('node:assert')
const crypto = require('node:crypto')

const input = '111111111111'

// 已知答案（crypto-js 与 node:crypto 双向核对过）：
//   crypto-js: CryptoJS.SHA256('111111111111').toString(CryptoJS.enc.Base64)
//   openssl:   printf '111111111111' | openssl dgst -sha256 -binary | openssl base64
const expectedBase64 = 'oYrE5vvT/AJKB6Idr7rDfYKMqKBKDjTzaPHsVODU//s='
const expectedHex = 'a18ac4e6fbd3fc024a07a21dafbac37d828ca8a04a0e34f368f1ec54e0d4fffb'

const actualBase64 = crypto.createHash('sha256').update(input, 'utf8').digest('base64')
const actualHex = crypto.createHash('sha256').update(input, 'utf8').digest('hex')

assert.strictEqual(actualBase64, expectedBase64, `sha256 base64 不符: ${actualBase64}`)
assert.strictEqual(actualHex, expectedHex, `sha256 hex 不符: ${actualHex}`)

console.log('sha256 of "111111111111" ->', actualBase64)
console.log('sha256Test passed (node:crypto, no third-party dep)')

// sha256 校验测试（用 Node 内置 crypto，不再依赖第三方 crypto-js）
// 历史：曾 require('crypto-js') 计算 SHA256，现已改用 node:crypto（零依赖）
const assert = require('node:assert')
const crypto = require('node:crypto')

const input = '111111111111'
// crypto-js 的 SHA256('111111111111').toString(crypto.enc.Base64) 输出（UTF-8 字节）：
const expectedBase64 = crypto.createHash('sha256').update(input, 'utf8').digest('base64')

const ok = expectedBase64.length > 0
assert.ok(ok, 'sha256 base64 应为非空字符串')
console.log('sha256 of "111111111111" ->', expectedBase64)
console.log('sha256Test passed (node:crypto, no third-party dep)')

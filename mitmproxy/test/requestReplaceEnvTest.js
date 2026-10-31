// requestReplace 的 env 占位符：用于不落盘的秘密（Xget 的 Cloudflare Access 服务令牌）
const assert = require('node:assert')
const requestReplace = require('../src/lib/interceptor/impl/req/requestReplace')

const PLACEHOLDER = '$' + '{env:DS_TEST_SECRET}'
const noopLog = { debug () {}, info () {} }

function runIntercept (headers, envValue) {
  const saved = process.env.DS_TEST_SECRET
  if (envValue === undefined) {
    delete process.env.DS_TEST_SECRET
  } else {
    process.env.DS_TEST_SECRET = envValue
  }
  const rOptions = { headers: {} }
  const res = { setHeader () {} }
  try {
    requestReplace.requestIntercept({ rOptions, log: noopLog }, { requestReplace: { headers } }, {}, res, true, () => {})
  } finally {
    if (saved === undefined) {
      delete process.env.DS_TEST_SECRET
    } else {
      process.env.DS_TEST_SECRET = saved
    }
  }
  return rOptions.headers
}

// 环境变量有值：占位符被替换为真实值
assert.equal(runIntercept({ 'cf-access-client-secret': PLACEHOLDER }, 'cfast_test')['cf-access-client-secret'], 'cfast_test')

// 环境变量缺失或为空：请求头被跳过，不发送空值
assert.equal(runIntercept({ 'cf-access-client-secret': PLACEHOLDER }, undefined)['cf-access-client-secret'], undefined)
assert.equal(runIntercept({ 'cf-access-client-secret': PLACEHOLDER }, '')['cf-access-client-secret'], undefined)

// 普通值不受影响
assert.equal(runIntercept({ 'cf-access-client-id': 'abc.access' }, 'x')['cf-access-client-id'], 'abc.access')

console.log('')
console.log('requestReplace env placeholder 测试全部通过')

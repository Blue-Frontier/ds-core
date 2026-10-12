// upgradeHandler 行为测试：验证 SNI/verifyHost/DNS 优选 作用到升级路径
const assert = require('node:assert')
const createUpgradeHandler = require('../src/lib/proxy/mitmproxy/createUpgradeHandler')
const util = require('../src/lib/proxy/common/util')
const https = require('node:https')
const http = require('node:http')

// 捕获 https.request / http.request 被调用时的 options（不发真请求）
function captureRequest () {
  const captured = { httpsOpts: null, httpOpts: null, fake: null }
  const origHttps = https.request
  const origHttp = http.request
  const makeFake = (opts) => {
    const { EventEmitter } = require('node:events')
    const fake = new EventEmitter()
    fake.end = () => {}
    fake.destroy = (e) => { fake.emit('error', e || new Error('destroyed')) }
    return fake
  }
  https.request = (opts, cb) => {
    captured.httpsOpts = opts
    const fake = makeFake(opts)
    captured.fake = fake
    return fake
  }
  http.request = (opts, cb) => {
    captured.httpOpts = opts
    const fake = makeFake(opts)
    captured.fake = fake
    return fake
  }
  return {
    captured,
    restore () {
      https.request = origHttps
      http.request = origHttp
    },
  }
}

const settings = { verifySsl: true }

// 测 1: 默认路径（无拦截器）——handler 应补上 servername = hostname
;(function testDefaultSni () {
  const handler = createUpgradeHandler(settings, null, null, null)
  const fakeReq = {
    url: '/',
    method: 'GET',
    headers: { host: 'example.com:443', upgrade: 'websocket', connection: 'Upgrade', 'sec-websocket-key': 'x' },
    socket: {},
  }
  const { captured, restore } = captureRequest()
  const fakeSocket = { destroyed: false, end: () => {}, write: () => {} }
  handler(fakeReq, fakeSocket, null, true)
  restore()
  assert.ok(captured.httpsOpts, '走 https.request（ssl=true）')
  assert.strictEqual(captured.httpsOpts.servername, 'example.com', '默认 servername = hostname')
  assert.strictEqual(captured.httpsOpts.hostname, 'example.com')
  assert.strictEqual(captured.httpsOpts.checkServerIdentity, undefined, '默认路径 servername=verifyHost=hostname，不需要覆盖 checkServerIdentity')
  console.log('√ 默认路径：handler 补齐 servername = hostname')
})()

// 测 2: sni 拦截器把 servername 改写到 huggingface.cn，verifyHost 同步
;(function testSniInterceptor () {
  const fakeReq = {
    url: '/',
    method: 'GET',
    headers: { host: 'huggingface.co:443', upgrade: 'websocket', connection: 'Upgrade' },
    socket: {},
  }
  const createIntercepts = (context) => [
    {
      name: 'sni',
      priority: 123,
      requestIntercept (ctx, req, res, ssl, next) {
        // 模拟 sni.js 拦截器的行为
        ctx.rOptions.servername = 'huggingface.cn'
        ctx.rOptions.verifyHost = 'huggingface.cn'
        next()
        return true
      },
    },
  ]
  const handler = createUpgradeHandler(settings, null, null, createIntercepts)
  const { captured, restore } = captureRequest()
  const fakeSocket = { destroyed: false, end: () => {}, write: () => {} }
  handler(fakeReq, fakeSocket, null, true)
  restore()
  assert.ok(captured.httpsOpts, 'https.request 被调用')
  
  assert.strictEqual(captured.httpsOpts.servername, 'huggingface.cn', '拦截器改写了 servername')
  assert.strictEqual(captured.httpsOpts.verifyHost, 'huggingface.cn', '拦截器写入了 verifyHost')
  assert.strictEqual(typeof captured.httpsOpts.checkServerIdentity, 'function', 'verifyHost !== hostname 时设 checkServerIdentity')
  // checkServerIdentity 应接受 huggingface.cn 的证书
  // 闭包 checkServerIdentity = (_host, cert) => tls.checkServerIdentity(verifyHost, cert)
  // 它忽略 _host 参数，始终用 verifyHost（'huggingface.cn'）做校验。
  // 所以：CN=huggingface.cn 的证书 → 通过；CN=other.com 的证书 → 被拒绝（证明 verifyHost 生效）。
  const matchCert = {
    subject: { CN: 'huggingface.cn', C: 'CN' },
    valid_to: new Date(Date.now() + 3600 * 1000).toUTCString(),
  }
  assert.doesNotThrow(() => captured.httpsOpts.checkServerIdentity('whatever', matchCert), 'verifyHost 与证书 CN 一致时通过')
  // 证书 CN 与 verifyHost 不一致 → 拒绝（Node 不同版本：抛错或返回 truthy 结果对象）
  const mismatchCert = {
    subject: { CN: 'other.com', C: 'CN' },
    valid_to: new Date(Date.now() + 3600 * 1000).toUTCString(),
  }
  let rejected = false
  try {
    const r = captured.httpsOpts.checkServerIdentity('whatever', mismatchCert)
    rejected = !!r // 返回 truthy 结果对象 = 拒绝
  } catch (e) {
    rejected = true // 抛出 ERR_TLS_CERT_ALTNAME_INVALID = 拒绝
  }
  assert.ok(rejected, '证书 CN 与 verifyHost 不一致时应被拒绝（证明 verifyHost 生效）')
  console.log('√ sni 拦截器：servername/verifyHost 应用到升级路径')
})()

// 测 3: DNS 优选 lookup 挂到 clientOptions
;(function testDnsLookup () {
  const fakeReq = {
    url: '/',
    method: 'GET',
    headers: { host: 'github.com:443', upgrade: 'websocket', connection: 'Upgrade' },
    socket: {},
  }
  // 最小 dnsConfig：mapping 把 github.com 映射到某 DNS（此处不真正解析，只验证 handler 会挂 lookup）
  const dnsConfig = {
    dnsMap: {
      mapping: {},
      preSetIpList: {},
      whiteList: {},
      dns: { providers: {} },
    },
  }
  // 用 stub DnsUtil 替换，验证 getDNSAndFamily 被调用 + lookup 挂上
  const DnsUtil = require('../src/lib/dns')
  const origGet = DnsUtil.getDNSAndFamily
  let dnsCall = null
  DnsUtil.getDNSAndFamily = (cfg, host) => {
    dnsCall = host
    // 返回一个最小 dns 对象
    return {
      dns: {
        dnsName: 'test-dns',
        lookup: () => Promise.resolve('2606:50c0::1'),
      },
      family: 6,
    }
  }
  const { captured, restore } = captureRequest()
  const handler = createUpgradeHandler(settings, null, dnsConfig, null)
  const fakeSocket = { destroyed: false, end: () => {}, write: () => {} }
  handler(fakeReq, fakeSocket, null, true)
  restore()
  DnsUtil.getDNSAndFamily = origGet
  assert.strictEqual(dnsCall, 'github.com', 'getDNSAndFamily 被调用（传了 github.com）')
  assert.ok(captured.httpsOpts, 'https.request 被调用')
  assert.strictEqual(typeof captured.httpsOpts.lookup, 'function', 'clientOptions.lookup 被挂上')
  assert.strictEqual(captured.httpsOpts.family, 6, 'dnsAndFamily.family=6 传播到 clientOptions.family')
  console.log('√ DNS 优选：lookup 挂到升级路径 clientOptions')
})()

// 测 4: 升级失败时回 502 给客户端
;(function testUpgradeFailure502 () {
  const fakeReq = {
    url: '/',
    method: 'GET',
    headers: { host: 'fail.example.com:443', upgrade: 'websocket', connection: 'Upgrade' },
    socket: {},
  }
  const handler = createUpgradeHandler(settings, null, null, null)
  const { captured, restore } = captureRequest()
  let endPayload = null
  const fakeSocket = {
    destroyed: false,
    end: (p) => { endPayload = p },
    write: () => {},
  }
  handler(fakeReq, fakeSocket, null, true)
  // 模拟上游报错
  if (captured.fake) {
    captured.fake.emit('error', new Error('connect ECONNREFUSED'))
  }
  restore()
  assert.strictEqual(endPayload, 'HTTP/1.1 502 Bad Gateway\r\n\r\n', '升级失败时回 502 给客户端')
  console.log('√ 升级失败：502 兜底回给客户端')
})()

// 测 5: 上游回非 101（如 403）时透传状态+头
;(function testNon101Passthrough () {
  const fakeReq = {
    url: '/',
    method: 'GET',
    headers: { host: 'auth.example.com:443', upgrade: 'websocket', connection: 'Upgrade' },
    socket: {},
  }
  const handler = createUpgradeHandler(settings, null, null, null)
  const { captured, restore } = captureRequest()
  let written = null
  const fakeSocket = {
    destroyed: false,
    end: () => {},
    write: (p) => { written = p },
  }
  handler(fakeReq, fakeSocket, null, true)
  // 模拟上游返回 403（非 upgrade）
  const fakeRes = {
    statusCode: 403,
    statusMessage: 'Forbidden',
    upgrade: false,
    headers: { 'content-type': 'text/plain', 'www-authenticate': 'Basic realm="x"' },
    pipe: (target) => {},
  }
  if (captured.fake) {
    captured.fake.emit('response', fakeRes)
  }
  restore()
  assert.ok(written, '非 101 时向客户端写响应')
  assert.ok(written.includes('HTTP/1.1 403'), '透传了 403 状态行')
  assert.ok(written.includes('www-authenticate'), '透传了响应头')
  console.log('√ 非 101：状态行+响应头透传给客户端')
})()

console.log('')
console.log('upgradeHandler sni/verifyHost/dns/502/非101 行为测试全部通过')

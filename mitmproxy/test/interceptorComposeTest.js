// 拦截器组合性测试（#745）：
//  - sni / unVerifySsl 都只改 rOptions，必须能叠加执行（以前首个真值返回就让后面的拦截器全部跳过）
//  - 证书校验策略只由显式配置决定：sni 只改握手，不再隐式换免校验 agent
const assert = require('node:assert')
const sni = require('../src/lib/interceptor/impl/req/sni')
const unVerifySsl = require('../src/lib/interceptor/impl/req/unVerifySsl')
const proxy = require('../src/lib/interceptor/impl/req/proxy')
const { applyTlsVerifyPolicy } = require('../src/lib/proxy/mitmproxy/tlsVerify')

function createRes () {
  const headers = new Map()
  return {
    setHeader (name, value) {
      headers.set(name.toLowerCase(), value)
    },
    getHeader (name) {
      return headers.get(name.toLowerCase())
    },
    headers,
  }
}

function createContext (hostname, options = {}) {
  const { rejectUnauthorized = true } = options
  const unVerifySslAgent = { options: { rejectUnauthorized: false } }
  const agent = { options: { rejectUnauthorized }, unVerifySslAgent }
  const logs = []
  const log = {
    info: (...args) => logs.push(args.join(' ')),
    warn: (...args) => logs.push(args.join(' ')),
    error: (...args) => logs.push(args.join(' ')),
  }
  const rOptions = {
    protocol: 'https:',
    hostname,
    host: hostname,
    port: 443,
    path: '/',
    method: 'GET',
    headers: {},
    agent,
  }
  return { context: { rOptions, log }, rOptions, agent, unVerifySslAgent, logs }
}

// 与 createRequestHandler.requestInterceptorPromise 的循环保持一致（这些拦截器都是同步的）
function runChain (interceptors, context, res) {
  const next = () => {}
  for (const interceptor of interceptors) {
    const goNext = interceptor.requestIntercept(context, null, res, true, next)
    if (goNext) {
      if (goNext !== 'no-next') {
        next()
      }
      return
    }
  }
  next()
}

function wrap (impl, interceptOpt) {
  return {
    requestIntercept: (context, req, res, ssl, next) => impl.requestIntercept(context, interceptOpt, req, res, ssl, next),
  }
}

function certOf (cn) {
  return {
    subject: { CN: cn, C: 'CN' },
    valid_to: new Date(Date.now() + 3600 * 1000).toUTCString(),
  }
}

function isRejected (checkServerIdentity, cn) {
  try {
    return !!checkServerIdentity('ignored', certOf(cn))
  } catch {
    return true
  }
}

// 测 1: sni 只改 SNI，返回 undefined（链继续），不再把 agent 换成免校验的
;(function testSniIsNotTerminal () {
  const { context, rOptions, agent } = createContext('github.com')
  const res = createRes()
  const ret = sni.requestIntercept(context, { sni: 'baidu.com' }, null, res, true, () => {})
  assert.strictEqual(ret, undefined, 'sni 返回 undefined，让拦截器链继续')
  assert.strictEqual(rOptions.servername, 'baidu.com', 'servername 按规则改写')
  assert.strictEqual(rOptions.agent, agent, 'sni 不得顺手换免校验 agent')
  assert.ok(res.getHeader('DS-Interceptor').includes('sni: baidu.com'), '响应头留下 sni 标记')
  assert.ok(!/unVerifySsl/.test(res.getHeader('DS-Interceptor')), '响应头不能声称已免校验')
  console.log('√ sni 只改 SNI：不终结请求、不隐式免校验')
})()

// 测 2: sni: "" 表示不发送 SNI，同样是修改型拦截器
;(function testSniDisabled () {
  const { context, rOptions, agent } = createContext('www.reddit.com')
  const res = createRes()
  const ret = sni.requestIntercept(context, { sni: '' }, null, res, true, () => {})
  assert.strictEqual(ret, undefined, 'sni:"" 也返回 undefined')
  assert.strictEqual(rOptions.servername, '', '空串 servername = 不发 SNI 扩展')
  assert.strictEqual(rOptions.agent, agent, 'sni:"" 不决定校验策略')
  assert.ok(res.getHeader('DS-Interceptor').includes('sni: (disabled)'))
  console.log('√ sni:"" 与常规分支走同一套策略')
})()

// 测 3: 两个修改型拦截器叠加执行（修复前 unVerifySsl 永远执行不到）
;(function testComposeSniAndUnVerifySsl () {
  const { context, rOptions, unVerifySslAgent, logs } = createContext('www.reddit.com')
  const res = createRes()
  runChain([
    wrap(sni, { sni: 'baidu.com', unVerifySsl: true }),
    wrap(unVerifySsl, { sni: 'baidu.com', unVerifySsl: true }),
  ], context, res)
  assert.strictEqual(rOptions.servername, 'baidu.com')
  assert.strictEqual(rOptions.agent, unVerifySslAgent, '显式 unVerifySsl 换成免校验 agent')
  const header = res.getHeader('DS-Interceptor')
  assert.ok(header.includes('sni: baidu.com'), '响应头保留 sni 标记')
  assert.ok(header.includes('unVerifySsl'), '响应头追加 unVerifySsl 标记')
  assert.ok(logs.some(l => l.includes('unVerifySsl intercept')), 'unVerifySsl 确实执行了')
  console.log(`√ sni + unVerifySsl 可组合：DS-Interceptor = ${header}`)
})()

// 测 4: Issue 复现里的目标用法 { sni: "", unVerifySsl: true }
;(function testComposeSniDisabledAndUnVerifySsl () {
  const { context, rOptions, unVerifySslAgent } = createContext('www.reddit.com')
  const res = createRes()
  runChain([
    wrap(sni, { sni: '', unVerifySsl: true }),
    wrap(unVerifySsl, { sni: '', unVerifySsl: true }),
  ], context, res)
  assert.strictEqual(rOptions.servername, '', '彻底不发 SNI')
  assert.strictEqual(rOptions.agent, unVerifySslAgent, '同时接受对端默认证书')
  const header = res.getHeader('DS-Interceptor')
  assert.ok(header.includes('sni: (disabled)') && header.includes('unVerifySsl'))
  console.log(`√ { sni: "", unVerifySsl: true } 同时生效：DS-Interceptor = ${header}`)
})()

// 测 5: 只配 sni 时不得隐式免校验（回归护栏）
;(function testSniAloneKeepsVerify () {
  const { context, rOptions, agent } = createContext('github.com')
  const res = createRes()
  runChain([wrap(sni, { sni: 'baidu.com' })], context, res)
  assert.strictEqual(rOptions.agent, agent, '只有 sni 时证书校验保持开启')
  assert.ok(!/unVerifySsl/.test(res.getHeader('DS-Interceptor')))
  console.log('√ 只配 sni：证书校验仍然开启')
})()

// 测 6: 两个拦截器都能被 is() 选中，配置作者不需要二选一
;(function testIsComposition () {
  const rule = { sni: '', unVerifySsl: true }
  assert.strictEqual(sni.is(rule), true, '空串 sni 也命中 sni 拦截器')
  assert.strictEqual(unVerifySsl.is(rule), true, 'unVerifySsl 同时命中')
  assert.strictEqual(unVerifySsl.is({ ssl: false }), true, 'ssl:false 等价于 unVerifySsl')
  console.log('√ sni 与 unVerifySsl 的 is() 同时命中')
})()

// 测 7: verifyHost 与禁用 SNI 一起配置（Fastly 这类默认证书边缘的写法）
;(function testVerifyHostWithDisabledSni () {
  const { context, rOptions } = createContext('www.reddit.com')
  const res = createRes()
  runChain([wrap(sni, { sni: '', verifyHost: 'default.ssl.fastly.net' })], context, res)
  assert.strictEqual(rOptions.servername, '')
  assert.strictEqual(rOptions.verifyHost, 'default.ssl.fastly.net')
  assert.ok(res.getHeader('DS-Interceptor').includes('verifyHost: default.ssl.fastly.net'))
  console.log('√ sni:"" + verifyHost：可以校验对端默认证书')
})()

// 测 8: 默认按真实域名校验证书
;(function testTlsVerifyDefault () {
  const rOptions = { protocol: 'https:', hostname: 'example.com' }
  applyTlsVerifyPolicy(rOptions, null)
  assert.strictEqual(rOptions.servername, 'example.com', '默认 servername = 真实域名')
  assert.strictEqual(rOptions.checkServerIdentity, undefined, '默认交给 Node 校验真实域名')
  console.log('√ 默认路径：按真实域名校验')
})()

// 测 9: 伪装 SNI 时，证书仍按真实域名校验
;(function testTlsVerifyWithFakeSni () {
  const rOptions = { protocol: 'https:', hostname: 'github.com', servername: 'baidu.com' }
  applyTlsVerifyPolicy(rOptions, null)
  assert.strictEqual(typeof rOptions.checkServerIdentity, 'function', 'servername 偏离真实域名时接管校验')
  assert.strictEqual(isRejected(rOptions.checkServerIdentity, 'github.com'), false, '真实域名证书通过')
  assert.strictEqual(isRejected(rOptions.checkServerIdentity, 'baidu.com'), true, '伪装域名的证书被拒')
  console.log('√ 伪装 SNI：证书按真实域名校验')
})()

// 测 10: verifyHost 覆盖校验域名，并给出安全告警
;(function testTlsVerifyWithVerifyHost () {
  const logs = []
  const rOptions = { protocol: 'https:', hostname: 'huggingface.co', servername: 'huggingface.cn', verifyHost: 'huggingface.cn' }
  applyTlsVerifyPolicy(rOptions, { warn: msg => logs.push(msg) })
  assert.strictEqual(typeof rOptions.checkServerIdentity, 'function', '伪装 SNI 后接管校验')
  assert.strictEqual(isRejected(rOptions.checkServerIdentity, 'huggingface.cn'), false, 'verifyHost 的证书通过')
  assert.strictEqual(isRejected(rOptions.checkServerIdentity, 'huggingface.co'), true, '真实域名证书反而不匹配')
  assert.ok(logs.some(l => l.includes('[安全风险]')), 'verifyHost ≠ 真实域名时打安全告警')

  // verifyHost 就是真实域名时不需要接管，也不告警
  const logs2 = []
  const rOptions2 = { protocol: 'https:', hostname: 'example.com', servername: 'baidu.com', verifyHost: 'example.com' }
  applyTlsVerifyPolicy(rOptions2, { warn: msg => logs2.push(msg) })
  assert.strictEqual(typeof rOptions2.checkServerIdentity, 'function', 'SNI 偏离时接管校验')
  assert.strictEqual(isRejected(rOptions2.checkServerIdentity, 'example.com'), false, '按真实域名校验')
  assert.strictEqual(logs2.length, 0, 'verifyHost 等于真实域名时不告警')
  console.log('√ verifyHost：按指定域名校验 + 安全告警')
})()

// 测 11: 禁用 SNI 时，默认仍按真实域名校验（不能用对端默认证书蒙混过关）
;(function testTlsVerifyWithDisabledSni () {
  const rOptions = { protocol: 'https:', hostname: 'www.reddit.com', servername: '' }
  applyTlsVerifyPolicy(rOptions, null)
  assert.strictEqual(rOptions.servername, '', '空 servername 不被真实域名覆盖')
  assert.strictEqual(isRejected(rOptions.checkServerIdentity, 'default.ssl.fastly.net'), true, '默认证书不匹配真实域名时拒绝')
  console.log('√ 禁用 SNI：默认仍按真实域名校验')
})()

// 测 12: proxy 分支同样支持 sni:"" + unVerifySsl，并且不隐式免校验
;(function testProxyComposition () {
  const rule = { proxy: 'cdn.example.net', sni: '', unVerifySsl: true }
  const { context, rOptions, unVerifySslAgent } = createContext('raw.example.com')
  const res = createRes()
  proxy.requestIntercept(context, rule, null, res, true, () => {})
  assert.strictEqual(rOptions.hostname, 'cdn.example.net', 'proxy 换目标')
  assert.strictEqual(rOptions.servername, '', 'proxy + sni:"" 不发 SNI')
  assert.strictEqual(rOptions.agent, unVerifySslAgent, 'proxy + unVerifySsl 免校验')
  const header = res.getHeader('DS-Interceptor')
  assert.ok(header.includes('proxy: https://cdn.example.net/') && header.includes('sni: (disabled)') && header.includes('unVerifySsl'), `DS-Interceptor = ${header}`)

  const second = createContext('raw.example.com')
  proxy.requestIntercept(second.context, { proxy: 'cdn.example.net', sni: 'baidu.com' }, null, createRes(), true, () => {})
  assert.strictEqual(second.rOptions.agent, second.agent, 'proxy + sni 不再隐式免校验')
  console.log('√ proxy 分支：显式校验策略生效')
})()

// 测 13: 目标被改写到 overwall 服务器时，原规则的 unVerifySsl 不漏到新目标
;(function testRestoreVerifySslOnTargetChange () {
  const { restoreVerifySslAgent } = require('../src/lib/interceptor/impl/req/interceptorUtil')
  const { context, rOptions, agent, unVerifySslAgent } = createContext('github.com')
  // 模拟 util.createHttpsAgent 里建立的反向引用
  unVerifySslAgent.verifySslAgent = agent
  const rule = { sni: 'baidu.com', unVerifySsl: true }
  runChain([wrap(sni, rule), wrap(unVerifySsl, rule)], context, createRes())
  assert.strictEqual(rOptions.agent, unVerifySslAgent, '先按规则免校验')
  assert.strictEqual(restoreVerifySslAgent(rOptions), true)
  assert.strictEqual(rOptions.agent, agent, '目标改写后恢复默认校验策略')
  console.log('√ overwall 改写目标后恢复默认校验策略')
})()

// 测 14: overwall 接管后，原域名的 SNI 伪装 / 证书校验域名 / 免校验策略都不带走
;(function testOverwallResetsTlsPolicy () {
  const { createOverwallMiddleware } = require('../src/lib/proxy/middleware/overwall')
  const middleware = createOverwallMiddleware({
    enabled: true,
    server: { 'ow.example.com': { id: 1, port: 8443, path: '' } },
    targets: { 'github.com': true },
  })
  assert.ok(middleware, 'overwall middleware 创建成功')

  const { context, rOptions, agent, unVerifySslAgent } = createContext('github.com')
  unVerifySslAgent.verifySslAgent = agent
  rOptions.servername = 'baidu.com'
  rOptions.verifyHost = 'baidu.com'
  rOptions.agent = unVerifySslAgent
  const res = createRes()
  middleware.requestIntercept(context, { url: '/' }, res, true, () => {})

  assert.strictEqual(rOptions.hostname, 'ow.example.com', '目标换成 overwall 服务器')
  assert.strictEqual(rOptions.servername, undefined, '不把伪装 SNI 带到 overwall 服务器')
  assert.strictEqual(rOptions.verifyHost, undefined, '不把 verifyHost 带到 overwall 服务器')
  assert.strictEqual(rOptions.agent, agent, '恢复默认校验策略')
  console.log('√ overwall 接管后重置 TLS 策略')
})()

console.log('')
console.log('拦截器组合性（sni / unVerifySsl / proxy）测试全部通过')

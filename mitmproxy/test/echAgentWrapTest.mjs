/**
 * 回归测试：包装「校验/不校验」代理对时必须终止
 *
 * createHttpsAgent（src/lib/proxy/common/util.js）造出的是一对互相引用的代理：
 *   agent.unVerifySslAgent.verifySslAgent === agent
 * 如果包装时先递归、后登记，这一对就会无限递归，抛出
 * RangeError: Maximum call stack size exceeded（桌面版访问 x.com 时的报错）。
 *
 * 运行：node test/echAgentWrapTest.mjs
 */
import assert from 'node:assert'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { createEchAgentPair } = require('../src/lib/proxy/common/ech/EchHttpsAgent.js')

const verifySslAgent = { options: {} }
const unVerifySslAgent = { options: {} }
verifySslAgent.unVerifySslAgent = unVerifySslAgent
unVerifySslAgent.verifySslAgent = verifySslAgent

const pair = createEchAgentPair({
  dnsConfig: { ech: { domains: ['*.x.com'] }, dnsMap: {} },
  ech: { domains: ['*.x.com'], enabled: true, use: true },
})
assert.ok(pair != null, 'ECH 代理对应当可用')

const wrapped = pair.wrap(verifySslAgent)
assert.ok(wrapped != null, '包装结果不为空')
assert.strictEqual(pair.wrap(verifySslAgent), wrapped, '同一个代理只包装一次')
assert.strictEqual(
  wrapped.unVerifySslAgent.verifySslAgent,
  wrapped,
  '反向引用应当指向包装后的代理，而不是原始代理',
)

console.log('ech 代理包装：通过（无栈溢出，反向引用保持）')

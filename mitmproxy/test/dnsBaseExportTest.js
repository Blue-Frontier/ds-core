// issue #742 防回归：dns/base 导出上的 reportIPv6Error 必须是可调用函数。
// 历史上 `module.exports.reportIPv6Error` 在 `module.exports = class BaseDNS` 之前执行，
// 类替换整个导出后该属性丢失，createRequestHandler 解构到 undefined，
// ENETUNREACH 错误路径调用它时在事件回调里抛 uncaught TypeError。
const assert = require('node:assert')
const dnsBase = require('../src/lib/dns/base')

assert.strictEqual(typeof dnsBase, 'function', 'module.exports 仍是 BaseDNS 类（子类 extends 依赖）')
assert.strictEqual(typeof dnsBase.reportIPv6Error, 'function', 'reportIPv6Error 必须导出为函数（issue #742）')

// 调用不得抛错：IPv4 直接忽略；IPv6 计数（本进程内只计一次，够不到 3 次的禁用阈值）
assert.doesNotThrow(() => dnsBase.reportIPv6Error('8.8.8.8'), 'IPv4 地址应被安全忽略')
assert.doesNotThrow(() => dnsBase.reportIPv6Error('2606:50c0:8000::154'), 'IPv6 地址调用应安全执行')

// 调用方用法（createRequestHandler.js 的解构方式）拿到的也必须是函数
const { reportIPv6Error } = require('../src/lib/dns/base')
assert.strictEqual(typeof reportIPv6Error, 'function', '解构导入 reportIPv6Error 必须是函数（issue #742）')

console.log('')
console.log('dns/base reportIPv6Error 导出防回归测试全部通过')

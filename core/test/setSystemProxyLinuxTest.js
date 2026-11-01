const assert = require('node:assert')
const setSystemProxy = require('../src/shell/scripts/set-system-proxy/index.js')

const { ipv4WildcardToCidr } = setSystemProxy

// eslint-disable-next-line no-undef
describe('linux proxy exclude: ipv4 wildcard to cidr', () => {
  // eslint-disable-next-line no-undef
  it('尾部连续通配符转成 CIDR', () => {
    assert.strictEqual(ipv4WildcardToCidr('192.168.*.*'), '192.168.0.0/16')
    assert.strictEqual(ipv4WildcardToCidr('192.168.1.*'), '192.168.1.0/24')
    assert.strictEqual(ipv4WildcardToCidr('10.*.*.*'), '10.0.0.0/8')
  })

  // eslint-disable-next-line no-undef
  it('非尾部通配、全通配、非 IPv4 一律不转换', () => {
    assert.strictEqual(ipv4WildcardToCidr('192.168.0.1'), null, '精确 IP 不处理')
    assert.strictEqual(ipv4WildcardToCidr('192.168.*.1'), null, '通配后面还有数字，无法用 CIDR 表达')
    assert.strictEqual(ipv4WildcardToCidr('*.*.*.*'), null, '全通配不能转成 0.0.0.0/0 全排除')
    assert.strictEqual(ipv4WildcardToCidr('192.168.*'), null, '三段不处理')
    assert.strictEqual(ipv4WildcardToCidr('*.example.com'), null, '域名通配不处理')
    assert.strictEqual(ipv4WildcardToCidr('192.168.256.*'), null, '非法段值不处理')
    assert.strictEqual(ipv4WildcardToCidr(''), null)
    assert.strictEqual(ipv4WildcardToCidr(null), null)
  })
})

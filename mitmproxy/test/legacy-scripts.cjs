/**
 * test/ 目录里有两类历史测试：
 *
 *   local — 只在本机跑、结果确定，写成了「require 即执行」的脚本形式。
 *           这类脚本一旦断言失败会直接 process.exit(1)，把整个 mocha 进程带走，
 *           于是连已通过的用例和失败汇总都看不到。现在由 legacyScriptsTest.js
 *           用子进程逐个执行，失败只算该条失败。
 *
 *   manual — 依赖公网（DoH/DoT 服务器）、第三方账号或真实 OCR 服务，不能进 CI：
 *           网络抖动会让测试随机变红，境内环境还会长时间超时。
 *           需要时手动执行：node test/dnsTest.mjs 之类。
 *
 * 新增真正的 mocha 测试不需要登记在这里，放进 test/ 就会被自动执行。
 * 断言逻辑仍留在各自脚本里，迁移成 describe/it 时可以逐个从 local 列表删除。
 */
const local = [
  'dnsBaseExportTest.js',
  'interceptorComposeTest.js',
  'lodashTest.js',
  'matchTest.js',
  'matchUtilTest.js',
  'monkeyTest.js',
  'pacTest.js',
  'p2pLinkTest.js',
  'p2pTlsConnectTest.js',
  'proxyTest.js',
  'requestReplaceEnvTest.js',
  'responseReplaceTest.js',
  'sha256Test.js',
  'upgradeHandlerTest.js',
  'utilTest.js',
]

const manual = [
  // 需要公网 DNS / DoH / DoT
  'dnsDefaultLookupTest.mjs',
  'dnsEchTest.mjs',
  'dnsSpeedTest.js',
  'dnsTest.mjs',
  'dnsTest-abroad.mjs',
  'dnsTest-abroad-doh-sni.mjs',
  'dnsTest-abroad-dot-sni.mjs',
  'ipv6-test.mjs',
  // 依赖第三方账号（百度 OCR），脚本里自带凭据，不应在 CI 里调用
  'baiduOcrTest.js',
]

module.exports = {
  local,
  manual,
}

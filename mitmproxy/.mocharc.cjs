// mocha 配置：脚本式测试由 legacyScriptsTest.js 在子进程里逐个跑，
// 依赖公网的脚本（manual）不参与 npm test，避免 CI 随机变红或长时间超时。
const { local, manual } = require('./test/legacy-scripts.cjs')

module.exports = {
  ignore: [...local, ...manual].map(file => `test/${file}`),
}

/**
 * 高端口范围内随机挑一个当前空闲端口（用于 P2P 监听）
 */
const net = require('node:net')

function isPortFree (port, host = '0.0.0.0') {
  return new Promise((resolve) => {
    const srv = net.createServer()
    srv.once('error', () => resolve(false))
    srv.once('listening', () => {
      srv.close(() => resolve(true))
    })
    srv.listen(port, host)
  })
}

/**
 * @param {object} [options]
 * @param {number} [options.min=49152]
 * @param {number} [options.max=65535]
 * @param {number} [options.attempts=32]
 * @returns {Promise<number>}
 */
async function pickRandomHighPort (options = {}) {
  const min = options.min || 49152
  const max = options.max || 65535
  const attempts = options.attempts || 32
  for (let i = 0; i < attempts; i++) {
    const port = min + Math.floor(Math.random() * (max - min + 1))
    if (await isPortFree(port)) {
      return port
    }
  }
  throw new Error('未找到空闲高端口')
}

module.exports = {
  isPortFree,
  pickRandomHighPort,
}

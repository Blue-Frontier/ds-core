/**
 * 对称 NAT 端口预测：用同一/不同 socket 打多次 STUN，
 * 若映射端口近似线性递增，则预测「对新目的端」的候选外网端口。
 * 无中继；打洞失败即失败。
 */
const dgram = require('node:dgram')
const net = require('node:net')
const stun = require('./stun')

/**
 * 从同一 socket 连续问多个 STUN，观察外部端口是否递增
 * @returns {Promise<{publicIp: string, ports: number[], delta: number|null, symmetricLike: boolean}>}
 */
async function probePortPattern (samples = 4) {
  const servers = stun.DEFAULT_STUN
  const results = []
  for (let i = 0; i < samples; i++) {
    const server = servers[i % servers.length]
    const mapped = await stun.stunOnce(server, 1500)
    if (mapped && mapped.address) {
      results.push(mapped)
    }
  }
  if (results.length === 0) {
    return { publicIp: '', ports: [], delta: null, symmetricLike: false }
  }
  const ports = results.map((r) => r.port)
  const publicIp = results[0].address
  let delta = null
  if (ports.length >= 2) {
    const diffs = []
    for (let i = 1; i < ports.length; i++) {
      diffs.push(ports[i] - ports[i - 1])
    }
    // 多数相邻差值相同且非 0 → 近似线性（对称 NAT 常见）
    const mode = diffs.slice().sort((a, b) => a - b)[Math.floor(diffs.length / 2)]
    if (mode !== 0) {
      delta = mode
    }
  }
  // 同 IP、端口各不相同 → 像对称 NAT
  const unique = new Set(ports)
  const symmetricLike = unique.size === ports.length && ports.length >= 2
  return { publicIp, ports, delta, symmetricLike }
}

/**
 * 根据最后映射端口 + delta 预测下一批候选端口
 */
function predictPorts (lastPort, delta, count = 8) {
  if (!Number.isFinite(lastPort) || !Number.isFinite(delta) || delta === 0) {
    // 退化为邻域扫描（生日攻击常见区间）
    const base = lastPort || 0
    const list = []
    for (let i = -3; i <= 4; i++) {
      const p = base + i
      if (p > 0 && p < 65535) {
        list.push(p)
      }
    }
    return list
  }
  const list = []
  for (let i = 1; i <= count; i++) {
    const p = lastPort + delta * i
    if (p > 0 && p < 65535) {
      list.push(p)
    }
  }
  return list
}

/**
 * TCP 同时拨号打洞：双方约好同一时刻 connect 对方公网候选端口。
 * 成功返回 socket；全部失败返回 null。
 *
 * @param {object} options
 * @param {string} options.remoteHost 对方公网/内网 IP
 * @param {number[]} options.remotePorts 候选端口
 * @param {number} options.localPort 本地出站绑定端口（尽量与 STUN 时一致）
 * @param {number} [options.timeoutMs]
 * @returns {Promise<net.Socket|null>}
 */
function tcpHolePunch ({ remoteHost, remotePorts, localPort, timeoutMs = 3000 }) {
  return new Promise((resolve) => {
    const ports = [...new Set(remotePorts.filter((p) => p > 0 && p < 65535))]
    if (!remoteHost || ports.length === 0) {
      resolve(null)
      return
    }
    const sockets = []
    let done = false
    const finish = (result) => {
      if (done) {
        return
      }
      done = true
      for (const s of sockets) {
        if (s !== result) {
          try {
            s.destroy()
          } catch {
            // ignore
          }
        }
      }
      resolve(result)
    }
    const timer = setTimeout(() => finish(null), timeoutMs)

    for (const port of ports) {
      const socket = new net.Socket()
      sockets.push(socket)
      const opts = { port, host: remoteHost }
      // 绑定本地端口有助于保持 NAT 映射（失败则随机）
      if (localPort) {
        opts.localPort = localPort
      }
      socket.once('connect', () => {
        clearTimeout(timer)
        finish(socket)
      })
      socket.once('error', () => {
        // 单路失败继续其它候选
      })
      try {
        socket.connect(opts)
      } catch {
        // ignore
      }
    }
  })
}

/**
 * UDP 打洞：向对方候选端口发探测包，等 echo（需对端同样 listen）。
 * 这里只做「发探测 + 等回包」半边，对称 NAT 下配合端口预测。
 */
function udpPunch ({ remoteHost, remotePorts, localPort, timeoutMs = 3000 }) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })
    let done = false
    const finish = (value) => {
      if (done) {
        return
      }
      done = true
      try {
        socket.close()
      } catch {
        // ignore
      }
      resolve(value)
    }
    const timer = setTimeout(() => finish(null), timeoutMs)
    socket.on('message', (msg, rinfo) => {
      clearTimeout(timer)
      finish({ socket, message: msg, rinfo })
    })
    socket.on('error', () => finish(null))
    const payload = Buffer.from('ds-p2p-punch')
    socket.bind(localPort || 0, () => {
      for (const port of remotePorts) {
        try {
          socket.send(payload, port, remoteHost)
        } catch {
          // ignore
        }
      }
    })
  })
}

module.exports = {
  probePortPattern,
  predictPorts,
  tcpHolePunch,
  udpPunch,
}

/**
 * 连接方式判断：
 * - 本机网卡上是否有公网地址
 * - UPnP 是否真的映射成功
 * - STUN 只反映 NAT 出口，不能当「本机有公网 IP」
 */
const os = require('node:os')

function isPrivateIPv4 (ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip)
  if (!m) {
    return true
  }
  const a = Number(m[1])
  const b = Number(m[2])
  if (a === 0 || a === 127 || a >= 224) {
    return true
  }
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)) {
    return true
  }
  return false
}

function isPrivateIp (ip) {
  if (!ip) {
    return true
  }
  const v = String(ip).replace(/^\[|\]$/g, '')
  if (v.includes(':')) {
    // IPv6：链路本地 / ULA / 环回 视为非公网
    const lower = v.toLowerCase()
    if (lower === '::1' || lower.startsWith('fe80') || lower.startsWith('fc') || lower.startsWith('fd')) {
      return true
    }
    return false
  }
  return isPrivateIPv4(v)
}

function listLocalAddresses () {
  const result = { public: [], private: [] }
  const ifaces = os.networkInterfaces()
  for (const addrs of Object.values(ifaces)) {
    for (const a of addrs || []) {
      if (a.internal || !a.address) {
        continue
      }
      const addr = String(a.address)
      if (isPrivateIp(addr)) {
        result.private.push(addr)
      } else {
        result.public.push({ address: addr, family: a.family === 6 || a.family === 'IPv6' ? 6 : 4 })
      }
    }
  }
  return result
}

/**
 * @param {object} [options]
 * @param {boolean} [options.upnp] UPnP 映射是否成功
 * @param {string} [options.stunAddress] STUN 看到的出口地址（≠本机公网）
 * @param {string} [options.publicHost] 用于分享链接的 host
 */
function resolveConnectionMode (options = {}) {
  const upnp = !!options.upnp
  const local = listLocalAddresses()
  const realPublic = local.public[0] || null

  if (upnp) {
    const host = options.stunAddress || options.publicHost || (realPublic && realPublic.address) || ''
    const v6 = host.includes(':')
    return v6 ? 'UPnP/公网IPv6' : 'UPnP/公网IPv4'
  }

  if (realPublic) {
    return realPublic.family === 6 ? '公网IPv6' : '公网IPv4'
  }

  // 本机无公网地址：STUN 只说明有 NAT 出口，不能写成「公网」
  return '仅局域网'
}

module.exports = {
  resolveConnectionMode,
  isPrivateIp,
  listLocalAddresses,
}

/**
 * 节点侧配额账本：按客户端 nodeId 记账（卡密兑换后增加流量）
 * 文件: ~/.dev-sidecar/p2p-quota.json
 */
const fs = require('node:fs')
const path = require('node:path')
const os = require('node:os')

function quotaPath () {
  const home = process.env.USERPROFILE || process.env.HOME || os.homedir()
  return path.resolve(home, './.dev-sidecar/p2p-quota.json')
}

function loadLedger () {
  try {
    const p = quotaPath()
    if (!fs.existsSync(p)) {
      return { clients: {}, usedCards: {} }
    }
    const data = JSON.parse(fs.readFileSync(p, 'utf8')) || {}
    return {
      clients: data.clients || {},
      usedCards: data.usedCards || {},
    }
  } catch {
    return { clients: {}, usedCards: {} }
  }
}

function saveLedger (ledger) {
  const p = quotaPath()
  fs.mkdirSync(path.dirname(p), { recursive: true })
  fs.writeFileSync(p, `${JSON.stringify(ledger, null, 2)}\n`, 'utf8')
}

function getQuota (clientNodeId) {
  const ledger = loadLedger()
  const entry = ledger.clients[clientNodeId]
  return {
    clientNodeId,
    totalGb: entry?.totalGb || 0,
    usedGb: entry?.usedGb || 0,
    availableGb: Math.max(0, (entry?.totalGb || 0) - (entry?.usedGb || 0)),
    updatedAt: entry?.updatedAt || null,
  }
}

function addQuota (clientNodeId, gb) {
  const ledger = loadLedger()
  const entry = ledger.clients[clientNodeId] || { totalGb: 0, usedGb: 0 }
  entry.totalGb = (entry.totalGb || 0) + Number(gb || 0)
  entry.updatedAt = Date.now()
  ledger.clients[clientNodeId] = entry
  saveLedger(ledger)
  return getQuota(clientNodeId)
}

function markCardUsed (cardId) {
  const ledger = loadLedger()
  if (ledger.usedCards[cardId]) {
    return false
  }
  ledger.usedCards[cardId] = Date.now()
  saveLedger(ledger)
  return true
}

function addUsage (clientNodeId, gb) {
  const ledger = loadLedger()
  const entry = ledger.clients[clientNodeId] || { totalGb: 0, usedGb: 0 }
  entry.usedGb = (entry.usedGb || 0) + Number(gb || 0)
  entry.updatedAt = Date.now()
  ledger.clients[clientNodeId] = entry
  saveLedger(ledger)
  return getQuota(clientNodeId)
}

module.exports = {
  quotaPath,
  getQuota,
  addQuota,
  addUsage,
  markCardUsed,
  loadLedger,
}

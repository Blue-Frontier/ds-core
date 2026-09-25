const { ShareServer } = require('./shareServer')
const link = require('./link')
const stun = require('./stun')
const upnp = require('./upnp')
const holePunch = require('./holePunch')
const cert = require('./cert')
const upstream = require('./upstream')
const connectMode = require('./connectMode')
const pickPort = require('./pickPort')
const identity = require('./identity')
const card = require('./card')
const quota = require('./quota')
const nodeKey = require('./nodeKey')
const caSecret = require('./caSecret')

module.exports = {
  ShareServer,
  ...link,
  ...connectMode,
  ...pickPort,
  ...identity,
  ...card,
  ...quota,
  ...caSecret,
  nodeKeyPath: identity.identityPath,
  loadOrCreateNodeKey: identity.getIdentity,
  stun,
  upnp,
  holePunch,
  cert,
  upstream,
}

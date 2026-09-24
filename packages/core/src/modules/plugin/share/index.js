/**
 * L1 节点分享插件：境内 hop 上的 TLS+HTTP CONNECT + ds-p2p:// 链接
 * 出墙仍走 DS 原有加速/中转，不经本插件伪装。
 */
const shareConfig = require('./config')

const SharePlugin = function (context) {
  const { config, log } = context
  let shareServer = null
  let shareInfo = { host: '', port: 0, link: '', tls: true }

  const api = {
    async start () {
      const setting = config.get().plugin.share.setting
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      shareServer = new p2p.ShareServer({
        host: setting.listenHost,
        port: setting.listenPort,
        token: setting.token,
        name: setting.name,
        // 节点间 hop：TLS+CONNECT（自签）；不需要像真站
        tls: true,
      })
      await shareServer.start()
      shareInfo.port = setting.listenPort
      shareInfo.host = setting.listenHost
      shareInfo.tls = true

      let publicHost = null
      try {
        const mapped = setting.useUpnp
          ? await p2p.upnp.mapPort({
            internalPort: setting.listenPort,
            externalPort: setting.listenPort,
            description: 'dev-sidecar-p2p',
          })
          : null
        if (mapped) {
          shareServer.upnpStop = mapped.stop
          publicHost = mapped.externalHost
        }
      } catch (e) {
        log.warn('UPnP 端口映射失败:', e.message)
      }

      if (!publicHost) {
        try {
          const stunAddr = await p2p.stun.getPublicAddress()
          if (stunAddr) {
            publicHost = stunAddr.address
          }
        } catch (e) {
          log.warn('STUN 探测公网地址失败:', e.message)
        }
      }

      shareInfo.publicHost = publicHost || ''
      shareInfo.link = shareServer.getLink(publicHost || undefined)
      if (!publicHost && (setting.listenHost === '0.0.0.0' || setting.listenHost === '::')) {
        log.warn('未能探测公网地址，请手动修改分享链接中的 host（可填局域网 IP 或固定公网 IP）')
      }
      log.info('共享节点已启动 (TLS+CONNECT)，分享链接:', shareInfo.link)
      return shareInfo
    },

    async close () {
      if (shareServer) {
        await shareServer.stop()
        shareServer = null
      }
    },

    async stop () {
      return api.close()
    },

    async restart () {
      await api.close()
      return api.start()
    },

    getShareInfo () {
      return { ...shareInfo }
    },

    /**
     * 经任一 ds-p2p peer 建隧道到 targetHost:targetPort（境内节点互连）
     * @returns {Promise<{socket: import('node:net').Socket, peer: object}>}
     */
    async openTunnel (targetHost, targetPort) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      const peers = api.listPeers()
      return p2p.upstream.connectViaAnyPeer(peers, targetHost, targetPort)
    },

    listPeers () {
      return (config.get().plugin.share.setting.peers || []).slice()
    },

    async addPeer (uri) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      const peer = p2p.parseLink(uri)
      if (!peer) {
        throw new Error('无效的 ds-p2p:// 链接')
      }
      peer.tls = true
      const list = (config.get().plugin.share.setting.peers || []).filter(
        (p) => !(p.host === peer.host && p.port === peer.port),
      )
      list.push(peer)
      await config.update({ plugin: { share: { setting: { peers: list } } } })
      return peer
    },

    async addPeersFromText (text) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      const parsed = p2p.parsePeerList(text)
      let list = (config.get().plugin.share.setting.peers || []).slice()
      for (const peer of parsed) {
        peer.tls = true
        list = list.filter((p) => !(p.host === peer.host && p.port === peer.port))
        list.push(peer)
      }
      await config.update({ plugin: { share: { setting: { peers: list } } } })
      return parsed
    },

    async removePeer (host, port) {
      const list = (config.get().plugin.share.setting.peers || []).filter(
        (p) => !(p.host === host && p.port === port),
      )
      await config.update({ plugin: { share: { setting: { peers: list } } } })
      return true
    },
  }
  return api
}

module.exports = {
  key: 'share',
  config: shareConfig,
  status: {
    enabled: false,
  },
  plugin: SharePlugin,
}

/**
 * L1 节点分享插件：TLS+CONNECT + 配额/卡密
 */
const shareConfig = require('./config')

const SharePlugin = function (context) {
  const { config, event, log } = context
  let shareServer = null
  let shareInfo = { host: '', port: 0, link: '', publicHost: '', connectionMode: '未启动', nodeId: '' }

  const api = {
    async start () {
      const setting = config.get().plugin.share.setting
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      const me = p2p.getIdentity()
      shareInfo.nodeId = me.nodeId

      shareServer = new p2p.ShareServer({
        host: setting.listenHost,
        port: setting.listenPort,
        token: setting.token,
        name: setting.name,
      })
      await shareServer.start()

      let listenPort = Number(setting.listenPort) || shareServer.port
      if (!setting.listenPort) {
        // shareServer may have used default; prefer explicit random if still 0
        listenPort = shareServer.port
      }
      shareInfo.port = listenPort
      shareInfo.host = setting.listenHost

      // 先标记已启动，UPnP/STUN 在后台补充公网地址，不阻塞 start
      shareInfo.publicHost = ''
      shareInfo.connectionMode = '启动中'
      shareInfo.link = shareServer.getLink(undefined)
      event.fire('status', { key: 'plugin.share.enabled', value: true })
      log.info('P2P节点分享已启动（公网地址探测中）:', shareInfo.nodeId, shareInfo.link)

      // 异步：UPnP / STUN，完成后回填 link / connectionMode
      ;(async () => {
        try {
          let publicHost = null
          let upnp = false
          try {
            const mapped = setting.useUpnp
              ? await p2p.upnp.mapPort({
                internalPort: listenPort,
                externalPort: listenPort,
                description: 'dev-sidecar-p2p',
              })
              : null
            if (mapped) {
              shareServer.upnpStop = mapped.stop
              publicHost = mapped.externalHost
              upnp = true
            }
          } catch (e) {
            log.warn('UPnP 端口映射失败:', e.message)
          }

          let stunHost = null
          if (!publicHost) {
            try {
              const stunAddr = await p2p.stun.getPublicAddress()
              if (stunAddr) {
                stunHost = stunAddr.address
              }
            } catch (e) {
              log.warn('STUN 探测公网地址失败:', e.message)
            }
          }

          if (!shareServer) {
            return // 已关闭
          }
          shareInfo.publicHost = publicHost || stunHost || ''
          shareInfo.connectionMode = p2p.resolveConnectionMode({
            upnp,
            stunAddress: stunHost,
            publicHost: shareInfo.publicHost,
          })
          shareInfo.link = shareServer.getLink(shareInfo.publicHost || undefined)
          log.info('P2P节点分享公网地址就绪:', shareInfo.connectionMode, shareInfo.publicHost, shareInfo.link)
        } catch (e) {
          log.warn('P2P 公网地址探测失败:', e.message)
        }
      })()

      return shareInfo
    },

    async close () {
      if (shareServer) {
        await shareServer.stop()
        shareServer = null
      }
      shareInfo = {
        host: '',
        port: 0,
        link: '',
        publicHost: '',
        connectionMode: '未启动',
        nodeId: shareInfo.nodeId || '',
      }
      event.fire('status', { key: 'plugin.share.enabled', value: false })
    },

    async stop () {
      return api.close()
    },

    async restart () {
      await api.close()
      return api.start()
    },

    getShareInfo () {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      const me = p2p.getIdentity()
      shareInfo.nodeId = me.nodeId
      if (!shareServer) {
        return { link: '', connectionMode: '未启动', publicHost: '', port: 0, nodeId: me.nodeId }
      }
      const setting = config.get().plugin.share.setting
      shareInfo.link = shareServer.getLink(shareInfo.publicHost || undefined)
      shareInfo.port = setting.listenPort || shareInfo.port
      return { ...shareInfo }
    },

    getNodeId () {
      return require('@blue-frontier/mitmproxy/src/lib/p2p').getIdentity().nodeId
    },

    /** 查询对端 nodeId（需 token） */
    async getPeerInfo (peer) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      return p2p.upstream.getPeerInfo({
        host: peer.host,
        port: peer.port,
        token: peer.token,
      })
    },

    /** 在对端兑换卡密，返回 { ok, quota?, reason? } */
    async redeemCardOnPeer (peer, card) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      const me = p2p.getIdentity()
      const res = await p2p.upstream.redeemCardOnPeer({
        host: peer.host,
        port: peer.port,
        token: peer.token,
      }, card, me.nodeId)
      return res.body || { ok: false, reason: `HTTP ${res.status}` }
    },

    async issueCard (opts) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      return p2p.issueCard(opts)
    },

    async redeemCard (raw) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      return p2p.redeemCard(raw)
    },

    async openTunnel (targetHost, targetPort) {
      const p2p = require('@blue-frontier/mitmproxy/src/lib/p2p')
      return p2p.upstream.connectViaAnyPeer(api.listPeers(), targetHost, targetPort)
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
      peer.uri = uri
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

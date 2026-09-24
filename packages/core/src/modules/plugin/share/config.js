module.exports = {
  name: '节点分享 (ds-p2p)',
  enabled: false,
  tip: 'L1：把本机作为对外 HTTP 代理分享给其他 DS 用户；需公网 IP 或路由器 UPnP',
  setting: {
    listenHost: '0.0.0.0',
    listenPort: 31288,
    token: '',
    name: '',
    useUpnp: true,
    peers: [],
  },
}

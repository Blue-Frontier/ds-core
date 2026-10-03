module.exports = {
  name: 'P2P节点分享',
  enabled: false,
  needUnlock: true, // 需 setting.json 解锁增强模式后才在首页/托盘显示开关
  tip: '境内节点互连（TLS 1.3 + CONNECT）；出墙仍走 DS 原有加速',
  setting: {
    listenHost: '0.0.0.0',
    listenPort: 0,
    token: '',
    name: '',
    useUpnp: true,
    peers: [],
  },
}

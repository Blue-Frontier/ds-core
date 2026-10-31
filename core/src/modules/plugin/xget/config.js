module.exports = {
  name: 'Xget 加速',
  statusOff: true,
  enabled: false,
  tip: '启用并填写 Xget 实例地址后，Xget 的全平台加速规则会合并进配置，优先级等同于本地用户配置；实例挂在 Cloudflare Access 后面时，可填写服务令牌，插件规则会自动携带 CF Access 请求头',
  setting: {
    instanceUrl: '',
    // 可选：Cloudflare Access 服务令牌（两项都填写才生效）
    cfAccessClientId: '',
    cfAccessClientSecret: '',
  },
}

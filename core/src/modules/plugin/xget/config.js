module.exports = {
  name: 'Xget 加速',
  statusOff: true,
  enabled: false,
  tip: '启用并填写 Xget 实例地址后，Xget 的全平台加速规则会合并进配置，优先级等同于本地用户配置；实例挂在 Cloudflare Access 后面时，可保存服务令牌，插件规则会自动携带 CF Access 请求头（令牌存系统密钥库，不写配置文件）',
  setting: {
    instanceUrl: '',
    // 可选：Cloudflare Access 服务令牌。ID 不是秘密，照常存在配置里；
    // Secret 存 SecretStore（系统密钥库），不进配置文件。
    cfAccessClientId: '',
    // 旧版本遗留的明文字段：仅用于启动时迁移进 SecretStore，迁移后会被清空
    cfAccessClientSecret: '',
  },
}

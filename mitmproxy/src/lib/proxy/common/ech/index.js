/**
 * 上游ECH（Encrypted Client Hello，RFC 9849）支持
 *
 * Node（OpenSSL）本身没有提供ECH能力，这里用纯JS实现了 TLS 1.3 客户端 + ECH，
 * 通过 https.Agent 的方式接入到上游请求中，仅对配置指定的域名生效。
 */
module.exports = {
  ...require('./EchHttpsAgent'),
  ...require('./ech'),
  ...require('./hpke'),
  ...require('./tls13'),
  ...require('./tlsSocket'),
}

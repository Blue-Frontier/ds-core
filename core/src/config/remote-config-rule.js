/**
 * 「配置拉取」的默认对抗规则（共享远程配置与个人远程配置一视同仁）。
 *
 * 为什么需要它：拉取配置是"用来获得规则的请求"，它本身却常常拿不到任何规则保护 ——
 * 用户不会把配置地址写进 intercepts / dns.mapping，于是只能直连 + 系统DNS，
 * 一旦遇到 SNI 干扰或 DNS 污染就永远拉不到（表现为超时/挂起，且日志里既无成功也无失败）。
 *
 * 这里给出的默认策略（三件套，全部复用 DS 自身既有机制，不新增对抗手段）：
 *   ① `intercepts[host] = { '.*': { sni } }` —— SNI 伪装，并顺带触发 DS 自己的 DNS 解析；
 *   ② `dns.mapping[host] = <Cloudflare DoH>` —— 干净解析，不依赖 ForSNI 兜底（那默认是国内 DoT）；
 *   ③ `preSetIpList[host]` —— 已知可靠 IP，命中即跳过解析（DNS 被污染时的终极保底）。
 *
 * 可被配置覆盖（便于远程调整、不必发版）：
 *   `app.remoteConfig.fetchRule = { sni, dns, preSetIpList }`（放在 SYNC 区块之外，人手维护）
 *
 * 注意：本模块只产出数据，不修改传入对象；合并由调用方完成（便于单测）。
 */

/**
 * SNI 诱饵的默认值：null = 不改写。
 *
 * 实测（2026-10-06）：对 Cloudflare 前置的地址发 SNI=baidu.com 会被直接拒（ssl/tls alert
 * handshake failure），因为 Cloudflare 没有 baidu.com 的证书 —— 诱饵必须是**目标所在边缘自己拥有的域名**
 * （Cloudflare 系可用 cloudflare-ech.com）。因此默认不做改写，需要时用
 * pp.remoteConfig.fetchRule.sni 显式指定。
 */
const DEFAULT_SNI = null

/** 默认 DNS：在配置的 providers 里挑一个指向 Cloudflare DoH 的；挑不到就补一份等价的 */
const DEFAULT_DNS_PROVIDER = 'cf-DoH'
const CLOUDFLARE_DOH_SERVER = 'https://cloudflare-dns.com/dns-query'

/**
 * 官方配置域名的已知可靠 IP（Cloudflare anycast）。
 * 实测方式：2026-10-05 解析 ds-official-config.bestar.de5.net 后用 TCP 443 逐个连通性验证，仅写入验证通过的 IPv4。
 * 需要更新时，直接改这里，或用 `app.remoteConfig.fetchRule.preSetIpList` 覆盖。
 */
const DEFAULT_PRE_SET_IP_LIST = {
  'ds-official-config.bestar.de5.net': {
    '104.21.24.188': true,
    '172.67.219.233': true,
  },
}

/**
 * 在 providers 里挑选（必要时补齐）Cloudflare DoH provider。
 *
 * @param {object} providers serverConfig.dns.providers（会被返回的 providers 补丁覆盖，此处只读）
 * @param {string} [preferred] 覆盖指定的 provider 名
 * @returns {{name: string, patch: (object|null)}} 选中的名字与需要补齐的 provider 定义
 */
function pickCloudflareDohProvider (providers, preferred) {
  if (typeof preferred === 'string' && preferred !== '') {
    if (providers[preferred] != null) {
      return { name: preferred, patch: null }
    }
    return { name: preferred, patch: { server: CLOUDFLARE_DOH_SERVER } }
  }
  for (const [name, conf] of Object.entries(providers || {})) {
    if (conf && typeof conf.server === 'string' && conf.server.includes('cloudflare-dns.com')) {
      return { name, patch: null }
    }
  }
  return { name: DEFAULT_DNS_PROVIDER, patch: { server: CLOUDFLARE_DOH_SERVER } }
}

/**
 * 由 URL 取 hostname（非法则返回 null）。
 *
 * @param {unknown} url
 * @returns {string|null}
 */
function safeHostname (url) {
  if (typeof url !== 'string' || url === '') {
    return null
  }
  try {
    return new URL(url).hostname || null
  } catch {
    return null
  }
}

/**
 * 生成「配置拉取」需要注入的规则数据。
 *
 * @param {object}   options
 * @param {object}   options.remoteConfig  app.remoteConfig（含 url / personalUrl / enabled / fetchRule）
 * @param {object}   options.providers     serverConfig.dns.providers（只读，用于挑选 DNS）
 * @param {object}   [options.patch]       第一层默认值（默认用内置那套三件套）
 * @returns {{intercepts: object, dnsMapping: object, preSetIpList: object, providers: object, applied: Array}}
 */
function buildRemoteConfigFetchRules ({ remoteConfig, providers, patch }) {
  const empty = { intercepts: {}, dnsMapping: {}, preSetIpList: {}, providers: {}, applied: [] }
  if (remoteConfig == null || remoteConfig.enabled !== true) {
    return empty
  }

  const base = patch || {
    sni: DEFAULT_SNI,
    // dns: null 表示自动挑选（指向 cloudflare-dns.com 的 provider，挑不到就补一份 cf-DoH）
    // 注：该端点在中国大陆不可达（实测 ECONNRESET/超时），此时 DS 的解析层会自行
    // fallback to default DNS，因此映射仍保留 —— 对能直连 Cloudflare 的网络它提供干净解析。
    dns: null,
    preSetIpList: DEFAULT_PRE_SET_IP_LIST,
  }
  const override = remoteConfig.fetchRule || {}

  const sni = override.sni !== undefined ? override.sni : base.sni
  const dns = override.dns !== undefined ? override.dns : base.dns
  const preSetIpListAll = override.preSetIpList !== undefined ? override.preSetIpList : base.preSetIpList

  const result = { intercepts: {}, dnsMapping: {}, preSetIpList: {}, providers: {}, applied: [] }
  const picked = pickCloudflareDohProvider(providers, dns)
  if (picked.patch != null) {
    result.providers[picked.name] = picked.patch
  }

  for (const url of [remoteConfig.url, remoteConfig.personalUrl]) {
    const hostname = safeHostname(url)
    if (hostname == null) {
      continue
    }
    if (sni !== null && sni !== undefined) {
      result.intercepts[hostname] = {
        '.*': { sni, remark: '内置：远程配置拉取（默认对抗策略）' },
      }
    }
    result.dnsMapping[hostname] = picked.name
    const preSet = preSetIpListAll != null ? preSetIpListAll[hostname] : null
    if (preSet != null && Object.keys(preSet).length > 0) {
      result.preSetIpList[hostname] = { ...preSet }
    }
    result.applied.push({
      hostname,
      sni: sni !== null && sni !== undefined ? sni : '(保持原样)',
      dns: picked.name,
      preSetIpCount: preSet != null ? Object.keys(preSet).length : 0,
    })
  }

  return result
}

module.exports = {
  DEFAULT_SNI,
  DEFAULT_DNS_PROVIDER,
  DEFAULT_PRE_SET_IP_LIST,
  buildRemoteConfigFetchRules,
  pickCloudflareDohProvider,
  safeHostname,
}
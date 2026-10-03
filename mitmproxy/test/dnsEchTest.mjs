/**
 * ECH（RFC 9848）测试：通过DNS的 HTTPS(65) 记录获取 ech 参数
 *
 * 运行方式：
 *   node test/dnsEchTest.mjs
 *   node test/dnsEchTest.mjs crypto.cloudflare.com
 */
import assert from 'node:assert'
import dns from '../src/lib/dns/index.js'
import matchUtil from '../src/utils/util.match.js'
import svcbUtil from '../src/lib/dns/util.svcb.js'

// 兼容 mocha 加载本文件的情况（`mocha --exit` 会把选项一起放进 argv）
const argHostname = process.argv.slice(2).find(arg => !arg.startsWith('-') && arg.includes('.'))
const hostname = argHostname || 'crypto.cloudflare.com'
const noEchHostname = 'baidu.com'

const preSetIpList = matchUtil.domainMapRegexply({
  'preset.com': ['100.100.100.100'],
})

const dnsProviders = dns.initDNS({
  aliyunUDP: {
    server: 'udp://223.5.5.5',
  },
  aliyunTLS: {
    server: 'tls://dns.alidns.com:853',
  },
  aliyunHTTPS: {
    type: 'https',
    server: 'https://dns.alidns.com/dns-query',
  },
}, preSetIpList, {
  ech: {
    enabled: true,
    cacheSize: 100,
  },
})

const dnsConfig = {
  preSetIpList,
  dnsMap: dnsProviders,
  mapping: matchUtil.domainMapRegexply({
    [`*${hostname.split('.').slice(-2).join('.')}`]: 'aliyunUDP',
    '*cloudflare*': 'aliyunUDP',
  }),
  ech: {
    enabled: true,
  },
}

console.log('\n--------------- test util.svcb ---------------\n')
{
  // 编码报文的固定结构校验
  const query = svcbUtil.encodeQuery('a.b.com', { id: 0x1234 })
  assert.strictEqual(query.readUInt16BE(0), 0x1234) // ID
  assert.strictEqual(query.readUInt16BE(2), 0x0100) // 标准查询 + RD
  assert.strictEqual(query.readUInt16BE(4), 1) // QDCOUNT
  assert.strictEqual(query.readUInt16BE(10), 1) // ARCOUNT: EDNS0
  const { name, offset } = svcbUtil.decodeName(query, 12)
  assert.strictEqual(name, 'a.b.com')
  assert.strictEqual(query.readUInt16BE(offset), 65) // QTYPE = HTTPS
  assert.strictEqual(query.readUInt16BE(offset + 2), 1) // QCLASS = IN
  console.log('===> encodeQuery/decodeName 校验通过')

  // 展示格式解析（DoH JSON 接口返回的 data 字段）
  const presentation = svcbUtil.parsePresentation('1 . alpn="h2" ipv4hint="162.159.135.79,162.159.136.79" ech="AEX+DQBBigAgACClcPRSYIi9pRSXEYI2Mp1rDDKFgCgesWfIc4Sj2ogUFwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="')
  assert.strictEqual(presentation.priority, 1)
  assert.strictEqual(presentation.target, '.')
  assert.deepStrictEqual(presentation.paramMap.alpn, ['h2'])
  const config = svcbUtil.parseEchConfigList(presentation.ech)[0]
  assert.strictEqual(config.publicName, 'cloudflare-ech.com')
  assert.strictEqual(config.kemId, 0x0020) // DHKEM(X25519, HKDF-SHA256)
  assert.strictEqual(config.publicKey.length, 32)
  console.log('===> parsePresentation/parseEchConfigList 校验通过:', JSON.stringify({
    version: config.version,
    kem: config.kem,
    publicName: config.publicName,
    cipherSuites: config.cipherSuites,
  }))
}

console.log('\n--------------- test lookupEch (UDP) ---------------\n')
{
  const ech = await dns.lookupEch(dnsConfig, hostname)
  console.log(`===> ${hostname} ➜`, ech == null ? '未获取到ECH参数' : JSON.stringify({
    publicName: ech.publicName,
    kem: ech.config.kem,
    dnsName: ech.dnsName,
    dnsType: ech.dnsType,
    ttl: ech.ttl,
    echConfigListLength: ech.echConfigList.length,
  }))

  if (ech == null) {
    // 是否为DNS环境问题（如当前网络查不到该域名的HTTPS记录）导致的跳过，不做失败处理
    console.warn(`[WARN] 未获取到 ${hostname} 的ECH参数，跳过该用例（请检查当前网络的DNS是否支持查询HTTPS记录）`)
  } else {
    assert.strictEqual(ech.dnsType, 'UDP')
    assert.ok(ech.echConfigList.length > 0)
    assert.ok(ech.publicName.length > 0)

    // 第二次查询应命中缓存
    const cached = await dns.lookupEch(dnsConfig, hostname)
    assert.strictEqual(cached.echConfigList.toString('base64'), ech.echConfigList.toString('base64'))
    console.log('===> 缓存命中校验通过, echStat:', JSON.stringify(dnsProviders.aliyunUDP.echStat))
  }
}

console.log('\n--------------- test lookupEch (未下发ech参数的域名) ---------------\n')
{
  const ech = await dns.lookupEch(dnsConfig, noEchHostname)
  console.log(`===> ${noEchHostname} ➜`, ech)
  assert.strictEqual(ech, null)
  console.log('===> echStat:', JSON.stringify(dnsProviders.aliyunUDP.echStat))
}

console.log('\n--------------- test lookupEch (TLS/DoT) ---------------\n')
{
  const ech = await dnsProviders.aliyunTLS.lookupEch(hostname)
  console.log(`===> DoT ${hostname} ➜`, ech == null ? '未获取到ECH参数' : `${ech.publicName} (${ech.echConfigList.length} bytes)`)
}

console.log('\n--------------- test lookupEch (HTTPS/DoH) ---------------\n')
{
  const ech = await dnsProviders.aliyunHTTPS.lookupEch(hostname)
  console.log(`===> DoH ${hostname} ➜`, ech == null ? '未获取到ECH参数' : `${ech.publicName} (${ech.echConfigList.length} bytes)`)
}

console.log('\n--------------- test 未启用ECH时 ---------------\n')
{
  const disabled = dns.initDNS({
    aliyunUDP: { server: 'udp://223.5.5.5' },
  }, {}, { ech: { enabled: false } })
  assert.strictEqual(disabled.aliyunUDP.echEnabled, false)
  assert.strictEqual(await disabled.aliyunUDP.lookupEch(hostname), null)
  console.log('===> 关闭ECH后不发起查询，校验通过')
}

console.log('\n===> all done')

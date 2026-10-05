const http = require('node:http')
const https = require('node:https')
const net = require('node:net')
const tls = require('node:tls')
const { pipeline } = require('node:stream')
const jsonApi = require('../../../json')
const log = require('../../../utils/util.log.server')
const RequestCounter = require('../../choice/RequestCounter')
const commonUtil = require('../common/util')
// const upgradeHeader = /(^|,)\s*upgrade\s*($|,)/i
const DnsUtil = require('../../dns')
const { reportIPv6Error } = require('../../dns/base')
const compatible = require('../compatible/compatible')
const echUtil = require('../common/ech')
const InsertScriptMiddleware = require('../middleware/InsertScriptMiddleware')
const dnsLookup = require('./dnsLookup')

const MAX_SLOW_TIME = 8000 // 超过此时间 则认为太慢了
const CONNECT_TIMEOUT_MS = 7000 // 上游建连（含 TLS 握手）超时：SNI 伪装 + 跨境线路下握手可能偏慢，5s 会误杀可用 IP
// 使用上游ECH的请求：建连过程还包括查询DNS的HTTPS记录和ECH握手，需要更长的超时时间
const ECH_CONNECT_TIMEOUT = 30000
// 有 Content-Length 且未超限时可缓冲，便于安全重试（git-upload-pack 体通常很小）
const BUFFER_BODY_MAX = 2 * 1024 * 1024
const MAX_RETRY_BODY_SIZE = 1024 * 1024 // 自动重试时最多缓存 1MB 请求体，超过则跳过重试
const WWW_AUTH_HEADER_RE = /^www-authenticate$/i

// 可能携带请求体的方法；缺少 Content-Length 时无法有界缓存，禁止重试
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

// HTML 转义，防止请求可控内容写入错误页造成反射型 XSS
function escapeHtml (value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// 判断当前请求是否支持自动重试（方法可重试且请求体可有界缓存）
function canRetryWithBody (retryConfig, req) {
  const method = (req.method || 'GET').toUpperCase()
  if (!retryConfig.methods.includes(method)) {
    return false
  }

  // chunked 请求体无法在重试时重新发送，跳过重试
  if (req.headers['transfer-encoding']) {
    return false
  }

  // Expect: 100-continue 时客户端会等待确认后才发送请求体，不适合缓存重试
  if (req.headers.expect && req.headers.expect.toLowerCase().includes('100-continue')) {
    return false
  }

  if (BODY_METHODS.has(method)) {
    const contentLength = Number.parseInt(req.headers['content-length'], 10)
    // 未知长度无法有界缓存，避免无上限占用内存；超限则跳过重试
    if (!Number.isFinite(contentLength) || contentLength > MAX_RETRY_BODY_SIZE) {
      return false
    }
  }

  return true
}

// 缓存请求体，供自动重试时重新发送（有界：超过 MAX_RETRY_BODY_SIZE 则中止）
function bufferRequestBody (req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_RETRY_BODY_SIZE) {
        req.destroy()
        reject(new Error(`请求体超过重试缓存上限 ${MAX_RETRY_BODY_SIZE} bytes`))
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      resolve(Buffer.concat(chunks, size))
    })
    req.on('error', reject)
  })
}

// 日志用 rOptions 精简：agent 完整对象包含大量 socket/证书 Buffer，不能直接 JSON.stringify
function compactROptions (rOptions) {
  const agent = rOptions.agent
  let agentInfo = agent === false ? false : null
  if (agent && typeof agent === 'object') {
    agentInfo = {
      name: agent.constructor && agent.constructor.name,
      keepAlive: agent.options && agent.options.keepAlive,
      timeout: agent.options && agent.options.timeout,
      rejectUnauthorized: agent.options && agent.options.rejectUnauthorized,
      maxSockets: agent.maxSockets,
    }
  }

  return {
    protocol: rOptions.protocol,
    method: rOptions.method,
    hostname: rOptions.hostname,
    port: rOptions.port,
    path: rOptions.path,
    servername: rOptions.servername,
    family: rOptions.family,
    host: rOptions.host,
    headers: rOptions.headers,
    agent: agentInfo,
    maxHeaderSize: rOptions.maxHeaderSize,
    customSocketId: rOptions.customSocketId,
  }
}

// create requestHandler function
module.exports = function createRequestHandler (createIntercepts, middlewares, externalProxy, dnsConfig, setting, compatibleConfig) {
  // 上游ECH：只对配置中 `server.dns.ech.domains` 指定的域名生效，配置为空时返回null（保持原有行为）
  const echAgentPair = externalProxy == null
    ? echUtil.createEchAgentPair({ dnsConfig, ech: dnsConfig == null ? null : dnsConfig.ech })
    : null

  // return
  return function requestHandler (req, res, ssl) {
    let proxyReq

    // 兜底：若整个流程未写出任何响应（例如模拟器/WHPX 干扰导致上游挂起且未触发 error），
    // 超时后强制返回错误页，避免浏览器一直显示"未发送任何数据"
    let responded = false
    let emptyGuard = null
    const markResponded = () => {
      responded = true
      if (emptyGuard) {
        clearTimeout(emptyGuard)
        emptyGuard = null
      }
    }
    res.on('finish', markResponded)
    res.on('close', markResponded)
    emptyGuard = setTimeout(() => {
      if (responded || res.writableEnded)
        return
      log.error(`请求无响应，强制返回 504: ${url}`)
      try {
        if (!res.headersSent) {
          res.writeHead(504, { 'Content-Type': 'text/plain; charset=utf-8', 'DS-Error': 'empty-response-guard' })
        }
        res.end(`DevSidecar: no response from upstream\n${url}`)
      } catch {
        try {
          res.destroy()
        } catch { /* ignore */ }
      }
    }, 60000)
    emptyGuard.unref && emptyGuard.unref()

    const rOptions = commonUtil.getOptionsFromRequest(req, ssl, externalProxy, setting, compatibleConfig)
    let url = `${rOptions.method} ➜ ${rOptions.protocol}//${rOptions.hostname}:${rOptions.port}${rOptions.path}`

    if (rOptions.headers.connection === 'close') {
      req.socket && req.socket.setKeepAlive(false)
    } else if (rOptions.customSocketId != null) { // for NTLM
      req.socket && req.socket.setKeepAlive(true, 60 * 60 * 1000)
    } else {
      req.socket && req.socket.setKeepAlive(true, 30000)
    }
    const context = {
      rOptions,
      log,
      RequestCounter,
      setting,
    }
    let interceptors = createIntercepts(context)
    if (interceptors == null) {
      interceptors = []
    }
    const reqIncpts = interceptors.filter((item) => {
      return item.requestIntercept != null
    })
    const resIncpts = interceptors.filter((item) => {
      return item.responseIntercept != null
    })

    const requestInterceptorPromise = () => {
      return new Promise((resolve, reject) => {
        const next = () => {
          resolve()
        }
        try {
          if (setting.script.enabled) {
            reqIncpts.unshift(InsertScriptMiddleware)
          }
          for (const middleware of middlewares) {
            reqIncpts.push(middleware)
          }
          if (reqIncpts && reqIncpts.length > 0) {
            for (const reqIncpt of reqIncpts) {
              if (!reqIncpt.requestIntercept) {
                continue
              }
              const goNext = reqIncpt.requestIntercept(context, req, res, ssl, next)
              if (goNext) {
                if (goNext !== 'no-next') {
                  next()
                }
                return
              }
            }
            next()
          } else {
            next()
          }
        } catch (e) {
          reject(e)
        }
      })
    }

    function countSlow (isDnsIntercept, reason) {
      if (isDnsIntercept && isDnsIntercept.dns && isDnsIntercept.ip !== isDnsIntercept.hostname) {
        const { dns, ip, hostname } = isDnsIntercept
        dns.count(hostname, ip, true)
        log.error(`记录ip失败次数，用于优选ip！ hostname: ${hostname}, ip: ${ip}, reason: ${reason}, dns: ${dns.dnsName}`)
      }
      const counter = context.requestCount
      if (counter != null) {
        counter.count.doCount(counter.value, true)
        log.error(`记录Proxy请求失败次数，用于切换备选域名！ hostname: ${counter.value}, reason: ${reason}, counter.count:`, counter.count)
      }
    }

    const proxyRequestPromise = async () => {
      rOptions.host = rOptions.hostname || rOptions.host || 'localhost'
      // TLS：SNI 可按配置伪装（如 sni: baidu.com）防阻断；
      // 证书校验默认用真实域名（不能用伪装 SNI，也不能留空，否则会变成 Host: none）；
      // 但规则里显式配置了 verifyHost 时用它校验 —— 用于「换 SNI 敲门」类规则
      // （如 huggingface.co 用 huggingface.cn 的 SNI 连，服务器返回的就是 huggingface.cn 的证书）。
      if (rOptions.protocol === 'https:' && rOptions.hostname) {
        const realHost = rOptions.hostname
        if (rOptions.servername == null) {
          rOptions.servername = realHost
        }
        const verifyHost = (rOptions.verifyHost != null && rOptions.verifyHost !== '') ? rOptions.verifyHost : realHost
        if (rOptions.servername !== realHost || verifyHost !== realHost) {
          rOptions.checkServerIdentity = (_host, cert) => tls.checkServerIdentity(verifyHost, cert)
        }
      }

      // 首次发送前缓存小请求体；建连失败（SNI 伪装下偶发）时可安全重试（git-upload-pack 体通常很小）
      if (context.retryBody == null) {
        const contentLength = Number.parseInt(req.headers['content-length'], 10)
        const wantBuffer = !!context.retryConfig
          || (Number.isFinite(contentLength) && contentLength >= 0 && contentLength <= BUFFER_BODY_MAX)
        const methodsForCheck = context.retryConfig
          || { methods: [String(rOptions.method || 'GET').toUpperCase()], times: 1 }
        if (!wantBuffer) {
          // 无 body 或过大：不缓冲
        } else if (!canRetryWithBody(methodsForCheck, req)) {
          log.warn(`请求体不可安全重试，跳过缓冲: ${url}`)
          context.retryConfig = null
        } else {
          try {
            context.retryBody = await bufferRequestBody(req)
          } catch (e) {
            log.error(`缓存请求体失败，本次请求不自动重试: ${url}, error:`, e)
            context.retryConfig = null
            context.retryBody = null
            throw e
          }
        }
      }

      return new Promise((resolve, reject) => {
        // use the binded socket for NTLM
        if (rOptions.agent && rOptions.customSocketId != null && rOptions.agent.getName) {
          const socketName = rOptions.agent.getName(rOptions)
          const bindingSocket = rOptions.agent.sockets[socketName]
          if (bindingSocket && bindingSocket.length > 0) {
            bindingSocket[0].once('free', onFree)
            return
          }
        }
        onFree()

        function onFree () {
          url = `${rOptions.method} ➜ ${rOptions.protocol}//${rOptions.hostname}:${rOptions.port}${rOptions.path}`
          const start = Date.now()
          log.info('发起代理请求:', url, (rOptions.servername ? `, sni: ${rOptions.servername}` : ''), ', headers:', jsonApi.stringify2(rOptions.headers))

          const isDnsIntercept = {}
          let dnsHeaderLabel = null
          if (rOptions.hostname && net.isIP(rOptions.hostname)) {
            // 请求地址本身就是 IP 时，不会触发 DNS lookup，直接写入响应头
            res.setHeader('DS-DNS', `host: ${rOptions.hostname}`)
          } else if (dnsConfig && dnsConfig.dnsMap) {
            // ECH域名：默认强制忽略预设IP与IP测速结果，优先从ECH指定的DNS（未指定时为域名映射的DNS）解析，
            // 解析不出可用IP时由 dnsLookup 回退到预设IP；`server.dns.ech.preSetIpDomains` 里的域名例外则强制优先使用预设IP
            const isEchDomain = DnsUtil.isEchDomain(dnsConfig, rOptions.hostname)
            const ignorePreSetIp = isEchDomain && DnsUtil.isEchIgnorePreSetIp(dnsConfig, rOptions.hostname)
            let dnsAndFamily = DnsUtil.getDNSAndFamily(dnsConfig, rOptions.hostname)
            if (!dnsAndFamily && rOptions.servername && !isEchDomain) {
              const dns = dnsConfig.dnsMap.ForSNI
              if (dns) {
                dnsAndFamily = { dns }
                log.info(`域名 ${rOptions.hostname} 在dns中未配置，但使用了 sni: ${rOptions.servername}, 必须使用dns，现默认使用 '${dnsAndFamily.dnsName}' DNS.`)
              } else {
                log.warn(`域名 ${rOptions.hostname} 在dns中未配置，但使用了 sni: ${rOptions.servername}，然而DNS服务管理中，并未指定SNI默认使用的DNS。`)
              }
            }
            if (dnsAndFamily) {
              rOptions.lookup = dnsLookup.createLookupFunc(res, dnsAndFamily, 'request url', url, rOptions.port, isDnsIntercept, {
                ignorePreSetIpList: ignorePreSetIp,
                // ECH域名不做IP测速：测速只比较TCP连接耗时，选出的「最快IP」未必能完成ECH握手或数据面传输，
                // 会把请求长期固定在一个坏IP上（测速结果有缓存，而 countEchIp 的ECH失败反馈改不了它）。
                // 关闭测速后由「预设IP」缓存的 value 决定，并能被ECH失败反馈逐个切换IP。
                ignoreSpeedTest: isEchDomain,
                // ECH域名：ECH专用DNS解析不出可用IP时回退到预设IP，并在缓存退化为域名兜底项时重新尝试真实IP
                resetOnHostnameFallback: isEchDomain,
                preSetDns: ignorePreSetIp ? dnsConfig.dnsMap.PreSet : null,
              })
              if (dnsAndFamily.family === 6) {
                rOptions.family = 6
              }
              log.debug(`域名 ${rOptions.hostname} DNS: ${dnsAndFamily.dns.dnsName}, family: ${rOptions.family || 4}`)
              dnsHeaderLabel = dnsAndFamily.dns.dnsName === '预设IP' ? 'PreSet' : dnsAndFamily.dns.dnsName.replace(/[^\x20-\x7E]/g, '')
              res.setHeader('DS-DNS', dnsHeaderLabel)
            } else {
              // 未配置自定义 DNS，使用系统默认 DNS，并捕获 IP 写入响应头
              rOptions.lookup = dnsLookup.createDefaultLookupFunc(res, 'request url', url)
              dnsHeaderLabel = 'default'
              res.setHeader('DS-DNS', dnsHeaderLabel)
              log.info(`域名 ${rOptions.hostname} 在DNS中未配置，使用系统默认DNS`)
            }
          } else {
            rOptions.lookup = dnsLookup.createDefaultLookupFunc(res, 'request url', url)
            dnsHeaderLabel = 'default'
            res.setHeader('DS-DNS', dnsHeaderLabel)
            log.info(`域名 ${rOptions.hostname} DNS配置不存在，使用系统默认DNS`)
          }

          // rOptions.sigalgs = 'RSA-PSS+SHA256:RSA-PSS+SHA512:ECDSA+SHA256'
          // rOptions.agent.options.sigalgs = rOptions.sigalgs
          // rOptions.ciphers = 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES256-SHA256:HIGH'
          // rOptions.agent.options.ciphers = rOptions.ciphers
          // log.debug('rOptions:', rOptions.hostname + rOptions.path, '\r\n', rOptions)
          // log.debug('agent:', rOptions.agent)
          // log.debug('agent.options:', rOptions.agent.options)
          res.setHeader('DS-Proxy-Request', `${rOptions.protocol}//${rOptions.hostname}:${rOptions.port}${rOptions.path || req.url}`)

          // 自动兼容程序：2
          if (rOptions.agent) {
            const compatibleConfig = compatible.getRequestCompatibleConfig(rOptions, rOptions.compatibleConfig)
            if (compatibleConfig && compatibleConfig.rejectUnauthorized != null && rOptions.agent.options.rejectUnauthorized !== compatibleConfig.rejectUnauthorized) {
              if (compatibleConfig.rejectUnauthorized === false && rOptions.agent.unVerifySslAgent) {
                log.info(`【自动兼容程序】${rOptions.hostname}:${rOptions.port}: 设置 'rOptions.agent.options.rejectUnauthorized = ${compatibleConfig.rejectUnauthorized}'`)
                rOptions.agent = rOptions.agent.unVerifySslAgent
                res.setHeader('DS-Compatible', 'unVerifySsl')
              }
            }
          }

          // 上游ECH：指定域名在TLS握手时使用DNS下发的ECH参数（失败自动回退原生TLS）
          let isEchRequest = false
          if (echAgentPair != null && rOptions.protocol === 'https:' && typeof rOptions.agent === 'object' && rOptions.agent != null && echAgentPair.match(rOptions.hostname)) {
            isEchRequest = true
            rOptions.agent = echAgentPair.wrap(rOptions.agent)
          }

          res.setHeader('DS-Proxy-Request-Family', rOptions.family || 4)
          // 响应已开始后禁止再 destroy 上游（否则会掐断流式响应）
          let responseStarted = false
          proxyReq = (rOptions.protocol === 'https:' ? https : http).request(rOptions, (proxyRes) => {
            const cost = Date.now() - start
            if (rOptions.protocol === 'https:') {
              log.info(`代理请求返回: 【${proxyRes.statusCode}】${url}, cost: ${cost} ms`)
            } else {
              log.info(`请求返回: 【${proxyRes.statusCode}】${url}, cost: ${cost} ms`)
            }

            // 按需探测反馈：IP 连接成功
            if (isDnsIntercept && isDnsIntercept.tester) {
              isDnsIntercept.tester.reportProbeResult(isDnsIntercept.ip, true)
            }
            // log.info('request:', proxyReq, proxyReq.socket)

            if (cost > MAX_SLOW_TIME) {
              countSlow(isDnsIntercept, `代理请求成功但太慢, cost: ${cost} ms > ${MAX_SLOW_TIME} ms`)
            }

            // 已收到响应头：关掉请求级空闲超时，避免长流式（Gemini/SSE）中途被掐断
            responseStarted = true
            try {
              proxyReq.setTimeout(0)
            } catch {
              // ignore
            }

            resolve(proxyRes)
          })

          // 代理请求的事件监听
          // 建连计时器：只在「已经分配 socket 且仍 connecting」时生效。
          // 否则请求可能还在 agent 连接池排队，误 destroy 会导致 git 多连接时 ECONNRESET。
          let connectionTimer = null
          const clearConnectTimer = () => {
            if (connectionTimer) {
              clearTimeout(connectionTimer)
              connectionTimer = null
            }
          }
          const startConnectTimer = () => {
            if (connectionTimer) {
              return
            }
            connectionTimer = setTimeout(() => {
              connectionTimer = null
              const sock = proxyReq.socket
              if (!sock || !sock.connecting) {
                // 尚未拿到 socket（排队中）或已连上：不要杀连接
                return
              }
              if (isDnsIntercept && isDnsIntercept.tester && isDnsIntercept.ip) {
                isDnsIntercept.tester.reportProbeResult(isDnsIntercept.ip, false)
              }
              const cost = Date.now() - start
              const targetIp = (proxyReq.socket && proxyReq.socket.remoteAddress) || (isDnsIntercept && isDnsIntercept.ip) || ''
              const testerState = isDnsIntercept && isDnsIntercept.tester && isDnsIntercept.tester.getDebugState
                ? isDnsIntercept.tester.getDebugState()
                : null
              const errorMsg = `连接超时: ${url}, cost: ${cost} ms, targetIp: ${targetIp || 'unknown'}`
              log.error(errorMsg, ', rOptions:', jsonApi.stringify2(compactROptions(rOptions)), ', dnsState:', jsonApi.stringify2(testerState))
              countSlow(isDnsIntercept, `连接超时, cost: ${cost} ms`)
              const error = new Error(errorMsg)
              error.retryable = true
              proxyReq.destroy(error)
            }, isEchRequest ? ECH_CONNECT_TIMEOUT : CONNECT_TIMEOUT_MS)
          }
          proxyReq.once('socket', (socket) => {
            // 上游ECH：让调用方能在浏览器F12里看到这次请求是否真的用上了ECH
            //  - `DS-ECH: 1` 表示ECH握手成功（SNI已加密）
            //  - `DS-ECH: 0` 表示该域名在ECH名单中，但本次未能使用ECH（目标站未下发ECH记录、握手失败或已回退原生TLS）
            if (isEchRequest && res && !res.headersSent) {
              res.setHeader('DS-ECH', socket.echAccepted === true ? '1' : '0')
            }
            const updateDsDnsFromSocket = () => {
              if (res && !res.headersSent && dnsHeaderLabel && socket.remoteAddress) {
                let family = socket.remoteFamily
                if (family === 'IPv4') {
                  family = 4
                } else if (family === 'IPv6') {
                  family = 6
                } else {
                  family = net.isIP(socket.remoteAddress) === 6 ? 6 : 4
                }
                res.setHeader('DS-DNS', `${dnsHeaderLabel}: ${socket.remoteAddress} (IPv${family})`)
              }
            }
            updateDsDnsFromSocket()
            if (socket.connecting) {
              startConnectTimer()
              socket.once('connect', () => {
                clearConnectTimer()
                updateDsDnsFromSocket()
              })
            } else {
              // keep-alive 复用 socket
              clearConnectTimer()
            }
            socket.once('close', clearConnectTimer)
          })

          proxyReq.on('timeout', () => {
            clearConnectTimer()
            if (responseStarted) {
              // 流式响应传输中：超时只记录，不拆连接
              log.warn(`代理请求传输中超时（已忽略）: ${url}`)
              return
            }
            const cost = Date.now() - start
            const errorMsg = `代理请求超时: ${url}, cost: ${cost} ms`
            log.error(errorMsg, ', rOptions:', jsonApi.stringify2(compactROptions(rOptions)))
            countSlow(isDnsIntercept, `代理请求超时, cost: ${cost} ms`)
            proxyReq.end()
            proxyReq.destroy()
            const error = new Error(errorMsg)
            error.code = 'ETIMEOUT'
            error.status = 408
            error.retryable = true
            reject(error)
          })
          proxyReq.on('error', (e) => {
            if (connectionTimer) {
              clearTimeout(connectionTimer)
              connectionTimer = null
            }
            if (isDnsIntercept && isDnsIntercept.tester && isDnsIntercept.ip) {
              isDnsIntercept.tester.reportProbeResult(isDnsIntercept.ip, false)
            }
            const cost = Date.now() - start
            log.error(`代理请求错误: ${url}, cost: ${cost} ms, error:`, e, ', rOptions:', jsonApi.stringify2(compactROptions(rOptions)))
            countSlow(isDnsIntercept, `代理请求错误: ${e.message}`)
            if (e.code === 'ENETUNREACH' && isDnsIntercept && isDnsIntercept.ip) {
              reportIPv6Error(isDnsIntercept.ip)
            }
            e.retryable = true
            reject(e)

            // 自动兼容程序：2
            if (e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
              compatible.setRequestRejectUnauthorized(rOptions, false)
            }
          })
          proxyReq.on('aborted', () => {
            const cost = Date.now() - start
            const errorMsg = `代理请求被取消: ${url}, cost: ${cost} ms`
            log.error(errorMsg, ', rOptions:', jsonApi.stringify2(compactROptions(rOptions)))

            if (cost > MAX_SLOW_TIME) {
              countSlow(isDnsIntercept, `代理请求被取消，且请求太慢, cost: ${cost} ms > ${MAX_SLOW_TIME} ms`)
            }

            if (res.writableEnded) {
              return
            }
            reject(new Error(errorMsg))
          })

          // 设置代理请求超时（避免请求无限挂起）
          // agent.options.timeout 是连接池空闲超时（20s），不适合直接用作请求超时。
          // request timeout 是 socket 空闲超时：socket 上多久无数据即判定超时。
          // 部分站点响应慢（如 Google Cloud），默认 60 秒，最小 10 秒。
          const agentTimeout = (rOptions.agent && rOptions.agent.options && rOptions.agent.options.timeout) || 30000
          const reqTimeout = Math.max(agentTimeout * 2, 10000)
          proxyReq.setTimeout(reqTimeout)

          // 原始请求的事件监听
          req.on('aborted', () => {
            const cost = Date.now() - start
            const errorMsg = `请求被取消: ${url}, cost: ${cost} ms`
            log.error(errorMsg, ', rOptions:', jsonApi.stringify2(compactROptions(rOptions)))
            proxyReq.destroy()
            if (res.writableEnded) {
              return
            }
            reject(new Error(errorMsg))
          })
          req.on('error', (e) => {
            const cost = Date.now() - start
            log.error(`请求错误: ${url}, cost: ${cost} ms, error:`, e, ', rOptions:', jsonApi.stringify2(compactROptions(rOptions)))
            reject(e)
          })
          req.on('timeout', () => {
            const cost = Date.now() - start
            const errorMsg = `请求超时: ${url}, cost: ${cost} ms`
            log.error(errorMsg, ', rOptions:', jsonApi.stringify2(compactROptions(rOptions)))
            reject(new Error(errorMsg))
          })
          if (context.retryBody != null) {
            // 已缓存请求体（用于自动重试），直接写入
            if (context.retryBody.length > 0) {
              proxyReq.write(context.retryBody)
            }
            proxyReq.end()
          } else {
            req.pipe(proxyReq)
          }
        }
      })
    }

    // workflow control
    (async () => {
      await requestInterceptorPromise()

      if (res.writableEnded) {
        // log.info('res is writableEnded, return false')
        return false
      }

      // 每次循环读取 context.retryConfig：proxyRequestPromise 内校验失败会将其置空，
      // 避免本地快照仍非空导致 POST/无 Content-Length 请求被空体重试
      let retryCount = 0
      let proxyRes
      while (true) {
        try {
          proxyRes = await proxyRequestPromise()
        } catch (e) {
          // 仅当请求体已完整缓冲时才允许重试；否则管道已发出，重试会变空体
          const bodySafe = context.retryBody != null
          const retryLimit = context.retryConfig
            ? context.retryConfig.times
            : (bodySafe || (rOptions.method || 'GET').toUpperCase() === 'GET' ? 1 : 0)
          const canAutoRetry = e && e.retryable
          if (canAutoRetry && retryCount < retryLimit) {
            retryCount++
            context.retryCount = retryCount
            res.setHeader('DS-Retry', String(retryCount))
            log.warn(`请求失败，自动重试 (${retryCount}/${retryLimit}): ${url}, error: ${e.code || e.message}`)
            continue
          }
          throw e
        }

        // 收到配置的状态码（默认 500）时自动重试
        if (context.retryConfig && retryCount < context.retryConfig.times && context.retryConfig.statuses.includes(proxyRes.statusCode)) {
          retryCount++
          context.retryCount = retryCount
          res.setHeader('DS-Retry', String(retryCount))
          log.warn(`收到 ${proxyRes.statusCode} 响应，自动重试 (${retryCount}/${context.retryConfig.times}): ${url}`)
          proxyRes.on('error', () => {})
          proxyRes.resume()
          continue
        }
        break
      }

      // proxyRes.on('data', (chunk) => {
      //   // log.info('BODY: ')
      // })
      proxyRes.on('error', (error) => {
        countSlow(null, `error: ${error.message}`)
        log.error(`proxy res error: ${url}, error:`, error)
        // 流式响应中途失败时必须收尾，否则浏览器会一直停在“生成中/回答中”
        if (!res.writableEnded) {
          try {
            res.destroy(error)
          } catch {
            // ignore
          }
        }
      })
      proxyRes.on('aborted', () => {
        if (!res.writableEnded) {
          try {
            res.destroy()
          } catch {
            // ignore
          }
        }
      })

      const responseInterceptorPromise = new Promise((resolve, reject) => {
        const next = () => {
          resolve()
        }
        for (const middleware of middlewares) {
          if (middleware.responseInterceptor) {
            middleware.responseInterceptor(req, res, proxyReq, proxyRes, ssl, next)
          }
        }
        if (!setting.script.enabled) {
          next()
          return
        }
        try {
          if (resIncpts && resIncpts.length > 0) {
            let head = ''
            let body = ''
            for (const resIncpt of resIncpts) {
              const append = resIncpt.responseIntercept(context, req, res, proxyReq, proxyRes, ssl, next)
              // 判断是否已经关闭
              if (res.writableEnded) {
                next()
                return
              }
              if (append) {
                if (append.head) {
                  head += append.head
                }
                if (append.body) {
                  body += append.body
                }
              } else if (append === false) {
                break // 返回false表示终止拦截器，跳出循环
              }
            }
            InsertScriptMiddleware.responseInterceptor(req, res, proxyReq, proxyRes, ssl, next, {
              head,
              body,
            })
          } else {
            next()
          }
        } catch (e) {
          reject(e)
        }
      })

      await responseInterceptorPromise

      if (!res.headersSent) { // prevent duplicate set headers
        // HTTP/2 禁止头，上游服务器可能返回，直传会导致 http2 模块抛异常
        const HTTP2_FORBIDDEN = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'http2-settings'])
        Object.keys(proxyRes.headers).forEach((key) => {
          if (proxyRes.headers[key] !== undefined) {
            // https://github.com/nodejitsu/node-http-proxy/issues/362
            if (WWW_AUTH_HEADER_RE.test(key)) {
              if (proxyRes.headers[key]) {
                proxyRes.headers[key] = proxyRes.headers[key] && proxyRes.headers[key].split(',')
              }
              key = 'www-authenticate'
            }
            if (HTTP2_FORBIDDEN.has(key)) {
              return
            }
            res.setHeader(key, proxyRes.headers[key])
          }
        })

        if (proxyRes.statusCode >= 400) {
          countSlow(null, `Status return: ${proxyRes.statusCode}`)
        }
        res.writeHead(proxyRes.statusCode)
        // pipeline：任一端出错都会正确销毁两端，避免流式响应悬挂导致前端一直“回答中”
        pipeline(proxyRes, res, (err) => {
          if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
            log.warn(`响应流结束异常: ${url}, error:`, err.message)
          }
        })
      }
    })().catch((e) => {
      if (!res.writableEnded) {
        try {
          const status = e.status || 500
          const errorMsg = `目标网站请求错误：【${e.code || (e.status || 'UNKNOWN')}】 ${e.message}`
          const retryInfo = context.retryCount > 0 ? `自动重试：已尝试 ${context.retryCount} 次` : ''
          const target = `目标地址：${rOptions.protocol}//${rOptions.hostname}:${rOptions.port}${rOptions.path}`

          // 内容协商：
          // 1) 浏览器导航（document/iframe）→ HTML 统一样式错误页（黑底白字），动态值需转义防 XSS
          // 2) 明确要 JSON 的客户端 → application/json，避免把 HTML/text 当 JSON 解析失败
          // 3) 图片/脚本等 no-cors 子资源 → text/plain，避免被 Chromium ORB 拦截
          const accept = req.headers.accept || ''
          const secFetchDest = req.headers['sec-fetch-dest'] || ''
          const acceptsHtml = accept.includes('text/html') || secFetchDest === 'document' || secFetchDest === 'iframe'
          // 明确声明要 JSON，或典型 XHR API 调用（非文档/子资源）时返回 JSON
          const isAssetDest = secFetchDest === 'image'
            || secFetchDest === 'script'
            || secFetchDest === 'style'
            || secFetchDest === 'font'
            || secFetchDest === 'audio'
            || secFetchDest === 'video'
          const acceptsJson = !acceptsHtml && !isAssetDest && (
            accept.includes('application/json')
            || req.headers['x-requested-with'] === 'XMLHttpRequest'
          )
          const headers = {
            'Content-Type': acceptsHtml
              ? 'text/html;charset=UTF8'
              : acceptsJson
                ? 'application/json; charset=utf-8'
                : 'text/plain; charset=utf-8',
          }

          // 跨域读取错误正文：反射 Origin 即可。
          // 禁止同时设置 Allow-Credentials: true，否则任意站点可带凭据读响应（CodeQL high）。
          const requestOrigin = rOptions.headers.origin
          if (requestOrigin) {
            headers['Access-Control-Allow-Origin'] = requestOrigin
            headers.Vary = 'Origin'
          }

          res.writeHead(status, headers)

          if (acceptsHtml) {
            // 动态值必须转义，避免 hostname/path/e.message 写成可执行标记
            res.write(`<style>
              p {
                margin: 10px 0;
                color: white;
                background-color: black;
              }
            </style>
            <p>DevSidecar Error:</p>
            <p>${escapeHtml(errorMsg)}</p>
            ${retryInfo ? `<p>${escapeHtml(retryInfo)}</p>` : ''}
            <p>${escapeHtml(target)}</p>`,
            )
          } else if (acceptsJson) {
            res.write(JSON.stringify({
              error: 'DevSidecar Error',
              message: errorMsg,
              code: e.code || e.status || 'UNKNOWN',
              target,
              ...(retryInfo ? { retryInfo } : {}),
            }))
          } else {
            res.write(`DevSidecar Error:\n${errorMsg}\n${retryInfo ? `${retryInfo}\n` : ''}${target}`)
          }
        } catch {
          // do nothing
        }

        try {
          res.end()
        } catch {
          // do nothing
        }

        // region 忽略部分已经打印过ERROR日志的错误
        if (e.message) {
          const ignoreErrors = [
            '代理请求错误: ',
            '代理请求超时: ',
            '代理请求被取消: ',
          ]
          for (const ignoreError of ignoreErrors) {
            if (e.message.startsWith(ignoreError)) {
              return
            }
          }
        }
        // endregion

        log.error(`Request error: ${url}, error:`, e)
      }
    })
  }
}

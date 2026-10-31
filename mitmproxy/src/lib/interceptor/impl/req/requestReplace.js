const REMOVE = '[remove]'

// 支持 ${env:NAME} 占位：用于不落盘的秘密（如 Xget 的 CF Access 服务令牌）。
// 占位符在发请求时解析；环境变量缺失或为空时解析成空串，下面的逻辑会跳过/删除该请求头。
// 注：用拼接构造前缀与正则，避免 eslint 的 no-template-curly-in-string 误报。
const ENV_PLACEHOLDER_PREFIX = '$' + '{env:'
const ENV_PLACEHOLDER_RE = /\$\{env:([A-Za-z_]\w*)\}/g

function resolveEnvPlaceholders (value) {
  if (typeof value !== 'string' || !value.includes(ENV_PLACEHOLDER_PREFIX)) {
    return value
  }
  return value.replace(ENV_PLACEHOLDER_RE, (_, name) => process.env[name] || '')
}

const DS_DOWNLOAD_CHECK_RE = /DS_DOWNLOAD/i
const DS_DOWNLOAD_STRIP_RE = /[?&/]?DS_DOWNLOAD(=[^?&/]+)?$/i

function replaceRequestHeaders (rOptions, headers, log) {
  for (const key in headers) {
    let value = resolveEnvPlaceholders(headers[key])
    if (value === REMOVE) {
      value = null
    }

    if (value) {
      log.debug(`[DS-RequestReplace-Interceptor] replace '${key}': '${rOptions.headers[key.toLowerCase()]}' -> '${value}'`)
      rOptions.headers[key.toLowerCase()] = value
    } else if (rOptions.headers[key.toLowerCase()]) {
      log.debug(`[DS-RequestReplace-Interceptor] remove '${key}': '${rOptions.headers[key.toLowerCase()]}'`)
      delete rOptions.headers[key.toLowerCase()]
    }
  }

  log.debug(`[DS-RequestReplace-Interceptor] 最终headers: \r\n${JSON.stringify(rOptions.headers, null, '\t')}`)
}

module.exports = {
  name: 'requestReplace',
  priority: 111,
  requestIntercept (context, interceptOpt, req, res, ssl, next) {
    const { rOptions, log } = context

    const requestReplaceConfig = interceptOpt.requestReplace

    let actions = ''

    // 替换请求头
    if (requestReplaceConfig.headers) {
      replaceRequestHeaders(rOptions, requestReplaceConfig.headers, log)
      actions += `${actions ? ',' : ''}headers`
    }

    // 替换下载文件请求的请求地址（此功能主要是为了方便拦截配置）
    // 注：要转换为下载请求，需要 responseReplace 拦截器的配合使用。
    if (requestReplaceConfig.doDownload && DS_DOWNLOAD_CHECK_RE.test(rOptions.path)) {
      rOptions.doDownload = true
      rOptions.path = rOptions.path.replace(DS_DOWNLOAD_STRIP_RE, '')
      actions += `${actions ? ',' : ''}path:remove-DS_DOWNLOAD`
    }

    res.setHeader('DS-RequestReplace-Interceptor', actions)

    const url = `${rOptions.method} ➜ ${rOptions.protocol}//${rOptions.hostname}:${rOptions.port}${req.url}`
    log.info('requestReplace intercept:', url)
  },
  is (interceptOpt) {
    return !!interceptOpt.requestReplace
  },
}

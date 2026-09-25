/**
 * 日志脱敏：凭据永远打码；默认只保留 host，详细模式才保留 path（query 仍打码）。
 * 开关：DEV_SIDECAR_LOG_DETAIL=true 或配置 app.logDetail
 */
const SECRET_QUERY_KEYS = /([?&](?:token|password|passwd|pwd|secret|key|code|auth|signature|sig|access_token)=)[^&\s]+/gi
const AUTH_HEADER = /((?:proxy-)?authorization\s*[:=]\s*)\S+/gi
const PASSWORD_KV = /((?:dspassword|password|passwd|token|secret|privateKey|private_key)\s*[:=]\s*)\S+/gi
const DS_BLOB = /\b(ds-(?:p2p|card):\/\/)[A-Za-z0-9._-]+/g

function isDetail () {
  return process.env.DEV_SIDECAR_LOG_DETAIL === 'true'
}

function redactUrl (url) {
  try {
    const u = new URL(url)
    if (!isDetail()) {
      // 默认：只留 scheme://host[:port]
      return `${u.protocol}//${u.host}`
    }
    // 详细：保留 path，去掉 query/hash 中的敏感值
    return `${u.protocol}//${u.host}${u.pathname}`
  } catch {
    return url
  }
}

function shortNodeId (id) {
  const s = String(id || '')
  return s.length > 12 ? `${s.slice(0, 8)}…` : s
}

function redactText (text) {
  if (text == null) {
    return text
  }
  let s = String(text)
  // nodeId（sha256 base64url 约 43 字符）等长指纹缩写
  s = s.replace(/\b[A-Za-z0-9_-]{32,}\b/g, (m) => shortNodeId(m))
  s = s.replace(DS_BLOB, '$1***')
  s = s.replace(AUTH_HEADER, '$1***')
  s = s.replace(SECRET_QUERY_KEYS, '$1***')
  s = s.replace(PASSWORD_KV, '$1***')
  // 任意绝对 URL
  s = s.replace(/\bhttps?:\/\/[^\s"'<>]+/gi, (m) => redactUrl(m))
  return s
}

function redactArg (arg) {
  if (typeof arg === 'string') {
    return redactText(arg)
  }
  if (arg instanceof Error) {
    const e = new Error(redactText(arg.message))
    e.name = arg.name
    if (arg.stack) {
      e.stack = redactText(arg.stack)
    }
    return e
  }
  if (arg && typeof arg === 'object') {
    try {
      return JSON.parse(redactText(JSON.stringify(arg)))
    } catch {
      return arg
    }
  }
  return arg
}

function wrapLogger (logger) {
  if (!logger || logger.__redacted) {
    return logger
  }
  const wrapLevel = (level) => (...args) => {
    try {
      logger[level](...args.map(redactArg))
    } catch {
      logger[level](...args)
    }
  }
  const wrapped = {
    debug: wrapLevel('debug'),
    info: wrapLevel('info'),
    warn: wrapLevel('warn'),
    error: wrapLevel('error'),
    level: logger.level,
    category: logger.category,
    __redacted: true,
  }
  return wrapped
}

module.exports = {
  redactText,
  redactArg,
  wrapLogger,
  isDetail,
}

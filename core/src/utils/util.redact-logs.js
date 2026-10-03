/**
 * 对已有日志做一次性脱敏（含 log4js 轮转出的 .gz）。
 */
const fs = require('node:fs')
const path = require('node:path')
const zlib = require('node:zlib')
const { redactText } = require('./util.redact')

function redactTextContent (raw) {
  return raw
    .split(/\r?\n/)
    .map((line) => redactText(line))
    .join('\n')
}

function redactPlainFile (filePath) {
  const raw = fs.readFileSync(filePath, 'utf8')
  const next = redactTextContent(raw)
  if (next !== raw) {
    fs.writeFileSync(filePath, next, 'utf8')
    return true
  }
  return false
}

function redactGzipFile (filePath) {
  const raw = zlib.gunzipSync(fs.readFileSync(filePath)).toString('utf8')
  const next = redactTextContent(raw)
  if (next === raw) {
    return false
  }
  fs.writeFileSync(filePath, zlib.gzipSync(Buffer.from(next, 'utf8')))
  return true
}

function redactLogFile (filePath) {
  if (/\.gz$/i.test(filePath)) {
    return redactGzipFile(filePath)
  }
  return redactPlainFile(filePath)
}

function redactLogDir (dir) {
  if (!dir || !fs.existsSync(dir)) {
    return { files: 0, changed: 0 }
  }
  let files = 0
  let changed = 0
  const walk = (d) => {
    for (const name of fs.readdirSync(d)) {
      const full = path.join(d, name)
      let st
      try {
        st = fs.statSync(full)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        walk(full)
        continue
      }
      if (!/\.(log|txt)(\.gz)?$/i.test(name) && !/\.log\.\d+(\.gz)?$/i.test(name)) {
        continue
      }
      try {
        files++
        if (redactLogFile(full)) {
          changed++
        }
      } catch {
        // skip
      }
    }
  }
  walk(dir)
  return { files, changed }
}

module.exports = {
  redactLogFile,
  redactLogDir,
}

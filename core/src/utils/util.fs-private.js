/**
 * 敏感文件写入：尽量收紧为「仅当前用户可读写」。
 * POSIX 用 0600 创建，并对已存在的文件补一次 chmod；Windows 忽略 mode（用户目录 ACL 已限制访问）。
 */
const fs = require('node:fs')

function writeFilePrivate (file, data) {
  fs.writeFileSync(file, data, { encoding: 'utf8', mode: 0o600 })
  if (process.platform !== 'win32') {
    try {
      fs.chmodSync(file, 0o600)
    } catch {
      // 无权限时忽略：文件已写入，权限由 umask 决定
    }
  }
}

module.exports = {
  writeFilePrivate,
}

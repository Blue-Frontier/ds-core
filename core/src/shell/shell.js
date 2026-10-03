const childProcess = require('node:child_process')
const os = require('node:os')
const fixPath = require('fix-path')
const PowerShell = require('node-powershell')
const log = require('../utils/util.log.core')

fixPath()

class SystemShell {
  static async exec (cmds, args) {
    throw new Error('You have to implement the method exec!')
  }
}

class LinuxSystemShell extends SystemShell {
  static async exec (cmds) {
    if (typeof cmds === 'string') {
      cmds = [cmds]
    }
    // 共用一个 bash：多条命令拼进同一次 shell
    const body = cmds.map(c => String(c).trim()).filter(Boolean).join(' && ')
    if (body) {
      await childExec(body, { shell: '/bin/bash' })
    }
  }
}

class DarwinSystemShell extends SystemShell {
  static async exec (cmds) {
    if (typeof cmds === 'string') {
      cmds = [cmds]
    }
    const body = cmds.map(c => String(c).trim()).filter(Boolean).join(' && ')
    if (body) {
      return await childExec(body)
    }
  }
}

class WindowsSystemShell extends SystemShell {
  static async exec (cmds, args = { }) {
    let { type } = args
    type = type || 'ps'
    if (typeof cmds === 'string') {
      cmds = [cmds]
    }
    if (type === 'ps') {
      // 共用一个 PowerShell 会话跑完所有命令
      const ps = new PowerShell({
        executionPolicy: 'Bypass',
        noProfile: true,
      })

      for (const cmd of cmds) {
        ps.addCommand(cmd)
      }

      try {
        return await ps.invoke()
      } finally {
        ps.dispose()
      }
    } else {
      // 共用一个 cmd.exe：chcp + 全部命令拼进同一次 /c，避免 N 次进程创建
      const body = cmds
        .map(cmd => String(cmd).trim())
        .filter(Boolean)
        .join(' && ')
      const merged = body ? `chcp 65001 >nul & ${body}` : 'chcp 65001 >nul'
      return await childExecCmdWindows(merged, args)
    }
  }
}

function childExecCmdWindows (cmd, options = {}) {
  return new Promise((resolve, reject) => {
    const execOptions = { ...options, encoding: 'buffer' }
    delete execOptions.type
    delete execOptions.printErrorLog

    log.info('shell:', cmd)
    childProcess.execFile('cmd.exe', ['/d', '/s', '/c', cmd], execOptions, (error, stdout, stderr) => {
      // 解码输出：CMD 在 chcp 65001 后通常输出 UTF-8，
      // 但内置错误消息可能仍是系统编码（中文 Windows 为 GBK）
      const stdoutStr = _decodeBuffer(stdout)
      if (error) {
        const stderrStr = _decodeBuffer(stderr)
        if (options.printErrorLog !== false) {
          log.error('cmd 命令执行错误：\n===>\ncommands:', cmd, '\n   error:', error, '\n   stderr:', stderrStr, '\n<===')
        }
        reject(new Error(stderrStr || error.message))
      } else {
        resolve(stdoutStr.replace('Active code page: 65001\r\n', ''))
      }
    })
  })
}

/**
 * 解码 Buffer：先尝试 UTF-8，如果包含乱码则尝试 GBK（中文 Windows 控制台编码）
 */
function _decodeBuffer (buf) {
  if (!buf || buf.length === 0) {
    return ''
  }
  const utf8 = buf.toString('utf8')
  // 如果 UTF-8 解码结果包含替换字符（U+FFFD），说明原始数据不是 UTF-8
  if (utf8.includes('�')) {
    try {
      // 尝试 GBK 解码（Windows 中文系统控制台默认编码）
      return new TextDecoder('gbk', { fatal: true }).decode(buf)
    } catch {
      // GBK 解码失败，回退到 latin1 保留原始字节
      return buf.toString('latin1')
    }
  }
  return utf8
}

function childExec (composeCmds, options = {}) {
  return new Promise((resolve, reject) => {
    log.info('shell:', composeCmds)
    childProcess.exec(composeCmds, options, (error, stdout, stderr) => {
      if (error) {
        if (options.printErrorLog !== false) {
          log.error('cmd 命令执行错误：\n===>\ncommands:', composeCmds, '\n   error:', error, '\n<===')
        }
        const err = new Error(`${stderr || error.message} (command: ${composeCmds})`)
        err.code = error.code
        reject(err)
      } else {
        // log.info('cmd 命令完成：', stdout)
        resolve(stdout.replace('Active code page: 65001\r\n', ''))
      }
      // log.info('关闭 cmd')
      // ps.kill('SIGINT')
    })
  })
}

function getSystemShell () {
  switch (getSystemPlatform(true)) {
    case 'mac':
      return DarwinSystemShell
    case 'linux':
      return LinuxSystemShell
    case 'windows':
      return WindowsSystemShell
    default:
      throw new Error(`UNKNOWN OS TYPE ${os.platform()}`)
  }
}

function getSystemPlatform (throwIfUnknown = false) {
  switch (os.platform()) {
    case 'darwin':
      return 'mac'
    case 'linux':
      return 'linux'
    case 'win32':
      return 'windows'
    case 'win64':
      return 'windows'
    default:
      log.error(`UNKNOWN OS TYPE: ${os.platform()}`)
      if (throwIfUnknown) {
        throw new Error(`UNKNOWN OS TYPE '${os.platform()}'`)
      } else {
        return 'unknown-os'
      }
  }
}

async function execute (executor, args) {
  return executor[getSystemPlatform(true)](getSystemShell().exec, args)
}

async function execFile (file, args, options) {
  return new Promise((resolve, reject) => {
    try {
      childProcess.execFile(file, args, options, (err, stdout) => {
        if (err) {
          log.error('文件执行出错：', file, err)
          reject(err)
          return
        }
        log.debug('文件执行成功：', file)
        resolve(stdout)
      })
    } catch (e) {
      log.error('文件执行出错：', file, e)
      reject(e)
    }
  })
}

module.exports = {
  getSystemShell,
  getSystemPlatform,
  execute,
  execFile,
}

const fs = require('node:fs')
const sudoPrompt = require('@vscode/sudo-prompt')
const log = require('../../utils/util.log.core')
const Shell = require('../shell')

const execute = Shell.execute

function assertCert (certPath) {
  if (!certPath) {
    throw new Error('证书路径为空，无法安装根证书。请确认证书文件已生成。')
  }
  if (!fs.existsSync(certPath)) {
    throw new Error(`证书文件不存在: ${certPath}`)
  }
}

/**
 * 用 @vscode/sudo-prompt 弹系统密码框执行提权命令。
 * 直接 sudo 在 GUI 进程里没有 TTY，会报 "a terminal is required to read the password"。
 */
function sudoExec (cmd) {
  return new Promise((resolve, reject) => {
    log.info('以管理员权限执行命令:', cmd)
    sudoPrompt.exec(cmd, { name: 'dev-sidecar' }, (error, stdout, stderr) => {
      if (stderr) {
        log.warn('以管理员权限执行命令，stderr:', stderr)
      }
      if (error) {
        log.error('以管理员权限执行命令失败:', error)
        reject(error)
      } else {
        resolve(stdout)
      }
    })
  })
}

/**
 * Linux 按发行版安装系统 CA：
 * - Debian/Ubuntu: /usr/local/share/ca-certificates + update-ca-certificates
 * - Arch / p11-kit: trust anchor 或 /etc/ca-certificates/trust-source/anchors + update-ca-trust
 * - Fedora/RHEL: /etc/pki/ca-trust/source/anchors + update-ca-trust
 * 传入的证书本身即为 .crt（dev-sidecar.ca.crt），无需再转扩展名。
 */
async function installLinuxCa (exec, certPath) {
  assertCert(certPath)

  const hasCmd = async (cmd) => {
    try {
      await exec(`command -v ${cmd} >/dev/null 2>&1`)
      return true
    } catch {
      return false
    }
  }

  // Arch：优先 p11-kit trust anchor
  if (fs.existsSync('/etc/arch-release') || (await hasCmd('trust'))) {
    try {
      await sudoExec(`trust anchor '${certPath}'`)
      return { method: 'arch:trust', cert: certPath }
    } catch (e) {
      try {
        await sudoExec(`mkdir -p /etc/ca-certificates/trust-source/anchors && cp '${certPath}' /etc/ca-certificates/trust-source/anchors/dev-sidecar-ca.crt && update-ca-trust`)
        return { method: 'arch:update-ca-trust', cert: certPath }
      } catch (e2) {
        throw new Error(`Arch 安装 CA 失败: ${e.message || e}; 回退失败: ${e2.message || e2}`)
      }
    }
  }

  // Fedora / RHEL / openSUSE 等 p11-kit
  if (fs.existsSync('/etc/redhat-release') || fs.existsSync('/etc/fedora-release') || fs.existsSync('/etc/pki/ca-trust')) {
    try {
      await sudoExec(`mkdir -p /etc/pki/ca-trust/source/anchors && cp '${certPath}' /etc/pki/ca-trust/source/anchors/dev-sidecar-ca.crt && update-ca-trust`)
      return { method: 'rhel:update-ca-trust', cert: certPath }
    } catch {
      // 继续尝试 Debian 方式
    }
  }

  // Debian / Ubuntu
  if (fs.existsSync('/etc/debian_version') || (await hasCmd('update-ca-certificates'))) {
    await sudoExec(`mkdir -p /usr/local/share/ca-certificates && cp '${certPath}' /usr/local/share/ca-certificates/dev-sidecar-ca.crt && update-ca-certificates`)
    return { method: 'debian:update-ca-certificates', cert: certPath }
  }

  // 兜底：若装了 update-ca-trust
  if (await hasCmd('update-ca-trust')) {
    const dir = fs.existsSync('/etc/pki/ca-trust/source/anchors')
      ? '/etc/pki/ca-trust/source/anchors'
      : '/etc/ca-certificates/trust-source/anchors'
    await sudoExec(`mkdir -p '${dir}' && cp '${certPath}' '${dir}/dev-sidecar-ca.crt' && update-ca-trust`)
    return { method: 'generic:update-ca-trust', cert: certPath }
  }

  throw new Error('无法识别 Linux 发行版的 CA 安装方式（需要 update-ca-certificates 或 update-ca-trust/trust）')
}

const executor = {
  async windows (exec, { certPath }) {
    assertCert(certPath)
    const cmds = [`start "" "${certPath}"`]
    await exec(cmds, { type: 'cmd' })
    return true
  },
  async linux (exec, { certPath }) {
    const result = await installLinuxCa(exec, certPath)
    return { success: true, ...result }
  },
  async mac (exec, { certPath }) {
    assertCert(certPath)
    const cmds = [`open "${certPath}"`]
    await exec(cmds, { type: 'cmd' })
    return true
  },
}

module.exports = async function (args) {
  return execute(executor, args)
}

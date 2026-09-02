/**
 * 设置环境变量
 */
const Registry = require('winreg')
const Shell = require('../shell')

const execute = Shell.execute

const executor = {
  async windows (exec, { list }) {
    const regKey = new Registry({
      hive: Registry.HKCU,
      key: '\\Environment',
    })

    const setItem = (item) => {
      const value = item.value == null ? '' : String(item.value)
      return new Promise((resolve, reject) => {
        regKey.set(item.key, Registry.REG_SZ, value, (err) => {
          if (err) {
            reject(err)
          } else {
            resolve()
          }
        })
      })
    }

    try {
      for (const item of list) {
        await setItem(item)
      }

      // 广播环境变量变更（setx 一个临时值触发 WM_SETTINGCHANGE）
      try {
        await exec('setx DS_REFRESH "1"', { type: 'cmd' })
      } catch {
        // 广播失败不影响主流程
      }

      // inject into current process so subsequent exec/child processes can inherit immediately
      let envUpdateError = null
      try {
        for (const item of list) {
          if (item.value == null) {
            delete process.env[item.key]
          } else {
            process.env[item.key] = String(item.value)
          }
        }
      } catch (e) {
        envUpdateError = e.message || String(e)
      }

      return { success: true, scope: 'User:winreg', envUpdateError }
    } catch (e) {
      return { success: false, error: 'Failed to set environment variables', details: e.message || String(e) }
    }
  },
  async linux (exec, { port }) {
    throw new Error('暂未实现此功能')
  },
  async mac (exec, { port }) {
    throw new Error('暂未实现此功能')
  },
}

module.exports = async function (args) {
  return execute(executor, args)
}

const { execFile } = require('node:child_process')

function execFileAsync (file, args) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (error, stdout) => {
      if (error) {
        reject(error)
      } else {
        resolve(stdout || '')
      }
    })
  })
}

// 解析 netstat -ano -p tcp：
// 找出所有 ESTABLISHED 连接的“本地端口 -> PID”映射。
// 监听器只对 TrafficMonitor 当前记录的客户端端口查表，因此不会误用代理服务端端口。
function parseNetstat (output) {
  const portPidMap = new Map()
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/^\s*TCP\s+([^:]+):(\d+)\s+([^:]+):(\d+)\s+(\S+)\s+(\d+)/)
    if (!match) {
      continue
    }
    const localPort = Number.parseInt(match[2], 10)
    const state = match[5]
    const pid = Number.parseInt(match[6], 10)
    if (state === 'ESTABLISHED') {
      portPidMap.set(localPort, pid)
    }
  }
  return portPidMap
}

// 解析 tasklist /FO CSV /NH："Image Name","PID","Session Name","Session#","Mem Usage"
function parseTasklist (output) {
  const pidNameMap = new Map()
  for (const line of output.split(/\r?\n/)) {
    const parts = line.split('","')
    if (parts.length < 2) {
      continue
    }
    const name = parts[0].replace(/^"/, '')
    const pid = Number.parseInt(parts[1], 10)
    if (!Number.isNaN(pid)) {
      pidNameMap.set(pid, name)
    }
  }
  return pidNameMap
}

function startProcessResolver (monitor, interval = 2500) {
  if (!monitor) {
    return () => {}
  }

  let running = false
  let timer = null

  const resolveOnce = async () => {
    if (running) {
      return
    }
    running = true
    try {
      const activePorts = monitor.getActiveClientPorts()
      if (!activePorts || activePorts.length === 0) {
        return
      }

      const netstatOutput = await execFileAsync('netstat.exe', ['-ano', '-p', 'tcp'])
      const portPidMap = parseNetstat(netstatOutput)
      if (portPidMap.size === 0) {
        return
      }

      const pids = [...new Set(activePorts.map((port) => portPidMap.get(port)).filter((pid) => pid != null))]
      if (pids.length === 0) {
        return
      }

      const tasklistOutput = await execFileAsync('tasklist.exe', ['/FO', 'CSV', '/NH'])
      const pidNameMap = parseTasklist(tasklistOutput)

      for (const clientPort of activePorts) {
        const pid = portPidMap.get(clientPort)
        if (pid == null) {
          continue
        }
        const name = pidNameMap.get(pid)
        if (name) {
          monitor.setProcessName(clientPort, name)
        }
      }
    } catch {
      // 进程解析失败不影响流量统计
    } finally {
      running = false
    }
  }

  resolveOnce()
  timer = setInterval(resolveOnce, interval)
  if (timer.unref) {
    timer.unref()
  }

  return () => {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }
}

module.exports = {
  startProcessResolver,
  parseNetstat,
  parseTasklist,
}

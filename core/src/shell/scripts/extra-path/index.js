const path = require('node:path')
const fs = require('node:fs')
const log = require('../../../utils/util.log.core')

function getExtraPath () {
  // 1) 显式指定（GUI 启动时设置）
  let extraPath = process.env.DS_EXTRA_PATH
  // 2) Electron 打包后：resources/extra（extraResources，asar 外）
  //    getAppPath()/app.asar 内的 exe 无法执行，不能作为回退
  const candidates = []
  if (extraPath) {
    candidates.push(extraPath)
  }
  if (process.resourcesPath) {
    candidates.push(path.join(process.resourcesPath, 'extra'))
  }
  // 3) 开发模式：本文件所在包目录（core 源码内，可能自带 exe）
  candidates.push(__dirname)

  for (const p of candidates) {
    if (p && fs.existsSync(path.join(p, 'sysproxy.exe'))) {
      if (p !== extraPath) {
        log.info('extraPath 解析为:', p)
      }
      return p
    }
  }

  extraPath = extraPath || candidates[1] || __dirname
  log.info('extraPath:', extraPath)
  return extraPath
}

function getProxyExePath () {
  const extraPath = getExtraPath()
  return path.join(extraPath, 'sysproxy.exe')
}

function getEnableLoopbackPath () {
  const extraPath = getExtraPath()
  return path.join(extraPath, 'EnableLoopback.exe')
}

module.exports = {
  getProxyExePath,
  getEnableLoopbackPath,
}

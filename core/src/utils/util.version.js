function parseVersion (version) {
  const matched = version.match(/^v?(\d{1,2}(?:\.\d{1,2})*)[.-]?(.*)$/)
  if (!matched) {
    throw new Error(`Invalid version string: ${version}`)
  }
  const versionInfo = {
    versions: matched[1].split('.'), // 版本号数组
    pre: matched[2], // 预发布版本号
  }

  // 将 versions 中的数字字符串转为数字
  for (let i = 0; i < versionInfo.versions.length; i++) {
    versionInfo.versions[i] = Number.parseInt(versionInfo.versions[i])
  }

  return versionInfo
}

/**
 * 比较版本号
 *
 * @param onlineVersion  线上版本号
 * @param currentVersion 当前版本号
 * @param log            日志对象
 * @returns {number} 比较线上版本号是否为更新的版本，大于0=是|0=相等|小于0=否|-999=出现异常，比较结果未知
 */
function isNewVersion (onlineVersion, currentVersion, log = null) {
  if (onlineVersion === currentVersion) {
    return 0
  }

  try {
    const onlineVersionObj = parseVersion(onlineVersion)
    const curVersionObj = parseVersion(currentVersion)

    const { versions: versions1 } = onlineVersionObj
    const { versions: versions2 } = curVersionObj

    if (versions1.length !== versions2.length) {
      // 短的数组补0
      if (versions1.length < versions2.length) {
        for (let i = versions1.length; i < versions2.length; i++) {
          versions1.push(0)
        }
      } else if (versions1.length > versions2.length) {
        for (let i = versions2.length; i < versions1.length; i++) {
          versions2.push(0)
        }
      }
    }

    // 版本数组比对
    for (let i = 0; i < versions1.length; i++) {
      if (versions1[i] > versions2[i]) {
        return i + 1 // 为新版本，需要更新
      } else if (versions1[i] < versions2[i]) {
        return -(i + 1) // 为旧版本，无需更新
      }
    }

    // 版本号相同，继续比对预发布版本号。
    //
    // ⚠️ 已知缺陷：下面把整个 pre 段当作**字符串**比较，因此 <run_number> 跨位数时会判反方向：
    //    "beta.100" < "beta.99"（逐字符比 "1" < "9"），于是当前 beta.99 看线上 beta.100 会得到
    //    -101「无需更新」；同理 "beta.9" 会被判定为比 "beta.788" 更新。
    //    实际影响有限：正式版用户看不到预发布版更新（见 packages/gui/src/bridge/update/backend.js
    //    里的 skipPreRelease 守卫），且线上「最近可用版本」通常就是最新的那个，触发需要
    //    「当前号比线上大但位数更少」这种巧合。2026-10 时 run_number 已近 800，下一个坎是 1000。
    //    若要彻底修：按 "." 分段、数字段按数值比较（semver 语义），而不是整段比字符串。
    if (onlineVersionObj.pre && curVersionObj.pre) {
      // 都为预发布版本时，直接比较预发布版本号字符串的大小
      if (onlineVersionObj.pre > curVersionObj.pre) {
        return 101
      } else if (onlineVersionObj.pre < curVersionObj.pre) {
        return -101
      }
    } else if (!onlineVersionObj.pre && curVersionObj.pre) {
      // 线上为正式版本，当前版本为预发布版本，需要更新
      return 102
    } else if (onlineVersionObj.pre && !curVersionObj.pre) {
      // 线上为预发布版本，当前版本为正式版本，无需更新
      return -102
    }

    return 0 // 相同版本，无需更新
  } catch (e) {
    (log || console).error(`比对版本失败，当前版本号：${currentVersion}，线上版本号：${onlineVersion}, error:`, e)
    return -999 // 比对异常
  }
}

module.exports = { isNewVersion }

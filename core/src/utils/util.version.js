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
 * 按 semver 语义比较预发布段（如 beta.100 / dev.abc123）
 * @returns {number} 大于 0 表示 a 比 b 新
 */
function comparePrerelease (a, b) {
  const pa = String(a).split('.')
  const pb = String(b).split('.')
  const max = Math.max(pa.length, pb.length)
  for (let i = 0; i < max; i++) {
    if (i >= pa.length) {
      return -1
    }
    if (i >= pb.length) {
      return 1
    }
    const na = /^\d+$/.test(pa[i]) ? Number(pa[i]) : null
    const nb = /^\d+$/.test(pb[i]) ? Number(pb[i]) : null
    if (na != null && nb != null) {
      if (na !== nb) {
        return na > nb ? 1 : -1
      }
      continue
    }
    if (na != null) {
      return -1 // 数字段的优先级低于字母段（semver）
    }
    if (nb != null) {
      return 1
    }
    if (pa[i] !== pb[i]) {
      return pa[i] > pb[i] ? 1 : -1
    }
  }
  return 0
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
    // 预发布段按 semver 语义比较：按 "." 分段，纯数字段按数值比较，其余按 ASCII 比较；
    // 这样 beta.100 > beta.99、alpha.10 > alpha.9，而不是逐字符比字符串。
    // 不同标签之间的优先级：alpha < beta < dev < rc（ASCII 比较即满足）。
    if (onlineVersionObj.pre && curVersionObj.pre) {
      return comparePrerelease(onlineVersionObj.pre, curVersionObj.pre) > 0 ? 101 : -101
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

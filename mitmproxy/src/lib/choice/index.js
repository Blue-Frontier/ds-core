const { LRUCache } = require('lru-cache')
const log = require('../../utils/util.log.server')

const cacheSize = 1024

class ChoiceCache {
  constructor () {
    this.cache = new LRUCache({
      maxSize: cacheSize,
      sizeCalculation: () => {
        return 1
      },
    })
  }

  get (key) {
    return this.cache.get(key)
  }

  getOrCreate (key, backupList) {
    log.info('get counter:', key)
    let item = this.cache.get(key)
    if (item == null) {
      item = new DynamicChoice(key)
      item.setBackupList(backupList)
      this.cache.set(key, item)
    }
    return item
  }
}

class DynamicChoice {
  constructor (key) {
    this.key = key
    this.countMap = {} /* ip -> count { value, total, error, keepErrorCount, successRate }  */
    this.value = null // 当前使用的host
    this.backupList = [] // 备选host列表
    this.createTime = new Date()
  }

  doRank () {
    // 将count里面根据成功率排序
    const countList = []
    for (const key in this.countMap) {
      countList.push(this.countMap[key])
    }

    // 将countList根据成功率排序
    countList.sort((a, b) => {
      return b.successRate - a.successRate
    })

    log.info('Do rank:', JSON.stringify(countList))

    const newBackupList = countList.map(item => item.value)
    this.setBackupList(newBackupList)
  }

  /**
   * 设置新的backup列表
   * @param newBackupList 新的backupList
   */
  setBackupList (newBackupList) {
    this.backupList = [...newBackupList]
    let defaultTotal = newBackupList.length
    for (const ip of newBackupList) {
      if (!this.countMap[ip]) {
        this.countMap[ip] = { value: ip, total: defaultTotal, error: 0, keepErrorCount: 0, successRate: 0.5 }
        defaultTotal--
      }
    }
    this.value = this.backupList.shift()
    this.doCount(this.value, false)
  }

  countStart (value) {
    this.doCount(value, false)
  }

  /**
   * 换下一个
   * @param count 计数器
   */
  changeNext (count) {
    log.info('切换backup', count, this.backupList)
    count.keepErrorCount = 0 // 清空连续失败
    count.total = 0
    count.error = 0

    const valueBackup = this.value
    if (this.backupList.length > 0) {
      this.value = this.backupList.shift()
      log.info(`切换backup完成: ${this.key}, ip: ${valueBackup} ➜ ${this.value}, this:`, this)
    } else {
      this.value = null
      log.info(`切换backup完成: ${this.key}, backupList为空了，设置this.value: from '${valueBackup}' to null. this:`, this)
    }
  }

  /**
   * 重置失败计数，从候选中重新选择一个「真实IP」（不是域名兜底项）
   *
   * 真实IP连续失败后 value 会退化成域名兜底项（见 `dns/base.js` 的 `ipList.push(hostname)`），
   * 此时下游会把域名交给系统DNS解析（可能被投毒或阻断），需要给真实IP一次新的机会。
   *
   * @param hostname 域名兜底项（不会被选中）
   * @returns {boolean} 是否成功选出了真实IP（false 表示候选中只有域名兜底项）
   */
  resetChoice (hostname) {
    const ipList = []
    for (const key in this.countMap) {
      const count = this.countMap[key]
      count.keepErrorCount = 0 // 清空连续失败
      count.total = 0
      count.error = 0
      count.successRate = 1.0
      if (key !== hostname) {
        ipList.push(key)
      }
    }

    if (ipList.length === 0) {
      return false
    }

    const valueBackup = this.value
    this.backupList = ipList
    this.value = this.backupList.shift()
    this.doCount(this.value, false)
    log.info(`重置失败计数完成: ${this.key}, ip: ${valueBackup} ➜ ${this.value}, backupList: ${JSON.stringify(this.backupList)}`)
    return true
  }

  /**
   * 记录使用次数或错误次数
   * @param ip
   * @param isError
   */
  doCount (ip, isError) {
    let count = this.countMap[ip]
    if (count == null) {
      count = this.countMap[ip] = { value: ip, total: 5, error: 0, keepErrorCount: 0, successRate: 1 }
    }

    if (isError) {
      count.error++ // 失败次数+1
      count.keepErrorCount++ // 连续失败次数+1
    } else {
      count.keepErrorCount = 0 // 成功后重置连续失败计数
    }
    count.total++ // 总次数+1

    // 计算成功率
    count.successRate = 1.0 - (count.error / count.total)

    // 判断是否需要切换下一个
    if (isError && this.value === ip) {
      // 连续失败 1 次就切：坏 IP 不值得等 3 次 × 15s = 45s
      if (count.keepErrorCount >= 1) {
        this.changeNext(count)
      } else if (count.successRate < 0.4) {
        // 成功率小于40%,切换下一个
        this.changeNext(count)
      }
    }
  }
}

module.exports = {
  DynamicChoice,
  ChoiceCache,
}

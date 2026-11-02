/* global describe, it */

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

// 全量模块加载：src 下每个 .js 都会被 require 一次。
// 目的是让「相对路径写错、包名拼错、循环依赖、顶层语法错误」在跑测试时就暴露，
// 而不是等用户装上新版本启动时才崩（2.3.4 的 util.secret-vault 路径错误就是这样漏掉的）。
describe('模块加载', () => {
  it('src 下所有 .js 文件都能被 require', () => {
    const root = path.resolve(__dirname, '../src')
    const files = []
    ;(function walk (dir) {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, ent.name)
        if (ent.isDirectory()) {
          walk(p)
        } else if (ent.name.endsWith('.js')) {
          files.push(p)
        }
      }
    })(root)

    const failures = []
    for (const file of files) {
      try {
        require(file)
      } catch (e) {
        failures.push(`${path.relative(root, file)}: ${String(e.message).split('\n')[0]}`)
      }
    }

    assert.deepEqual(failures, [], `以下文件加载失败：\n${failures.join('\n')}`)
  })
})

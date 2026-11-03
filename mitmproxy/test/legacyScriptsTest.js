/* global describe, it */

const assert = require('node:assert/strict')
const path = require('node:path')
const { execFile } = require('node:child_process')
const { local } = require('./legacy-scripts.cjs')

const ROOT = path.resolve(__dirname, '..')

function runScript (file) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [path.join('test', file)],
      { cwd: ROOT, timeout: 120000 },
      (error, stdout, stderr) => {
        resolve({ error, stdout, stderr })
      },
    )
  })
}

// 这些脚本是「require 即执行」的历史写法，直接在 mocha 进程里 require 会在失败时
// process.exit(1)，把整个测试进程带走、连汇总都看不到。放到子进程里跑，失败可归因。
describe('历史脚本式测试', () => {
  for (const file of local) {
    it(file, async () => {
      const { error, stdout, stderr } = await runScript(file)
      assert.equal(error, null, `exit=${error && error.code}\n${stderr || stdout}`)
    })
  }
})

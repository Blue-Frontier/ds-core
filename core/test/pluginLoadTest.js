/* global describe, it */

const assert = require('node:assert/strict')

// 顶层聚合入口的冒烟测试：plugin/index.js 会在启动时 require 所有插件，
// 任何一个插件内部的相对路径写错都会让主进程直接崩溃，单测必须覆盖这一层。
describe('plugin 聚合入口', () => {
  it('require 时不抛错，并导出 overwall / share 插件', () => {
    const plugin = require('../src/modules/plugin/index.js')

    assert.equal(plugin.overwall.key, 'overwall')
    assert.equal(plugin.share.key, 'share')
    assert.equal(typeof plugin.overwall.plugin, 'function')
    assert.equal(typeof plugin.share.plugin, 'function')
  })
})

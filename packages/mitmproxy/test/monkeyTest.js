const assert = require('node:assert')
const monkey = require('../src/lib/monkey')

let scripts
try {
  scripts = monkey.load('./extra/scripts/')
} catch {
  scripts = monkey.load('../extra/scripts/')
}

// console.log(scripts)
assert.strictEqual(scripts.github != null, true)
assert.strictEqual(scripts.google != null, true)
assert.strictEqual(scripts.tampermonkey != null, true)

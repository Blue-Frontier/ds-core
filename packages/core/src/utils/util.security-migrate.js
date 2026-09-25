/**
 * 迁移入口：按版本模块拆分，勿把业务写在这里。
 * 当前：2.2.0 → 3.0.0（migrations/to3.0.0.js）
 * 以后：新增 migrations/to3.x.js / to4.0.0.js 等。
 */
const to300 = require('./migrations/to3.0.0')

module.exports = {
  runSecurityMigration: to300.runMigration_to3_0_0,
  runMigration_to3_0_0: to300.runMigration_to3_0_0,
  MIGRATION_ID: to300.MIGRATION_ID,
  MIGRATION_TARGET: to300.MIGRATION_TARGET,
}

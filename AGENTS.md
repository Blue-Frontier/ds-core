# AGENTS.md — ds-core

本仓库是 DevSidecar **内核**（`Blue-Frontier/ds-core`），含两个包，**不是** monorepo 全家桶。

## 仓库边界

| 路径 | 包名 | 职责 |
|------|------|------|
| `core` | `@blue-frontier/dev-sidecar` | 配置合并、插件、系统代理、shell |
| `mitmproxy` | `@blue-frontier/mitmproxy` | MITM 代理、DNS、拦截、测速、流量 |

**禁止**在此仓修改 GUI / Electron / CLI 业务代码。

## 常用命令

```bash
pnpm install
pnpm lint
pnpm --filter @blue-frontier/dev-sidecar test
pnpm --filter @blue-frontier/mitmproxy test
```

单个测试文件：

```bash
pnpm --filter @blue-frontier/mitmproxy test -- test/regex.test.js
```

## 模块约定

- `core`、`mitmproxy` 使用 **CommonJS**（无 `"type": "module"`）
- 共享 JSON 解析：`@blue-frontier/mitmproxy/src/json`
- 日志：`core/src/utils/util.logger.js`；文件默认在 `~/.dev-sidecar/logs/`
- 用户配置：`~/.dev-sidecar/config.json`（兼容旧 `config.json5`）
- CA：`~/.dev-sidecar/dev-sidecar.ca.crt`
- 默认端口：HTTP 31180，HTTPS 31181 — **不要随意改默认值**

## 提交与推送

- AI 可 `git add`、整理改动、跑验证；**提交（含签名）由人类执行**
- 提交信息：`type(scope): 中文摘要`
- **推送由 AI 负责**：人类提交后告知 AI，AI 执行 `git push` 并做验证（推送不属于签名动作）
- 验证：`gh api repos/Blue-Frontier/ds-core/commits/main --jq .sha[0:8]` 与本地 HEAD 比对
- 父仓（ds-cli / 历史 monorepo）按**精确 SHA** 指向本仓；**本仓提交未推送前，父仓不得 bump 指针**
  —— 否则远端出现悬空引用，任何人 `git clone --recurse-submodules` 都会失败（已发生过两次）

## 与兄弟仓

- 改内核后：先在 ds-core 提交（**不需要打 tag**，父仓按精确 SHA 指向）→ cli/gui 更新 submodule 指针
- **三仓各自独立的版本号**：内核（本仓）、CLI（ds-cli）、GUI（dev-sidecar）互不同步；
### 内核版本号已废弃

- 本仓两个包的 `version` 字段**已废弃**，仅有形式作用（包必须有个版本号才能被 pnpm 解析）。
- 它的历史来源是抄历史 monorepo 的应用版本号，**与内核实际内容无关**，
  **不得在任何面向最终用户的地方展示**（CLI/GUI 的关于信息、状态输出、界面底栏等一律不显示）。
- 内核的身份一律用**提交 SHA**：短 SHA 面向用户展示（如 `ds-core@582630b`），
  长 SHA 供排障与构建日志对照。父仓（CLI/GUI）按精确 SHA 钉住子模块指针。
- 若将来确实需要"内核发布名"，用 git tag（如 `kernel-1.0.0`）当名字，钉指针仍走 SHA。
  CLI/GUI 的「关于」信息里应展示内嵌内核的版本与 SHA，便于对照
- GitHub：https://github.com/Blue-Frontier/ds-core  
- CLI：https://github.com/Blue-Frontier/ds-cli  
- 历史 monorepo：https://github.com/docmirror/dev-sidecar

## 发布

- 包为 private，**不发布 npm**
- 以 **git tag**（如 `v2.3.0`）作为消费方 pin 点

<!-- package: ds-core | org: Blue-Frontier -->

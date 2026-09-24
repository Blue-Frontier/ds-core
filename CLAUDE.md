# CLAUDE.md — ds-core

本仓库是 DevSidecar **内核**（`Blue-Frontier/ds-core`），含两个包，**不是** monorepo 全家桶。

## 仓库边界

| 路径 | 包名 | 职责 |
|------|------|------|
| `packages/core` | `@blue-frontier/dev-sidecar` | 配置合并、插件、系统代理、shell |
| `packages/mitmproxy` | `@blue-frontier/mitmproxy` | MITM 代理、DNS、拦截、测速、流量 |

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
- 日志：`packages/core/src/utils/util.logger.js`；文件默认在 `~/.dev-sidecar/logs/`
- 用户配置：`~/.dev-sidecar/config.json`（兼容旧 `config.json5`）
- CA：`~/.dev-sidecar/dev-sidecar.ca.crt`
- 默认端口：HTTP 31180，HTTPS 31181 — **不要随意改默认值**

## 提交

- AI 可 `git add`；**GPG/SSH 签名提交由人类执行**
- 提交信息：`type(scope): 中文摘要`

## 与兄弟仓

- 改内核后：打 tag（三仓同版本号）→ cli/gui 更新 submodule 指到该 tag
- GitHub：https://github.com/Blue-Frontier/ds-core  
- CLI：https://github.com/Blue-Frontier/ds-cli  
- 历史 monorepo：https://github.com/docmirror/dev-sidecar

## 发布

- 包为 private，**不发布 npm**
- 以 **git tag**（如 `v2.3.0`）作为消费方 pin 点

<!-- package: ds-core | org: Blue-Frontier -->

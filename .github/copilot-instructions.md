# Copilot / AI — ds-core

仓库：Blue-Frontier/ds-core。仅包含 `packages/core` 与 `packages/mitmproxy`。

- 包名：`@blue-frontier/dev-sidecar`、`@blue-frontier/mitmproxy`（private，不发 npm）
- 测试：`pnpm --filter @blue-frontier/dev-sidecar test` 与 mitmproxy filter
- 不要修改 GUI/CLI；跨仓改动先在本仓提交并打 tag
- 用户目录 `~/.dev-sidecar/`、端口 31180/31181 行为需保持兼容
- 提交：AI 可 stage，签名 commit 由人执行

文档互链：
- https://github.com/Blue-Frontier/ds-cli
- https://github.com/docmirror/dev-sidecar

<!-- package: ds-core | org: Blue-Frontier -->

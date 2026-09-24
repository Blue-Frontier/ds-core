# ds-core

DevSidecar 内核仓库（**三位一体**之 core）：`packages/core` + `packages/mitmproxy`。

原 monorepo 拆分自 [docmirror/dev-sidecar](https://github.com/docmirror/dev-sidecar)（Issue #698 代号：三位一体）。

## 三位一体

| 仓库 | 职责 | 地址 |
|------|------|------|
| **ds-core**（本仓） | 代理内核 core + mitmproxy | https://github.com/Blue-Frontier/ds-core |
| **ds-cli** | 命令行 / SEA | https://github.com/Blue-Frontier/ds-cli |
| **ds-gui**（后续） | 桌面 GUI | https://github.com/Blue-Frontier/ds-gui |
| 历史主仓 | 迁移前 monorepo（只读参考） | https://github.com/docmirror/dev-sidecar |

用户配置目录与端口约定三端一致：`~/.dev-sidecar/`，HTTP **31180** / HTTPS **31181**。

## 包名

| 目录 | npm 包名（内部） |
|------|------------------|
| `packages/core` | `@blue-frontier/dev-sidecar` |
| `packages/mitmproxy` | `@blue-frontier/mitmproxy` |

包为 **private**，不在 npm 发布；消费方通过 **git submodule + pnpm workspace** 引用。

> 历史包 `@docmirror/*@<=1.7.3` 仍在 registry 上，与本仓无关，勿再用于 2.x。

## 依赖关系

```
@blue-frontier/mitmproxy ──workspace──► @blue-frontier/dev-sidecar
```

（`mitmproxy` 使用 core 的 logger / config / merge；`core` 使用 `mitmproxy` 的 `src/json`。）

## 开发

```bash
pnpm install
pnpm test
pnpm lint
```

测试：

```bash
pnpm --filter @blue-frontier/dev-sidecar test
pnpm --filter @blue-frontier/mitmproxy test
```

## 被其他仓库引用

cli / gui 仓库将本仓放在 `vendor/ds-core`（git submodule），并在 `pnpm-workspace.yaml` 中包含：

```yaml
packages:
  - packages/*
  - vendor/ds-core/packages/*
```

## License

MPL-2.0

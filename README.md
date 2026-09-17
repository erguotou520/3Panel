# 3Panel

3Panel 是基于 [1Panel](https://github.com/1Panel-dev/1Panel) 二次开发的 Linux 服务器管理面板，使用 Go + Vue 3 构建，遵循 GPLv3 协议发布。

> 本项目为 1Panel 的衍生作品，产品名称、Logo 等品牌标识已全部替换为 3Panel，与上游项目无隶属关系。合规声明详见 [NOTICE.md](./NOTICE.md)。

## 环境要求

- Go `1.26.1`（见 `core/go.mod`、`agent/go.mod`）
- Node.js 与 npm（前端构建，依赖见 `frontend/package.json`）
- GNU Make（可选，用于一键构建）

## 目录结构

```text
├── agent/       # Agent 服务（独立 Go module）
├── core/        # Core 服务（独立 Go module）
├── frontend/    # 前端（Vue 3 + Vite + TypeScript）
├── scripts/     # 运维 / 诊断脚本
├── docs/        # 开发文档
└── Makefile     # 构建入口
```

## 构建

```bash
# 1. 前端
cd frontend && npm install && npm run build:pro

# 2. 后端（会先构建前端，再编译 core / agent，产物输出到 ./build）
make build_all
```

`make build_all` 会先构建前端并将产物写入 `core/cmd/server/web/assets`，该目录在仓库中默认只有占位文件，属正常现象。

其他常用目标：

| 命令 | 说明 |
| --- | --- |
| `make build_on_local` | 本地（darwin）构建 |
| `make clean_assets` | 清理前端构建产物 |
| `make upx_bin` | 压缩已构建的二进制 |

前端单独开发：

```bash
cd frontend
npm run dev          # 启动开发服务
npm run type-check   # 类型检查
npm run lint:eslint  # ESLint 自动修复
```

## 参与开发

- [CONTRIBUTING.md](./CONTRIBUTING.md)：PR / Issue 流程
- [docs/TRANSLATION.md](./docs/TRANSLATION.md)：新增语言（i18n）改造清单

## 许可证

基于 [GNU General Public License v3.0](./LICENSE) 发布，上游版权与许可证信息完整保留，详见 [NOTICE.md](./NOTICE.md)。

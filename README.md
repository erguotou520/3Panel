# 3Panel

3Panel 是基于 [1Panel](https://github.com/1Panel-dev/1Panel) 二次开发的 Linux 服务器管理面板，使用 Go + Vue 3 构建，遵循 GPLv3 协议发布。

> 本项目为 1Panel 的衍生作品，产品名称、Logo 等品牌标识已全部替换为 3Panel，与上游项目无隶属关系。合规声明详见 [NOTICE.md](./NOTICE.md)。

## 安装

一键安装（发布域名自带 CDN 加速，直连即可）：

```bash
bash -c "$(curl -sSL https://3panel.erguotou.me/package/quick_start.sh)"
```

安装包约 58MB，脚本支持断点续传——中断后重跑同一条命令会从上次的分片继续。已安装时会拒绝覆盖，并提示先卸载或走面板升级。

安装后的布局：

| 路径 | 说明 |
| --- | --- |
| `/usr/local/bin/3panel-core` | 主控服务 |
| `/usr/local/bin/3panel-agent` | 本机 agent |
| `/usr/local/bin/3pctl` | 运维入口 |
| `/opt/3panel` | 数据目录（可用 `PANEL_BASE_DIR` 改） |
| `3panel-core.service` / `3panel-agent.service` | systemd 服务 |

日常运维走 `3pctl`：`status` / `start` / `stop` / `restart` / `version` / `user-info` / `listen-ip` / `reset` / `restore` / `update` / `uninstall`，`3pctl --help` 看全部。

## 卸载

```bash
3pctl uninstall
```

需要 root，输入 `y` 确认。执行顺序：停并 disable 两个服务 → 删除 `/usr/local/bin/{3panel-core,3panel-agent,3pctl,lang}` 与 `${BASE_DIR}/3panel` → 删除 systemd 单元并 `daemon-reload`。

> ⚠️ 卸载会 `rm -rf ${BASE_DIR}/3panel`（默认 `/opt/3panel`），也就是**整个数据目录**——面板数据库、配置、日志、agent 证书一并删除且不可恢复。卸载前先备份这个目录。
> 只想升级的话不要卸载，走下面的升级流程。

节点机上（只装了 agent）同样用 `3pctl uninstall`；它会尝试停 `3panel-core.service` 并报不存在，可忽略，agent 与数据目录照常清理。

## 节点加入（多机管理）

面板「多机管理 → 添加节点」会直接给出一键命令，复制到目标机器执行即可——脚本会自动下载 agent 独立包、安装、向面板换取证书、注册并启动服务：

```bash
PANEL3_MASTER='<面板地址>' PANEL3_TOKEN='<token>' \
  bash -c "$(curl -sSL https://3panel.erguotou.me/package/join.sh)"
```

- 节点机只装 agent（amd64 ~26MB / arm64 ~23MB），不会装 core。
- token **一次性**且有有效期；用掉或过期后要回面板重新添加节点取新命令。
- 面板会主动连回节点的 `9999` 端口（`PANEL3_PORT` 可改），云厂商安全组也要放行。
- 机器上已经有 agent 二进制时，可用页面折叠区里的原始命令 `3panel-agent join --master <面板地址> --token <token>`。

## 升级

**主控**：面板内「面板设置 → 升级」，或 `3pctl update`。升级包从 `/package/{channel}/{version}/release/` 拉取，落地前先校 `.sha256`。

**节点 agent**：主控升级**不会带动节点**，节点版本只在节点列表里展示，面板不做一致性校验——所以旧 agent 仍能在线。但跨版本后主控可能调到 agent 上没有的接口而报错，建议跟随主控版本升级。

面板「多机管理 → 升级节点」会给出下面这条命令，复制到节点机上以 root 执行：

```bash
PANEL3_CHANNEL='stable' bash -c "$(curl -sSL https://3panel.erguotou.me/package/upgrade-agent.sh)"
```

- **不需要 token，也不会重新 join**：现有证书与 `<base-dir>/3panel` 下的数据原样保留，只替换二进制。
- 命令里的 `PANEL3_CHANNEL` 由面板按自己的升级频道生成，保证节点与主控同流（面板 `dev` 模式就发 `dev`）。
- `PANEL3_VERSION` 可钉住版本、`PANEL3_FORCE=1` 同版本也强制重装。
- 沿用节点上 `/usr/local/bin/3pctl` 里记录的 `BASE_DIR`、端口与语言，不改变节点布局；已是最新版本时直接退出。
- 前提是节点当初是**用一键命令加入**的（即存在 `/usr/local/bin/3pctl` 与 `3panel-agent`）。全新机器请走上面的「节点加入」。

**为什么不能重跑一键加入命令**：join token 是一次性的，且同名节点不能重复创建（`ErrRecordExist`），已加入的节点拿不到新 token——升级只能走上面这条独立通道。

升级完回面板点一次「健康检查」，节点 Online 且版本号更新即生效。

<details>
<summary>手工升级（不想跑脚本，或要装指定版本）</summary>

```bash
CHANNEL=stable   # 与主控 core/cmd/server/conf/app.yaml 的 base.mode 一致
VERSION="$(curl -sSL https://3panel.erguotou.me/package/$CHANNEL/latest)"
ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
PKG="3panel-agent-${VERSION}-linux-${ARCH}"

cd /tmp
curl -sSL -O "https://3panel.erguotou.me/package/${CHANNEL}/${VERSION}/release/${PKG}.tar.gz"
curl -sSL -O "https://3panel.erguotou.me/package/${CHANNEL}/${VERSION}/release/${PKG}.tar.gz.sha256"
# .sha256 里只有裸哈希、没有文件名，所以用字符串比较，不能用 sha256sum -c
[ "$(sha256sum "${PKG}.tar.gz" | awk '{print $1}')" = "$(cat "${PKG}.tar.gz.sha256")" ] || \
    { echo "checksum mismatch, abort"; exit 1; }
tar -zxf "${PKG}.tar.gz"

systemctl stop 3panel-agent                                        # ①
install -m 0755 "/tmp/${PKG}/3panel-agent" /usr/local/bin/3panel-agent
sed -i "s|^ORIGINAL_VERSION=.*|ORIGINAL_VERSION=${VERSION}|" /usr/local/bin/3pctl   # ②
systemctl start 3panel-agent
```

三个坑：

1. 必须先停服务——覆盖正在运行的二进制会报 `Text file busy`。
2. agent 上报的版本号读自 `/usr/local/bin/3pctl` 里的 `ORIGINAL_VERSION`，只换二进制的话面板上看到的还是旧版本号。
3. **不要**用包里的 `3pctl` 覆盖 `/usr/local/bin/3pctl`：那份是未改写的默认值 `CORE_SERVICE=3panel-core`，覆盖后 `3pctl status/restart` 会指向节点上并不存在的 core 服务。

</details>

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

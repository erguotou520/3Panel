# 3Panel 升级通道部署指引

> 面向自托管部署（唯一域名：`3panel.erguotou.me`）
> 本文档对应代码改动后的实际行为，改动清单见文末。

---

## 一、升级流程是怎么跑的

升级**不是**由 shell 脚本完成的，全部由 `core` 的 Go 代码执行。
入口：面板「系统 → 升级」，或 `POST /api/v2/core/upgrades/upgrade`。

```
① 版本探测     GET  {RepoURL}/{mode}/latest            纯文本最新版本号
                     {RepoURL}/{mode}/latest.current   旧版本兼容用 JSON map
② 对比当前版本  与 SystemVersion 比较，决定是否有新版本 / 是否需要 beta
③ 拉更新说明   GET  {RepoURL}/{mode}/{ver}/release/3panel-{ver}-release-notes
④ 下载升级包   GET  {RepoURL}/{mode}/{ver}/release/3panel-{ver}-linux-{arch}.tar.gz
⑤ 校验完整性   GET  {…}.tar.gz.sha256  → 强制比对 sha256（不一致即中止）
⑥ 解包         解到 {install_dir}/3panel/tmp/upgrade/{ver}/downloads/
⑦ 备份原文件   3panel-core / 3panel-agent / 3pctl / 服务脚本 → original/
⑧ 覆盖安装     → /usr/local/bin/{3panel-core,3panel-agent,3pctl}
                     lang/ → /usr/local/bin
                     GeoIP.mmdb → {install_dir}/3panel/geo/GeoIP.mmdb
                     initscript/{服务名} → 服务目录
⑨ 重启面板     重启核心与 agent
⑩ 收尾         写升级日志、更新 SystemVersion
失败任一环节 → handleRollback() 用 ⑦ 的备份回滚
```

关键代码：
- `core/app/service/upgrade.go` — 主流程（`CheckUpgrade` / `Upgrade` / `handleRollback` / `verifyUpgradePackage`）
- `core/utils/files/files.go` — `DownloadFileWithProxyStream` 下载、sha256 工具
- `core/utils/req_helper/requset.go` — 统一出站请求（TLS 校验已恢复）

> **升级后不再执行任何远程 shell 脚本。** 原 `writeLogs` / `runRemoteShellScript`
> 机制已整体删除（详见 §4.2）。

**`mode` 取值**：默认取 `global.CONF.Base.Mode`（`app.yaml` 里的 `base.mode`，仓库默认 `dev`）。
版本号含 `beta` 时自动切成 `beta`。发布 stable 包请把生产环境 `base.mode` 设为 `stable`。

**`arch` 取值**：`uname -a` 判定，产出 `amd64` / `arm64` / `armv7` / `ppc64le`。

---

## 二、必须在 3panel.erguotou.me 下托管的路径

以 `mode=stable`、`version=v1.0.0`、`arch=amd64` 为例。

> ⚠️ **频道由 `base.mode` 决定，先看你的 `mode` 是什么。**
> `core/app/service/upgrade.go` 的 `loadVersionByMode()`：
> `mode: dev` 时**只**读 `/package/dev/latest` 与 `/package/beta/latest`，
> 完全不碰 `stable`；只有 `mode: stable` 才读 `/package/stable/*`。
> 本仓库 `core/cmd/server/conf/app.yaml` 现为 **`mode: stable`**（2026-09-20 由 `dev` 切过来，
> 与应用商店的 `MODE=stable` 一致），所以面板读 `/package/stable/*`。
> `release-stable.yml` 对非 beta 版本**同时发到 `stable` 和 `dev` 两个频道**：发 `dev` 是
> 为了让切换之前装出去的、二进制里仍嵌着 `mode: dev` 的旧实例还能升级（它们读不到
> stable）；新装实例只认 stable。等旧实例都升一遍后，`dev` 这份副本可以考虑停发。
> 卸载/升级时的包路径同理：`mode: stable` 会去取 `/package/stable/<version>/release/…`。

### 2.1 升级通道（`RepoURL()` = `https://3panel.erguotou.me/package`）

下表以 `stable` 为例（本仓当前模式）；旧实例若仍是 `mode: dev`，把路径里的 `stable`
换成 `dev` 即可（两个频道的内容目前完全一致）。

| 用途 | 请求路径 | 期望内容 | 缺失后果 |
| --- | --- | --- | --- |
| 版本探测 | `/package/stable/latest` | 纯文本版本号，如 `v1.0.0`。**结尾不能有换行** | 检测不到新版本 |
| 版本探测（旧版兼容） | `/package/stable/latest.current` | JSON map `{"v1.0":"v1.0.3"}` | 落后小版本检测不到新版 |
| 更新说明 | `/package/stable/v1.0.0/release/3panel-v1.0.0-release-notes` | Markdown/纯文本 | 弹窗无说明（不阻断） |
| **升级包** | `/package/stable/v1.0.0/release/3panel-v1.0.0-linux-amd64.tar.gz` | tar.gz | **升级直接失败** |
| **完整性校验** | 同上 + `.sha256` | 一行摘要 | 跳过校验并记警告 |
| **agent 独立包** | `/package/stable/v1.0.0/release/3panel-agent-v1.0.0-linux-amd64.tar.gz` | tar.gz（+ `.sha256`） | 一键加入回退到整包抽取 |
| **一键安装脚本** | `/package/quick_start.sh` | bash 脚本，**路径里不带版本** | 一键安装命令 404 |
| **一键加入脚本** | `/package/join.sh` | bash 脚本，**路径里不带版本** | 面板生成的加入命令 404 |
| **节点安装器** | `/package/install-agent.sh` | bash 脚本 | 仅整包回退时需要 |
| **节点升级脚本** | `/package/upgrade-agent.sh` | bash 脚本，**路径里不带版本** | 面板「升级节点」给出的命令 404 |

> `latest` 由 `loadVersion()` 直接 `string(body)` 使用，**没有 TrimSpace**。
> 若带尾换行，版本号会变成 `"v1.0.0\n"` 而解析失败 —— 发布时必须用 `printf '%s'`（无换行）写入。

### 2.2 资源通道（`ResourceURL()` = `https://3panel.erguotou.me/resource`）

| 用途 | 请求路径 | 期望内容 |
| --- | --- | --- |
| 语言包 | `/resource/language/lang.tar.gz` | tar.gz，内含 `lang/*.sh`（解到 `/usr/local/bin`）。由 `build-release.sh` 产出 `dist/lang.tar.gz`、`release-stable.yml` 随发版上传 |
| GeoIP 库 | `/resource/geo/GeoIP.mmdb` | 自定义 schema 的 mmdb（≈19.5 MB，**非** MaxMind 官方格式，见 §5.4） |
| 脚本库数据 | `/resource/scripts/data.yaml` | yaml（脚本库索引） |
| 脚本库包 | `/resource/scripts/scripts.tar.gz` | tar.gz，内含 `scripts/sh/<key>.sh` |
| 脚本库版本 | `/resource/scripts/version.txt` | 纯文本（unix 秒），面板用它判断要不要重新同步 |

**这三个对象的上游在哪 —— v1/v2 路径是错开的，不能只换一个 base。**

1Panel 默认分支已切到 `dev-v2`，常量全变了（`ResourceURL()` → `.../1panel/resource/v2`、
`RepoURL()` → `.../1panel/package/v2`、`AppRepoURL()` → `apps-assets.fit2cloud.com`），
但**并不是所有资源都跟着搬**（2026-09 实测）：

| 对象 | v1 前缀 `.../1panel/…` | v2 前缀 `.../1panel/resource/v2/…` |
| --- | --- | --- |
| 脚本库 `scripts/*` | ❌ 404 | ✅ **200**（9 个脚本，version.txt 仍在更新） |
| 语言包 `language/lang.tar.gz` | ✅ 200（≈11.9 KB，含 en/fa/pt-BR/ru/zh） | ❌ 404 |
| GeoIP `geo/GeoIP.mmdb` | ✅ 200 | ❌ 404 |

所以脚本库只能用 v2 前缀取，语言包与 GeoIP 只能用 v1 前缀取。

**镜像方式：由 `scripts/cf-appstore-sync` 这个 Cloudflare Worker 负责，不在本地跑。**

Worker 本来就定时把应用商店镜像进 R2，资源通道作为同一次 cron 的附带动作
（只多一次 fetch；上游 `version.txt` 没变就一个字节都不写）。手动触发：

```bash
# 干跑：拉上游 + 校验，一个字节都不写桶（用来确认上游格式没变）
curl -s 'https://<worker>/sync-resource?dry=true' | jq .

# 正式同步脚本库（3 个对象）
curl -s 'https://<worker>/sync-resource' | jq .

# 需要时顺带镜像语言包 / GeoIP（默认关闭，见下）
curl -s 'https://<worker>/sync-resource?lang=true' | jq .
curl -s 'https://<worker>/sync-resource?geoip=true' | jq .

# 查看状态
curl -s 'https://<worker>/status' | jq .resource
```

| 查询参数 | 作用 |
| --- | --- |
| `?dry=true` | 只拉取并校验，不写桶 |
| `?force=true` | 忽略 stamp / ETag，强制重传 |
| `?lang=true` | 额外镜像 `/resource/language/lang.tar.gz` |
| `?geoip=true` | 额外镜像 `/resource/geo/GeoIP.mmdb`（≈19.5 MB） |

**发布前校验（不过就不覆盖，桶里现有的好数据原样保留）**：

- `data.yaml` 的每个 `key` 必须在 `scripts/sh/<key>.sh` 里有对应文件 ——
  缺文件的话面板会往脚本库写一条**空脚本**，界面上看不出坏在哪
- 脚本文件不得为 0 字节
- 语言包必须含 `lang/zh.sh`（`initLang()` 的哨兵）与 `lang/en.sh`（`install.sh` 回退）
- GeoIP 必须含 MaxMind 元数据标记且不小于 1 MB（挡住错误页被当成库镜像）

默认**不**让 cron 覆盖语言包：`/resource/language/lang.tar.gz` 由 `release-stable.yml`
从仓库内置的 `packaging/lang/` 产出，如果 Worker 也去镜像上游那份（5 种语言、键集合不同），
两者会互相覆盖、来回漂移。需要上游那份时用 `?lang=true` 单次拉取。

### 2.3 其他

| 用途 | 请求路径 | 说明 |
| --- | --- | --- |
| 代理连通性检测 | `/`（根路径） | 只需能建连，**不看状态码**，见 §6 |
| 文档搜索索引 | `/docs/v2/search/search_index.json` | 可选，用于「更新日志」；缺失只是没内容 |
| 应用商店 | `/package/{mode}/3panel/...` | 已就绪，见 `scripts/appstore-mirror` |

### 2.4 一键安装脚本（`/package/quick_start.sh`）

新装机器的一条命令：

```bash
bash -c "$(curl -sSL https://3panel.erguotou.me/package/quick_start.sh)"
```

> 发布域名本身就是对象存储 + CDN 加速，直连即可——不存在也不需要前缀代理。
> 早期用过 `https://proxy.erguotou.me/<完整URL>` 这种前缀反代，2026-09-20 已连同
> `PANEL3_PROXY` / `PANEL3_NO_PROXY` 一起移除，脚本里只保留发布源与自建镜像两条路径。

> ⚠️ **必须用 `bash -c "$(...)"`，不要 `curl ... | bash`。**
> 包内 `install.sh` 会用 stdin 询问端口/账号/密码；管道会把脚本文本喂给 `read`，
> 结果是创建出**空用户名空密码**的面板。

**它做什么**（`packaging/quick_start.sh`，只做引导，安装逻辑仍全在包内 `install.sh`）：

1. 校验命令/root/是否已安装 → 2. 解析架构（`uname -m`）→ 3. 取 `{mode}/latest` →
4. 下载 `3panel-{ver}-linux-{arch}.tar.gz` → 5. 校验 `<pkg>.sha256` →
6. 解压 → 7. `cd` 进包目录执行 `install.sh`，并把退出码原样返回。

**地址解析顺序**（第一个能返回非空版本号的胜出，失败的会打印
`unreachable, trying the next base: …`）：

```
PANEL3_MIRROR（若设，唯一候选）
  └→ {PANEL3_ORIGIN}                    # 默认 https://3panel.erguotou.me/package
```

> ⚠️ `PANEL3_ORIGIN` 是**发布通道的 base，必须带 `/package` 段**。
> 脚本会在它后面拼 `/$MODE/latest`；写成站点根会得到
> `https://3panel.erguotou.me/stable/latest` 的 **404**，现象很像网络故障。
> （这个坑真实踩过：本地测试全都显式传了带 `/package` 的地址，所以直到对真站
> 探测才暴露。现在有一条静态断言把默认值钉住了。）

**版本探测为什么要单独给更大的重试预算**：`latest` 只有几字节，但它是全流程最易
失败的一步 —— 实测这台机器到 Cloudflare 该边缘节点的 TLS 握手会被周期性重置
（连续 15 次里 1 次失败；网络差的窗口能到 2/5 甚至连续 12 次全失败，
`curl: (35) SSL_ERROR_SYSCALL` / `(28) SSL connection timeout`）。
所以探测用 `PANEL3_PROBE_RETRIES`（默认 6），下载用 `PANEL3_RETRIES`（默认 5）。
注意探测判据是**输出是否非空**而非管道退出码 —— `sh` 没有 `pipefail` 时，
curl 失败而 `tr` 成功会让管道返回 0 但输出为空。

**下载为什么要重试与续传**：实测直连 `3panel.erguotou.me` 拉 60 MB 包会周期性卡住，
4 次里有 3 次在 300 s 内只跑到 13–26 MB 就断；走代理拿到过 121 s 跑完全量（≈500 KB/s）。
所以脚本用 `curl -C -` 续传 + 默认 5 次重试。镜像站若忽略 Range（curl 退出码 33），
会自动去掉续传标志整包重下 —— 这条路径有专门的故障注入测试覆盖。

**分片会跨运行保留**：工作目录里若有一个**短于远端长度**的包，脚本会留着它并从断点
继续（打印 `incomplete partial found (…) — resuming`），而不是删掉重下 —— 在这条链路
上丢掉 40 MB 进度比重新开始更糟。长度**达到或超过**远端长度的文件会被删除，因为那正是
刚刚校验失败的那个。长度一致且校验通过则直接复用，完全不下载。

**校验和策略**：`.sha256` 取不到 → 只告警不阻断（避免校验文件故障堵塞安装）；
取到但与实际不符 → **删除包并中止，不执行 install.sh**。

**随脚本生效的安全闸门**（都在下载 60 MB 之前）：

| 条件 | 行为 |
| --- | --- |
| 非 root | 直接拒绝（省掉一次 60 MB 下载） |
| `/usr/local/bin/3pctl` 已存在 | 拒绝：升级请走面板，或先 `3pctl uninstall` |
| 非交互终端且未提供 `PANEL_USERNAME`/`PANEL_PASSWORD` | 拒绝（否则 `read` 拿到 EOF，会建出空密码账号） |
| `INSTALL_MODE` 不是 stable/dev/beta | 拒绝 |
| 架构不是 amd64/arm64（含 `ARCH` 覆盖值） | 拒绝 |

**环境变量**（前缀是 `PANEL3_`，不是 `3PANEL_` —— shell 变量名不能以数字开头）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `INSTALL_MODE` | `stable` | `stable` / `dev` / `beta` |
| `ARCH` | 自动 | `amd64` / `arm64`，其它值直接报错 |
| `PANEL3_MIRROR` | 空 | 指定唯一地址，跳过探测 |
| `PANEL3_ORIGIN` | `https://3panel.erguotou.me/package` | 发布源（**含 `/package` 段**，见下） |
| `PANEL3_WORKDIR` | `./3panel-install` | 下载与解压目录。重复运行会复用已校验的包；只剩**未完成的分片**时会从断点续传（见下） |
| `PANEL3_RETRIES` | `5` | 每个地址的下载尝试次数 |
| `PANEL3_PROBE_RETRIES` | `6` | 每个地址的**版本探测**尝试次数（探测请求小但最易失败，故预算更大） |
| `PANEL3_LANG` | 跟随 `$LANG` | `zh` / `en` |
| `PANEL_BASE_DIR` / `PANEL_PORT` / `PANEL_*` | 空 | 交给 `install.sh`，填写即无人值守 |

无人值守安装 —— 变量必须放进**环境**，`install.sh` 不解析命令行参数：

```bash
sudo PANEL_PORT=10086 PANEL_USERNAME=admin PANEL_PASSWORD='<密码>' \
  bash -c "$(curl -sSL <上面的脚本地址>)"
```

**发布方式**：`packaging/quick_start.sh` 是唯一源文件。

| 工作流 | 触发 | 上传目标 |
| --- | --- | --- |
| `publish-bootstrap.yml` | 改动该文件并推 `main`，或手动触发 | `/package/quick_start.sh` |
| `release-stable.yml` | 发版（兜底，路径同上） | 同上 |

路径里**不带版本号**（用户的命令是固定的），所以改脚本不必发版。
`dist/quick_start.sh` 也会随构建产出。

> ⚠️ `.gitignore` 里上游留了一条裸文件名 `quick_start.sh`（本意是忽略下载到仓库
> 根目录的那份），它会把 `packaging/quick_start.sh` **一起静默忽略** —— 新文件在
> `git status` 里根本不出现，CI 里也就找不到文件。已锚定为 `/quick_start.sh`，
> 与 `/3pctl`、`/install.sh` 同一处理。

---

### 2.5 节点一键加入（`/package/join.sh`）

面板「多机管理」里创建节点后，页面直接给出这条命令（主控由
`core/app/service/node.go` 的 `joinBootstrapCommand()` 生成，token 一次性有效）：

```bash
PANEL3_MASTER='https://<面板地址>:<端口>' PANEL3_TOKEN='<一次性 token>' \
  bash -c "$(curl -sSL https://3panel.erguotou.me/package/join.sh)"
```

发布域名自带 CDN，直连即可。早期这里做过「先走加速前缀、失败再直连」的双保险，2026-09-20
随前缀代理一起移除。脚本一旦拿到手，后面的下载源选择在 `join.sh` 内部已有重试和回退，
不依赖命令本身再兜一层。

**为什么需要它**：`3panel-agent join` 能加入，但节点机器上**没有** `3panel-agent`
这个二进制 —— 上游一直假设运维已经手动装好了。现在由 `join.sh` 把「下载 → 校验 →
安装 → 换证书 → 起服务」串起来：

1. 探测架构（amd64 / arm64）
2. 解析版本（默认取 `stable` 的 `latest`，可用 `PANEL3_VERSION` 钉住）
3. 依次尝试 agent 独立包 → 整包，**按 `.sha256` 是否存在判断**，不做 404 猜测
4. 下载（`-C -` 续传 + 重试，镜像不支持 Range 时退回整包重下）
5. 校验 sha256，不一致就删包中止
6. 解压后交给**包内**的 `install-agent.sh`

安装逻辑放在包里而不是 `join.sh` 里，是为了让它跟二进制同版本演进；`join.sh` 只做引导。

**为什么要有 agent 独立包**：整包 50MB+（面板本体 + 前端产物 + 19MB GeoIP），而节点
只需要 agent。独立包约 26MB，少了一半。若某个版本没发独立包，`join.sh` 会自动回退到
整包抽取 agent（只留 `3panel-agent` / `3pctl` / `lang/` / `initscript/3panel-agent.*`，
并从 `/package/install-agent.sh` 单独取一份安装器），所以「忘了发独立包」不会让节点装不上。

**环境变量**

| 变量 | 含义 | 默认 |
| --- | --- | --- |
| `PANEL3_MASTER` / `PANEL3_TOKEN` | 面板地址与一次性 token（必填） | — |
| `PANEL3_ADDR` / `PANEL3_PORT` | 面板回连本机的地址 / 监听端口 | 自动探测 / `9999` |
| `PANEL3_BASE_DIR` | 安装目录 | `/opt` |
| `PANEL3_VERSION` | 钉住版本；留空取 `latest` | — |
| `PANEL3_ORIGIN` / `PANEL3_MIRROR` | 发布源 / 自建镜像 | `…/package` / — |
| `PANEL3_RETRIES` / `PANEL3_PROBE_RETRIES` | 下载重试 / 版本探测重试 | `5` / `6` |
| `PANEL3_WORKDIR` / `PANEL3_LANG` / `PANEL3_NO_FIREWALL` | 下载目录 / 提示语言 / 不放行端口 | `/tmp/3panel-agent-join` / `zh` / `0` |

**发布方式**

| 文件 | 工作流 | 触发 | 上传目标 |
| --- | --- | --- | --- |
| `packaging/join.sh` | `publish-bootstrap.yml` | 改这两个文件并推 `main`，或手动 | `/package/join.sh` |
| `packaging/install-agent.sh` | 同上 | 同上 | `/package/install-agent.sh` |
| `3panel-agent-<ver>-linux-<arch>.tar.gz` | `release-stable.yml` | 发版 | `/package/<channel>/<ver>/release/` |

`join.sh` / `install-agent.sh` 的路径同样**不带版本号**。

> ⚠️ `packaging/build-release.sh` 会把发布版本号盖章进两个包内的 `3pctl`
> （`ORIGINAL_VERSION=<version>`）。这一步**不能省**：`install.sh` 是从包内 `3pctl`
> 反读版本再写进 `/usr/local/bin/3pctl` 的，`core/init/viper` 又从那里取面板版本；
> 不盖章的话，装好的面板会把自己的版本报成字面量 `version`，节点上报给主控的也是它。

---

### 2.6 节点 agent 一键升级（`/package/upgrade-agent.sh`）

面板「多机管理 → 升级节点」给出这条命令（主控由 `core/app/service/node.go` 的
`NodeService.UpgradeCommand()` 生成，**不含 token**）：

```bash
bash -c "$(curl -sSL https://3panel.erguotou.me/package/upgrade-agent.sh)"
```

**为什么必须单独开一条通道**（2026-09-20 查证）：

- 主控升级**不带动节点**。core 不校验节点版本，只在节点列表里展示，所以不能靠发版解决。
- **重跑一键加入命令走不通**：join token 是一次性的（`nodeTokenRepo` 的 `Used`），
  且 `Create` 遇到同名节点直接报 `ErrRecordExist` —— 已加入的节点拿不到新 token。
- 于是升级退化为**纯换二进制**：证书与注册关系都在 `<base-dir>/3panel` 下，原样保留即可。

**流程**（`packaging/upgrade-agent.sh`，只做引导）：

1. 从 `/usr/local/bin/3pctl` 反读现有 `BASE_DIR` / `ORIGINAL_VERSION` / `ORIGINAL_PORT` /
   `LANGUAGE`（缺失时分别回退 `/opt`、空、`9999`、`zh`）
2. 解析目标版本 —— **只读单一频道**（默认 `stable`），不像 `join.sh` 那样遍历
   stable/dev/beta：节点必须跟主控待在同一条通道上
3. 找包：agent 独立包 → 整包回退（按 `.sha256` 是否存在判断）
4. 下载 + 校验 sha256，不一致就删包中止
5. 解压后调用**包内** `install-agent.sh --no-join`

`install-agent.sh` 的 `--no-join`（`PANEL3_NO_JOIN=1`）复用安装器的全部步骤，只跳过
`open_firewall` 与 `run_join`；同时因为不换证书，`parse_args` 里对 `--master` / `--token`
的必填校验也被跳过。`BASE_DIR` / 端口 / 语言沿用调用方传入的现值，**不改变节点布局**。

**环境变量**

| 变量 | 含义 | 默认 |
| --- | --- | --- |
| `PANEL3_CHANNEL` | 发布频道 | `stable` |
| `PANEL3_VERSION` | 钉住版本；留空取该频道 `latest` | — |
| `PANEL3_ARCH` | 覆盖架构探测 | `uname -m` |
| `PANEL3_ORIGIN` / `PANEL3_MIRROR` | 发布源 / 自建镜像 | `…/package` / — |
| `PANEL3_RETRIES` / `PANEL3_PROBE_RETRIES` | 下载重试 / 探测重试 | `5` / `6` |
| `PANEL3_WORKDIR` / `PANEL3_LANG` | 下载目录 / 提示语言 | `/tmp/3panel-agent-upgrade` / `zh` |
| `PANEL3_FORCE=1` | 目标版本与当前一致时也重装一遍 | `0` |

目标版本与节点当前 `ORIGINAL_VERSION` 相同时脚本**直接退出**（exit 0），不会白停一次服务；
要强制重装用 `PANEL3_FORCE=1`。

**发布方式**

| 文件 | 工作流 | 触发 | 上传目标 |
| --- | --- | --- | --- |
| `packaging/upgrade-agent.sh` | `publish-bootstrap.yml` | 改文件并推 `main`，或手动触发 | `/package/upgrade-agent.sh` |

`build-release.sh` 也会把它复制进 `dist/`，`release-stable.yml` 发版时顺带上传一次作为兜底。
路径同样**不带版本号**。

> ⚠️ 该脚本依赖节点上存在 `/usr/local/bin/3pctl` 与 `3panel-agent`（即当初是用一键命令
> 加入的）。两者缺一时会明确报错而不是装出一份半成品。

---

## 三、升级包（tar.gz）内部结构要求

包内**必须**有与文件名同名的顶层目录，因为解包后代码按
`3panel-{version}-linux-{arch}` 去取：

```
3panel-v1.0.0-linux-amd64/          ← 顶层目录名必须与包名一致
├── 3panel-core                     → 覆盖 /usr/local/bin/3panel-core
├── 3panel-agent                    → 覆盖 /usr/local/bin/3panel-agent
├── 3pctl                           → 覆盖 /usr/local/bin/3pctl
├── install.sh                      → 全新安装用（升级路径不读）
├── GeoIP.mmdb                      → 覆盖 {install_dir}/3panel/geo/GeoIP.mmdb
├── lang/                           → 覆盖 /usr/local/bin/lang
│   ├── en.sh
│   └── zh.sh
└── initscript/
    ├── 3panel-core.service|openrc|init|procd
    └── 3panel-agent.service|openrc|init|procd
```

`initscript` 下取哪个文件由 `controller.SelectInitScript()` 按 init 系统决定：
systemd → `.service`、openrc → `.openrc`、sysvinit → `.procd`（OpenWrt）或 `.init`。

> `3pctl` 头部有一段 `KEY=VALUE` 会被面板**就地改写**：
> `BASE_DIR`、`LANGUAGE`（见 `ctl_conf.UpdateInFile`），
> 另有 `ORIGINAL_PORT` / `ORIGINAL_VERSION` / `ORIGINAL_USERNAME` /
> `ORIGINAL_PASSWORD` / `ORIGINAL_ENTRANCE` 会在首次启动时被读取。
> **这些键一个都不能删** —— `ctl_conf.Load()` 读不到会 panic。
> 仓库内模板见 `packaging/3pctl`。

---

## 四、安全机制现状

### 4.1 升级包 sha256 完整性校验（已实现 ✅）

在「下载完成」与「解包」之间插入校验（`verifyUpgradePackage`）：

1. 请求 `{升级包完整地址}.sha256`；
2. **能取到有效摘要** → **强制校验**，不一致则**中止升级**
   （`SystemStatus` 复位为 `Free`，不覆盖任何文件），日志记 `integrity check failed`；
3. **取不到（404 / 网络失败 / 无有效摘要）** → 记 `Warnf` 后**继续升级**，
   避免发布流程因缺少该文件而中断。

日志表现：
- 通过：`integrity verified: 3panel-v1.0.0-linux-amd64.tar.gz sha256=<摘要>`
- 跳过：`checksum ... unavailable (status 404, ...), integrity verification skipped`

发布时生成（一行即可，裸摘要或 `sha256sum` 格式都支持）：

```bash
sha256sum 3panel-v1.0.0-linux-amd64.tar.gz > 3panel-v1.0.0-linux-amd64.tar.gz.sha256
```

相关代码：`core/utils/files/files.go`（`FileSHA256` / `VerifyFileSHA256` / `ParseSHA256File`）、
`core/app/service/upgrade.go`（`verifyUpgradePackage`），
单元测试 `core/utils/files/checksum_test.go`（17 个用例）。

### 4.2 升级后远程脚本执行机制（已删除 ✅）

原来升级成功后会 `go writeLogs(version)` → 下载 `installation-log.sh` →
`sh -s 1p upgrade <version>` 以 root 执行。该脚本**对面板功能零贡献**（只做统计上报），
现已连同 `writeLogs`、`runRemoteShellScript`、`logs` 常量一并删除。
全项目已无 `installation-log` / `writeLogs` / `runRemoteShellScript` 残留。

---

## 五、自动发布（GitHub Actions）

`.github/workflows/release-stable.yml` 已就绪，配合 `packaging/` 一起工作：

```
packaging/
├── 3pctl                    # 控制脚本模板（含必需 KEY=VALUE 占位符）
├── install.sh               # 全新安装脚本
├── build-release.sh         # 本地/CI 通用打包脚本
└── initscript/              # core+agent 的 systemd / openrc / sysvinit / procd 定义
```

### 5.1 触发方式

- **推 tag**：`git tag v2.0.2 && git push github v2.0.2`
- **手动**：Actions → Release stable → Run workflow，填版本号

> 远端说明：本仓库有两个 remote —— `origin` 指向 `cnb.cool`（**不跑**这个 workflow），
> 发布走 `github`（`git@github.com:erguotou520/3Panel.git`）。别推错。
> 版本号必须**大于当前已安装的版本**，否则 `checkVersion()` 判定 remote 不大于
> current，面板不会提示升级。仓库里 `app.yaml` 的 `version` 只是开发默认值 ——
> 构建时会用 tag 覆盖它（见 §5.2），所以它不构成发布门槛。

版本号含 `beta` 时发布到 `beta` 通道，否则 `stable` **和 `dev`** —— 面板读 `stable`
（本仓 2026-09-20 起 `mode: stable`），`dev` 是发给切换之前装出的 `mode: dev` 旧实例的
兼容副本（见 §2.1）。

### 5.2 本地先验证一遍

```bash
# 复用已有前端产物，只打 amd64，快
SKIP_FRONTEND=1 ./packaging/build-release.sh v1.0.0 amd64

# 完整构建（前端 + amd64 + arm64）
./packaging/build-release.sh v1.0.0
```

产物落在 `dist/`：

```
dist/3panel-v1.0.0-linux-amd64.tar.gz
dist/3panel-v1.0.0-linux-amd64.tar.gz.sha256
dist/3panel-v1.0.0-linux-arm64.tar.gz        (+ .sha256)
dist/package/stable/latest
dist/package/stable/latest.current
dist/package/dev/latest            # 非 beta 版本会同时生成（见 §2.1 的 mode 说明）
dist/package/dev/latest.current
```

> ⚠️ **构建脚本会把 tag 版本写进 `core/cmd/server/conf/app.yaml` 再编译。**
> 该文件是 `//go:embed` 进 core 二进制的，而 `core/init/hook/hook.go` 的 `Init()`
> **每次启动**都会把数据库里的 `SystemVersion` 同步成它。版本号不写进包，升级后一重启
> 就回落到旧值，面板会永远提示同一个版本可升级。
> `build-release.sh` 在第 2 步做这件事，并在退出时把仓库文件还原（不污染工作区）；
> 验证方式：`strings <包内>/3panel-core | grep 'version: v'`。

### 5.3 上传目标（workflow 自动完成，需先配置）

Workflow 用 S3 兼容协议上传，适配 **Cloudflare R2 / AWS S3 / MinIO / 阿里云 OSS**。
在仓库 Settings → Secrets and variables → Actions 配置：

| 类型 | 名称 | 示例 |
| --- | --- | --- |
| Variable **或** Secret | `S3_BUCKET` | `3panel`（留空则跳过上传，只出 artifact） |
| Variable **或** Secret | `S3_ENDPOINT` | `https://<account>.r2.cloudflarestorage.com` |
| Secret | `AWS_ACCESS_KEY_ID` | R2/S3 的 Access Key |
| Secret | `AWS_SECRET_ACCESS_KEY` | 对应 Secret |
| Secret | `AWS_REGION` | 可选，R2 填 `auto` |

上传后的对象布局（桶根 = 域名根）：

```
package/stable/latest
package/stable/latest.current
package/stable/v1.0.0/release/3panel-v1.0.0-linux-amd64.tar.gz
package/stable/v1.0.0/release/3panel-v1.0.0-linux-amd64.tar.gz.sha256
package/stable/v1.0.0/release/3panel-v1.0.0-release-notes
package/dev/...                        # 非 beta 版本会整套再发一份（见 §2.1）
resource/language/lang.tar.gz          # 资源通道，非 package 通道
```

> `resource/language/lang.tar.gz` 由同一次发布顺带上传（`build-release.sh` 产出
> `dist/lang.tar.gz`）。它是面板在 `/usr/local/bin/lang` 缺失时唯一的获取途径，
> 因此必须保持在线 —— 详见 §5.4 与 §八。

### 5.4 语言包与 GeoIP

**语言包**：打包脚本优先使用仓库内置的 `packaging/lang/{en,zh}.sh`，
**不依赖外部主机**，构建可复现。仅当仓库内没有时才回退到
`RESOURCE_BASE/language/lang.tar.gz`。

同一份语言包还会被额外打成 `dist/lang.tar.gz`，作为**资源通道**对象
（`/resource/language/lang.tar.gz`）供面板运行时下载 —— 与升级包内的 `lang/` 同源，
不会出现两份内容漂移。两个文件的用途不同：

| 产物 | 谁来读 | 何时读 |
| --- | --- | --- |
| 包内 `lang/` | `initLang()` 从升级包 `tmp/<ver>/downloads/` 复制 | 升级时 |
| `dist/lang.tar.gz` | `downloadLangFromRemote()` 解到 `/usr/local/bin/` | `/usr/local/bin/lang` 缺失时 |

> ⚠️ `lang/` 内**必须**含 `zh.sh`。`core/init/geo/lang.go` 的 `initLang()` 用
> `/usr/local/bin/lang/zh.sh` 作为「语言包已安装」的哨兵 —— 缺了它，面板**每次启动都会
> 尝试重新下载**语言包。打包脚本已加这一步校验并会在缺失时告警；
> `dist/lang.tar.gz` 也必须保留这个文件（脚本从同一 `lang/` 目录打的包，天然满足）。

脚本还会优先从升级包内的 `lang/` 目录复制（而不是下载），所以把语言包打进包里
能让面板在无外网 / 资源域名不可用时也能拿到文案。

**只带 en/zh 是安全的**（已核过，不必凑齐上游的 5 种语言）：

- 仓库这份是**定制子集**：`en.sh` / `zh.sh` 各 47 键，键集合完全一致，`bash -n` 通过；
- 已用脚本提取 `3pctl` 与 `install.sh` 里引用的全部 `$VAR` 逐个比对语言包定义 ——
  **零缺失**（唯一命中的 `PANEL_PASSWORD` 是 install.sh 自己的局部变量，不是文案键）；
- 上游那份 112~114 键的通用包（en/fa/pt-BR/ru/zh）多出来的是 Docker 安装、加速源、
  语言选择提示等我们脚本用不到的键；
- 万一将来选了没有语言文件的语言也不会出现「文案全空」：`install.sh` 的
  `select_language()` 会回退到 `en`，`upgrade.go` 也用
  `ctl_conf.UpdateInFile("/usr/local/bin/3pctl", "LANGUAGE", oldLang)` 保留旧值。

**GeoIP**：仓库无法内置（19.5 MB 二进制 + 上游授权数据）。按以下优先级取：

1. `GEOIP_FILE=/path/to/GeoIP.mmdb` —— 本地文件，构建时原样打进包里
2. `<RESOURCE_BASE>/geo/GeoIP.mmdb` —— **你自己托管的副本（推荐）**
3. `GEOIP_FALLBACK` —— 默认指向上游 1Panel 的副本，见下

**先下载一份**（这份是本仓库唯一验证过、schema 能对上的）：

```bash
curl -fL -o GeoIP.mmdb \
  https://resource.fit2cloud.com/1panel/resource/geo/GeoIP.mmdb
ls -lh GeoIP.mmdb        # 约 19.5 MB
```

把它上传到你的资源域名即可，之后构建会优先用它：

```bash
# 自己托管（推荐，构建不再依赖上游）
#   上传到 https://3panel.erguotou.me/resource/geo/GeoIP.mmdb
SKIP_FRONTEND=1 ./packaging/build-release.sh v1.0.0 amd64

# 或者临时用本地文件 / 关掉 fallback
GEOIP_FILE=/tmp/GeoIP.mmdb GEOIP_FALLBACK= ./packaging/build-release.sh v1.0.0
```

> ### ⚠️ 不能用 MaxMind 官方 GeoLite2，schema 不匹配（会静默失效）
>
> `core/utils/geo/geo.go` 的 `LocationRes` 解码的是**自定义记录结构**，字段全在顶层：
>
> ```
> iso            : "CN"
> country        : {en: "China", zh: "中国"}
> latitude       : 32.0617
> longitude      : 118.7632
> province       : {en: "Jiangsu", zh: "江苏"}
> ```
>
> MaxMind 官方 GeoLite2-City 用的是 `country.iso_code` / `country.names.en` /
> `location.latitude` / `subdivisions[]` —— **嵌套层级完全不同**。
> 把官方文件直接替换进去**不会报错**，但每次查询都解析成空字符串：
> 登录日志的 IP 归属地会一片空白，且看不出哪里坏了。
>
> 只有 1Panel 发布的这份 mmdb 是重构过 schema 的（`database_type` 仍标称
> `GeoLite2-City`，但字段已扁平化 + 中英双语），所以**别换源**。
>
> 验证一份 mmdb 能不能用：
>
> ```bash
> pip install maxminddb
> python3 -c "
> import maxminddb, json
> r = maxminddb.open_database('GeoIP.mmdb')
> print(json.dumps(r.get('114.114.114.114'), ensure_ascii=False))
> # 期望: {'country': {'en': 'China', 'zh': '中国'}, 'iso': 'CN', 'latitude': ..., 'province': {'en': 'Jiangsu', 'zh': '江苏'}}
> "
> ```

取不到只警告不失败。缺失后果：登录日志里的 IP 归属地显示为空，其它功能不受影响
（面板启动时会自己从 `ResourceURL()` 下载一次）。

#### 5.4.1 GeoIP 需要后续维护吗？——基本不需要

**当前状态（2026-09-18 实测）**：

| 项 | 值 |
| --- | --- |
| sha256 | `fcad15e747a1fc3091ff69c36609fa1bf0721f453ea3f019d03bf7002976c80b` |
| md5 / HTTP ETag | `ed1d4dff6046ca32d5c7e6d86663b18b` |
| 大小 | 19,565,776 B（≈19.5 MB） |
| `database_type` | `GeoLite2-City`（字段已扁平化，见上方警告） |
| **数据构建时间** | **2024-12-25 13:52 (CST)**，即已 632 天 / 1.73 年 |
| 自托管地址 | `https://3panel.erguotou.me/resource/geo/GeoIP.mmdb` → HTTP 200 ✅ |

两点关键结论：

1. **上游自 2024-12-25 起就没有重建过这份库。** 本次从
   `https://resource.fit2cloud.com/1panel/resource/geo/GeoIP.mmdb` 重新下载的文件，
   与自托管那份、与你手上那份**逐字节完全一致**（`cmp` 无差异）。
   也就是说：你手上这份**就是最新版**，没有"更新的版本"可换。
   另一条独立佐证：1Panel v2 的新前缀 `/1panel/resource/v2/` 下**没有** `geo/` 目录
   （如 §2.2 的路径对照表），说明上游新版仍在复用这份 v1 文件，短期内不会有替代品。
2. **面板不会自动刷新它。** `agent/init/lang/lang.go` 的 `initLang()` 第一句判断是
   `if isLangExist && isGeoExist { return }` —— 文件存在就直接返回，永不下重。运行期
   唯一会覆盖它的是**升级包**：`core/app/service/upgrade.go` 在升级时把包内
   `GeoIP.mmdb` 拷到 `<install-dir>/3panel/geo/`。所以"更新 GeoIP" = 换掉资源站上的文件
   并打一个新版本包，不需要改任何代码或配置。

**影响面很小**：mmdb 在整仓只有两处只读用途 —— 登录日志的 IP 归属地
（`core/app/service/logs.go`）和 SSH 会话归属地（`agent/app/service/ssh.go`），
纯展示字段。数据陈旧只表现为新 IP 段归属地显示为空或不准，不影响任何功能。

**可选的例行检查**（不检查也没有风险，上游两年才可能动一次）：

```bash
# 上游是否重建过？（变了才需要处理）
curl -fsSL https://resource.fit2cloud.com/1panel/resource/geo/GeoIP.mmdb | shasum -a 256
# 期望: fcad15e747a1fc3091ff69c36609fa1bf0721f453ea3f019d03bf7002976c80b

# 自托管副本是否与上游一致？（不一致说明该重新镜像）
curl -fsSL https://3panel.erguotou.me/resource/geo/GeoIP.mmdb | shasum -a 256
```

> 若某天上游 hash 变了，**先别急着替换**：重新跑一次 §5.4 的 python 验证，
> 确认 `iso` / `country` / `province` 仍是扁平结构。上游一旦改成官方嵌套 schema，
> 直接换文件会让归属地**静默变空**（见上方警告）。验证通过再上传镜像 + 打新包。

> 顺带一提：同一资源站上 `RESOURCE_BASE/language/lang.tar.gz` 目前是 **404**。
> 这是**可修且已修**的：`build-release.sh` 现在会顺带产出 `dist/lang.tar.gz`
> （内含 `lang/{en,zh}.sh`，与升级包内的语言包同源），发布工作流会把它上传到
> `s3://<bucket>/resource/language/lang.tar.gz`。手动补也很简单：
>
> ```bash
> # 本地构建产物已就绪：dist/lang.tar.gz
> tar -tzf dist/lang.tar.gz          # 期望: lang/  lang/en.sh  lang/zh.sh
> # 上传到 https://3panel.erguotou.me/resource/language/lang.tar.gz
> curl -sI https://3panel.erguotou.me/resource/language/lang.tar.gz | head -3   # 期望 200
> ```
>
> 注意包内**必须**是 `lang/` 顶层目录（面板用 `tar zxvfC lang.tar.gz /usr/local/bin/`
> 解包），且**必须**含 `zh.sh` —— 它是 `initLang()` 的「语言包已安装」哨兵。

---

## 六、代理连通性检测是什么

`core/app/service/setting.go` 的 `checkProxy()`，在**保存代理配置时**（设置 → 代理）
用你填的代理发一个 GET 请求，验证代理是否可用；失败则拒绝保存（`ErrProxySetting`）。

要点：

- 只验证**能否建连并读到响应**，**不检查状态码** —— 返回 404 也算成功；
- 目标地址硬编码，现为 `https://3panel.erguotou.me/`（上游为 `1panel.cn`）；
- 超时已从 3s 放宽到 **10s**（跨境经代理建连 3s 偏紧，容易误判失败）。

> **注意**：这是 **HTTP/HTTPS/SOCKS5 正向代理**（用于受限网络下拉取镜像、升级包），
> 与「前缀式反代」（形如 `https://<前缀域名>/https://github.com/...`）**不是一回事**。
> 后者是 URL 重写服务，面板的代理设置填不进去，也不能直接替代。

---

## 七、本次改动清单

| 文件 | 改动 |
| --- | --- |
| `core/global/global.go` / `agent/global/global.go` | `RepoURL()` / `ResourceURL()` → `https://3panel.erguotou.me/package`、`/resource` |
| `core/app/service/logs.go` | **删除** `writeLogs` / `runRemoteShellScript` / `logs` 常量与相关 import |
| `core/app/service/upgrade.go` | 移除 `go writeLogs(...)` 调用；新增 `verifyUpgradePackage` 强制 sha256 校验 |
| `core/utils/files/files.go` | 新增 `FileSHA256` / `VerifyFileSHA256` / `ParseSHA256File` |
| `core/utils/files/checksum_test.go` | 新增单元测试（17 用例） |
| `core/app/service/setting.go` | 代理检测目标 → 自有域名；超时 3s → 10s；恢复 TLS 校验 |
| `core/utils/req_helper/requset.go` | 恢复 TLS 证书校验（移除 `InsecureSkipVerify: true`） |
| `agent/utils/req_helper/request.go`、`agent/utils/version/version.go` | 同上 |
| `core/utils/xpack/helper/multi_node_helper.go`、`agent/utils/xpack/helper/multi_node.go` | 同上（注释本就要求信任系统根证书） |
| `agent/utils/cloud_storage/client/ali.go` | 移除 8 处 `InsecureSkipVerify`（`api.alipan.com` 是公网 CA 证书） |
| `core/utils/cloud_storage/refresh_token.go` | 同上（`api.aliyundrive.com`） |
| `packaging/join.sh` | **新增**：节点一键加入引导脚本（取版本 → 选下载源 → 拉 agent 独立包，缺则回退整包 → 校验 → 解压 → 交接给包内 `install-agent.sh`），见 §2.5 |
| `packaging/install-agent.sh` | **新增**：节点侧安装器（装二进制 + 改写 `3pctl` + 语言包 + 服务定义 → 执行 `3panel-agent join` → 起服务） |
| `packaging/build-release.sh` | 新增 `3panel-agent-<ver>-linux-<arch>.tar.gz`（+ `.sha256`）产出；产出 `join.sh` / `install-agent.sh`；给两个包内的 `3pctl` 盖章 `ORIGINAL_VERSION=<version>` |
| `core/app/service/node.go` / `core/app/dto/node.go` | 新增 `joinBootstrapCommand()`：`Create()` 除原始 `3panel-agent join` 命令外，再返回一条带加速前缀、失败回退直连的一键命令；DTO 增加 `agentCommand` |
| `frontend/src/views/setting/node/index.vue`、`api/interface/setting.ts`、`lang/modules/{zh,en}.ts` | 加入命令对话框展示一键命令（可复制、显示过期时间），折叠区保留原始 `3panel-agent join` |
| `.github/workflows/publish-bootstrap.yml` | 扩展为同时发布 `join.sh` / `install-agent.sh`（路径同样不带版本） |
| `.github/workflows/publish-bootstrap.yml` | **新增**：改动 `packaging/quick_start.sh` 即上传 `/package/quick_start.sh`（路径不带版本，用户命令固定） |
| `.gitignore` | 裸文件名 `quick_start.sh` 锚定为 `/quick_start.sh`（原规则会静默忽略 `packaging/quick_start.sh`） |
| `packaging/` | **新增**：`3pctl`、`install.sh`、`build-release.sh`、`initscript/`（8 个服务定义）、`lang/`（内置语言包） |
| `packaging/build-release.sh` | 新增 `dist/lang.tar.gz` 产出（资源通道语言包）；GeoIP 多源取源 + `GEOIP_FILE`；新增「把 tag 版本 stamp 进 `go:embed` 的 `conf/app.yaml`，退出时还原」 |
| `scripts/cf-appstore-sync/src/index.js` | 新增 `/sync-resource` 端点：把上游脚本库（+可选语言包 / GeoIP）镜像进 R2，带发布前校验与 stamp 幂等 |
| `.github/workflows/release-stable.yml` | **新增**：tag 触发自动打包并发布到约定路径；含 `resource/language/lang.tar.gz` 上传。非 beta 版本同时发 `stable`+`dev`；`S3_*` 改由 job 级 `env` 取值（`secrets` 不能用于 `if:`），未配置打 `::warning::` |
| `frontend/src/**` | 移除商业版推广/论坛/定价外链（详见安全报告） |

---

## 八、上线前自检

一条命令体检所有面板会请求的地址：

```bash
B=https://3panel.erguotou.me
# 用 HEAD 的 content-length 报「对象真实大小」。不要用 GET 的 %{size_download}：
# 链路慢时 curl 会在 --max-time 内被掐断，那个数字是「已下载多少」，看着像文件变小了
# （实测 GeoIP 19.5 MB 被报成 3.5 MB / 6.8 MB，极易误判成文件损坏）。
probe() {
    h=$(curl -sS -I -L --max-time 25 "$1" 2>/dev/null)
    printf '%-4s %-11s %s\n' \
        "$(printf '%s' "$h" | awk '/^HTTP/{c=$2} END{print c}')" \
        "$(printf '%s' "$h" | tr -d '\r' | awk 'tolower($1)=="content-length:"{n=$2} END{print n+0}')" \
        "$1"
}
probe $B/resource/geo/GeoIP.mmdb
probe $B/resource/language/lang.tar.gz
probe $B/resource/scripts/data.yaml
probe $B/resource/scripts/scripts.tar.gz
probe $B/resource/scripts/version.txt
probe $B/package/stable/latest
probe $B/package/dev/latest          # dev 兼容副本，旧 mode: dev 实例读它（见 §2.1）
probe $B/package/quick_start.sh      # 一键安装脚本（路径不带版本，见 §2.4）
probe $B/package/join.sh             # 节点一键加入（路径不带版本，见 §2.5）
probe $B/package/install-agent.sh    # 整包回退时 join.sh 会单独取它
probe $B/dev/3panel.json.zip         # 应用商店也按 mode 分目录
probe $B/dev/3panel.json.version.txt

# agent 独立包（替换 <ver> / <arch>）
V=$(curl -sS --max-time 20 "$B/package/stable/latest")
probe $B/package/stable/$V/release/3panel-agent-$V-linux-amd64.tar.gz
probe $B/package/stable/$V/release/3panel-agent-$V-linux-amd64.tar.gz.sha256
probe $B/package/stable/$V/release/3panel-agent-$V-linux-arm64.tar.gz
```

> 探测包是否存在时，**路径必须带 `/{version}/release/` 段**：
> `package/{channel}/{version}/release/{archive}`。写成 `package/{channel}/{archive}`
> 会拿到一片 404，很容易误报成「这个版本的包丢了」。

**2026-09-20 实测结果（v2.0.4）**：

| 路径 | 状态 | 影响 / 处理 |
| --- | --- | --- |
| `/resource/geo/GeoIP.mmdb` | ✅ 200（19,565,776 B） | 正常，见 §5.4 |
| `/resource/language/lang.tar.gz` | ✅ 200（2,267 B） | 与 `dist/lang.tar.gz` 同源 |
| `/resource/scripts/*` | ✅ 200（`version.txt` 10 B / `data.yaml` 7,345 B / `scripts.tar.gz` 10,672 B） | Worker 的 `/sync-resource` 已部署并跑过；`scripts.tar.gz` 与上游逐字节一致 |
| `/package/{stable,dev}/latest` | ✅ 200 → `v2.0.4`（各 6 B，无尾换行） | 发布通道已上线 |
| `/package/quick_start.sh` | ✅ 200（18,732 B） | 一键安装，见 §2.4 |
| `/package/join.sh` | ✅ 200（16,239 B） | 节点一键加入，见 §2.5 |
| `/package/install-agent.sh` | ✅ 200（12,249 B） | 整包回退时 `join.sh` 单独取它 |
| `…/release/3panel-v2.0.4-linux-{amd64,arm64}.tar.gz` | ✅ 200（60,697,184 / 56,532,376 B） | 整包 |
| `…/release/3panel-agent-v2.0.4-linux-{amd64,arm64}.tar.gz` | ✅ 200（27,284,642 / 24,479,770 B） | **agent 独立包**，v2.0.3 起才有 |
| `/stable/3panel.json.zip`、`.version.txt` | ✅ 200（446,314 B） | 应用商店正常（当前 `mode: stable` 对应这一份；`/dev/` 下同样有一份，给旧实例） |
| `/package/beta/latest` | 404 | 正常：还没发过 beta |

v2.0.4 发布后核对：两个频道都是 `v2.0.4`，`latest.current` 为 `{"v2.0": "v2.0.4"}`，
四个包（整包 / agent × 两架构）均 206，下载 agent-arm64 重算 sha256
`beea79bf…c7a576` 与线上 `.sha256` 一致。

更早的端到端（2026-09-19，v2.0.3）：解析 `v2.0.3` → **直接命中 agent 独立包** →
sha256 `1e5e5d21…2b0cfc7` 与线上 `.sha256` 一致 → 解压 → 交给 `install-agent.sh`。
（v2.0.2 时同一测试会走整包回退，因为那次发布早于 agent 独立包。）

### 首次发布已完成（2026-09-18，v2.0.1）

`v2.0.1` 是发布通道的第一次真实发布，端到端核过（不只是看 CI 变绿）：

| 校验项 | 结果 |
| --- | --- |
| `gh run watch` | 12 步全绿，6m17s |
| `/package/{stable,dev}/latest` | `v2.0.1`，hex 确认**无尾换行** |
| `/package/{stable,dev}/latest.current` | `{"v2.0": "v2.0.1"}` |
| 包体（两个频道各一份） | 200 / 60,729,158 B |
| 下载后本地重算 sha256 | `47385b39…187a`，与已发布 `.sha256` **完全一致** |
| 包顶层目录 | `3panel-v2.0.1-linux-amd64`（符合 `upgrade.go` 取路径的契约） |
| `strings 3panel-core` | `version: v2.0.1` —— 构建期的版本 stamp 生效 |

后续发版：

```bash
git tag v2.0.4 && git push github v2.0.4    # 触发 release-stable.yml（远端是 github，不是 origin）
```

`v2.0.4` 刚按此流程发过（2026-09-20：两个频道 + 两个架构 + agent 独立包全齐，`latest`
与 `latest.current` 都指向它）。更早的 `v2.0.1` / `v2.0.2` / `v2.0.3` 同样跑通，
所以这条链路是稳的。

⚠️ 唯一约束：**新 tag 必须大于当前已安装的版本**，否则 `checkVersion()` 判定 remote
不大于 current，面板不会提示升级。仓库里 `core/cmd/server/conf/app.yaml` 的 `version`
只是开发默认值 —— 构建时会用 tag 覆盖它（见 §5.2），所以它**不**构成发布门槛。

前提是仓库已配置好对象存储：

| 名称 | 类型 | 示例 |
| --- | --- | --- |
| `S3_ENDPOINT` | Variable **或** Secret | `https://<account>.r2.cloudflarestorage.com` |
| `S3_BUCKET` | Variable **或** Secret | `3panel` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Secret | R2/S3 的 key |
| `AWS_REGION` | Secret（可选） | 默认 `auto` |

> **坑（曾踩过）**：`secrets` 上下文在 `if:` 条件里**不可用**（GitHub 的
> context-availability 表里没有它），所以两个 `S3_*` 只要有人配成了 Secret、
> 而 `if:` 读的是 `vars.*`，Publish 步骤就会**静默跳过** —— 日志里只是少一段，
> 不报错，现象是面板永远提示「已是最新」。
> 现在工作流把取值放在 job 级 `env`（`vars.S3_BUCKET || secrets.S3_BUCKET`），
> `if:` 读 `env.S3_BUCKET`，两处都认；另有一个 `Check publish configuration`
> 步骤会在未配置时打 `::warning::`，不再静默。

### 脚本库 404 的影响与处理

`core/app/service/script_library.go` 会拉 `/resource/scripts/{data.yaml,scripts.tar.gz,version.txt}`。
全 404 意味着**脚本库同步每次都失败**，而 `ScriptSync` 默认是 `StatusEnable`，
所以启动时同步一次、之后每天最多 3 次都会报错，面板里也拉不到系统脚本。

处理方式：`scripts/cf-appstore-sync` 这个 Worker 的 `/sync-resource` 端点从上游 v2 前缀
镜像这三个小文件（约 20 KB），详见 §2.2。

> TLS 校验已恢复：上述地址必须使用**受信任 CA 签发的证书**
> （Cloudflare 托管默认满足）。自签名证书会导致升级失败 —— 这是预期行为。

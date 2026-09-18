# appstore-mirror

把上游 1Panel 应用商店**完整**镜像到你自己的 R2 桶，在本地跑（Node，无 Cloudflare Worker 的子请求数限制）。

```
┌─ 上游 ──────────────────────────┐        ┌─ 你的 R2 ─────────────────────────────┐
│ apps.1panel.pro/dev/1panel/...  │  ───▶  │ 3panel.erguotou.me/dev/3panel/...     │
└─────────────────────────────────┘        └───────────────────────────────────────┘
```

## 为什么需要它

面板会向 `AppRepoURL()`（= `https://3panel.erguotou.me`）请求这些文件，**少一个就会出问题**：

| 请求路径 | 缺失时的症状 |
| --- | --- |
| `<mode>/3panel.json.zip` | 同步应用商店失败 |
| `<mode>/3panel.json.version.txt` | 检测不到商店更新 |
| `<mode>/3panel/<app>/logo.png` | **应用图标全部空白** |
| `<mode>/3panel/<app>/<ver>/docker-compose.yml` | **打开安装页报「当前应用版本已从远程服务下架」、安装按钮点不了** |
| `<mode>/3panel/<app>/<ver>/<app>-<ver>.tar.gz` | 安装/升级时下载失败 |

两个容易踩的坑，这个脚本都处理了：

1. **图标和安装包在商店 JSON 里是绝对地址**（指向 `apps.1panel.pro`），所以镜像时必须同步改写 JSON，否则面板会一直回源到上游。
2. **`docker-compose.yml` 对「所有类型」的应用都需要**。面板在本地没有 compose 缓存时，任何应用的安装页都会去拉它（`agent/app/service/app.go`），并不是只有 `runtime/php/node` 需要。
   —— 之前的 `scripts/cf-appstore-sync` Worker 只镜像了 `runtime/php/node` 的 compose，且受**免费版单次 50 个子请求**限制每轮只能跑 ~50 个资源，所以镜像一直是残缺的。

## 前置准备

1. **R2 桶**（已有 `appstore` 桶则跳过）
2. **API Token**：Cloudflare 控制台 → R2 → API → Manage API Tokens → Create API Token
   - 权限选 `Object Read & Write`，范围限定到该桶
3. **公开访问域名**：给桶绑定自定义域名（这里就是 `3panel.erguotou.me`），或启用 `r2.dev` 域名
   - 面板通过这个域名取文件，必须是 https

## 使用

```bash
cd scripts/appstore-mirror
npm install

cp .env.example .env
# 编辑 .env，填 R2_ACCOUNT_ID / R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY

node --env-file=.env mirror.mjs
```

> Node 需要 ≥ 20.6 才能用 `--env-file`。低版本可以改成 `export $(grep -v '^#' .env | xargs) && node mirror.mjs`，或装 `dotenv`。

### 常用参数

| 命令 | 作用 |
| --- | --- |
| `node --env-file=.env mirror.mjs` | 增量同步（默认）：先列出桶里已有的对象，**只下载缺失的文件**；已有的发一次条件请求确认没变（304 则不重传） |
| `... mirror.mjs --force` | 忽略桶内已有对象与 ETag，全部重新拉取覆盖 |
| `... mirror.mjs --dry-run` | 只跑到「要传哪些文件」，不写 R2（不需要凭证） |
| `... mirror.mjs --verify-only` | 不传输，只抽样检查线上 URL 是否可访问 |
| `... mirror.mjs --limit 20` | 只处理前 20 个资源，用于试跑 |

其他可调项（写在 `.env` 里）：`CONCURRENCY`（并发，默认 6）、`TIMEOUT_MS`（单请求超时，默认 300000，应用包最大约 80 MB）、`SYNC_APP_PACKAGES`、`SYNC_DATA_YML`。

> **中断/失败后直接重跑即可**：脚本会列出桶内对象，已经传上去的完全不碰，只补缺的那些。所以断点续传不会重下 0.7 GB。
> 想确认当前到底缺什么，用 `--verify-only` 之外还可以跑一次同步：结束时打印的 `uploaded / already-present / missing-upstream / failed` 就是完整账目。

### 首次运行

完整镜像约 4440 个资源：192 图标 + 1416 `docker-compose.yml` + 1416 `data.yml` + 1416 安装包（安装包约 0.7 GB）。

**如果你的桶里已经有安装包**（`curl` 能直接下到 `.../<app>-<ver>.tar.gz`），可以先跳过安装包，省掉 0.7 GB 重传：

```bash
SYNC_APP_PACKAGES=false node --env-file=.env mirror.mjs
```

这样只会补 `docker-compose.yml` / `data.yml` / 图标（约 3000 个小文件）。

> ⚠️ **索引里所有地址（含安装包）始终指向你自己的 `DST_ORIGIN`，永远不会回退到上游。**
> 所以 `SYNC_APP_PACKAGES=false` 的前提是桶里确实已有全部安装包 —— 脚本会拿桶内清单核对，缺了就明确告警，不会偷偷把地址改回上游。
> 要补齐缺失的包，去掉这个开关再跑一次即可。

中断或个别失败后**直接重跑即可**：脚本先列出桶内对象，已经存在的完全不重新下载，只补缺的那些。失败的会重试；上游本身就是 404 的会归类为 `missing-upstream`（通常是非容器类应用，无害）。

## 跑完之后

回到面板点一次「应用商店 → 同步」，或重启 agent（`agent` 启动时会自动同步）。因为源码里 `AppRepoURL()` 指向你自己的域名，同步就会从你的 R2 取数据。

## 配置对照（必须一致）

| 脚本变量 | 必须等于 |
| --- | --- |
| `MODE` | `/opt/3panel/conf/app.yaml` 里的 `base.mode`（当前是 `dev`） |
| `DST_ORIGIN` | 源码 `AppRepoURL()` 的返回值（当前是 `https://3panel.erguotou.me`） |
| `SRC_ORIGIN` | 上游源站，保持默认 |

想同时镜像多个环境，分别跑：`MODE=dev node --env-file=.env mirror.mjs`、`MODE=stable node --env-file=.env mirror.mjs`（上游 `stable` 也存在）。状态文件按 `mode` 隔离，互不影响。

## 排查

- **抽样自检出现 FAIL**：确认桶的公开域名已生效、没有被 Cloudflare 缓存住旧内容（可在控制台 Purge Cache）。
- **403 / 429 变多**：上游对突发并发限流，把 `CONCURRENCY` 调小（例如 3）。
- **面板仍报「已从远程服务下架」**：说明该版本的 `docker-compose.yml` 没上到桶里。手动验证：
  ```bash
  curl -I https://3panel.erguotou.me/dev/3panel/act_runner/0.4.1/docker-compose.yml
  ```
  应为 `200`。
- **图标空白**：确认 `SYNC_APP_PACKAGES` 没被误设，以及 `<mode>/3panel/<app>/logo.png` 可访问。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `mirror.mjs` | 同步主程序（零依赖实现 zip 读写，仅上传需要 `@aws-sdk/client-s3`） |
| `.env.example` | 配置模板 |
| `.mirror-state.json` | 本地增量状态（ETag 缓存），已 gitignore |

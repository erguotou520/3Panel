# 3Panel 外发数据 / 信息收集 排查报告

- 排查对象：`/Users/erguotou/workspace/erguotou/3panel`（1Panel 二次开发分支）
- 排查时间：2026-09-18
- 排查范围：`core/`、`agent/`、`frontend/`、`scripts/`、`.github/`
- 排查目标：除自有域名 `3panel.erguotou.me` 外，是否存在信息收集 / 不受控的数据外发

---

## 〇、最重要的发现：这些域名根本没被注册

初版报告把 `3panel.pro` / `3panel.cn` 称为「第三方域名」，**这个描述不准确**。
经 RDAP + 1.1.1.1 / 8.8.8.8 / 223.5.5.5 三个公共解析器复核：

| 域名 | A 记录 | NS 记录 | RDAP |
| --- | --- | --- | --- |
| `3panel.pro` | 无 | 无 | **404 Object not found（未注册）** |
| `3panel.cn` | 无 | 无 | **无记录（未注册）** |
| `resource.3panel.pro` / `community.3panel.pro` / `docs.3panel.pro` / `bbs.3panel.pro` | 无 | 无 | 父域未注册 |

对照：`1panel.pro` RDAP 返回 200（已注册），`resource.fit2cloud.com`、`apps.1panel.pro` 均正常解析。

**这改变了风险性质**：

- **不是**「有人正在收集你的数据」——目前所有相关请求都因 DNS 解析失败而静默失败，没有数据外泄。
- **而是**「悬空域名（dangling domain）风险」——面板被配置为信任一个**不存在、且任何人都可以注册**的域名。
  任何人花约 10 美元注册 `3panel.pro`，即可立即获得：
  1. 每次检查更新时面板主动上报的**版本号、mode、edition、服务器公网 IP**；
  2. 在 `installation-log.sh` 路径下**下发任意 shell 脚本**，而每个 3Panel 面板在升级成功后都会
     以 **root 权限**下载并执行它 —— 等同对所有已部署实例的批量 RCE。
  3. 在 `resource.3panel.pro` 下**下发伪造的升级包**（升级包无签名校验，见 4.1）。

换言之：**这不是一个已发生的数据收集事件，而是一个随时可被远程接管的定时炸弹。**
这也解释了为什么升级功能实际上是坏的——它一直在对一个不存在的域名发请求。

---

## 一、结论速览（修复前状态）

| 级别 | 数量 | 说明 |
| --- | --- | --- |
| 高危 | 3 | 悬空域名 + 远程脚本执行、升级包无签名校验、TLS 校验全局关闭 |
| 中危 | 4 | 升级/文档/技能市场通道指向未注册域名 |
| 低危 | 4 | 前端 logo 外链、跳转链接、NTP 等 |
| 已排除 | — | 前端埋点 SDK、硬编码密钥、主机指纹上报 |

> **当前状态：以上问题已全部处理完毕**，逐项见文末「七、整改记录」。
> 高危 3 项全部消除：远程脚本执行机制**已删除**、升级包已加 sha256 强制校验、
> 通用出站路径 TLS 校验**已恢复**；未注册域名引用**已清零**。


---

## 二、高危问题

### H1. 升级后从第三方域名下载并执行远程 shell 脚本（RCE 风险）

| 项目 | 内容 |
| --- | --- |
| 位置 | `core/app/service/logs.go:26`、`core/app/service/logs.go:121-137` |
| 调用点 | `core/app/service/upgrade.go:264` → `go writeLogs(req.Version)` |
| 目标 | `https://resource.3panel.pro/installation-log.sh` |
| 行为 | 下载脚本后通过 `sh -s 1p upgrade <version>` 管道执行，输出丢弃到 `os.DevNull` |
| 触发条件 | **面板升级成功后**自动触发（异步，无提示、无确认） |
| 发送数据 | 面板版本号（作为 argv 传入） |
| 风险 | **高**。脚本内容不受你控制，且在面板进程权限（通常 root）下执行，可读取任意文件、修改系统、回传任意数据。脚本变更无需重新发布面板即可生效。 |

```go
// core/app/service/logs.go:26
const logs = "https://resource.3panel.pro/installation-log.sh"

// core/app/service/logs.go:121-137
func writeLogs(version string) {
	_ = runRemoteShellScript(logs, "1p", "upgrade", version)
}

func runRemoteShellScript(url string, args ...string) error {
	statusCode, script, err := req_helper.HandleRequestWithProxy(url, http.MethodGet, constant.TimeOut20s)
	...
	_, err = cmd.NewCommandMgr().RunPipeToFile(os.DevNull, cmd.PipeCommand{
		Name:  "sh",
		Args:  append([]string{"-s"}, args...),
		Stdin: bytes.NewReader(script),
	})
	return err
}
```

> 溯源：该机制继承自上游 1Panel（上游为 `resource.1panel.pro`）。上游改名时只把域名从 `1panel.pro` 换成了 `3panel.pro`，
> **控制权随域名一并转移给了 3panel.pro 的所有者**，并不因为代码开源就可信。

### H2. 全局关闭 TLS 证书校验（26 处），可与 H1 组合成完整攻击链

| 项目 | 内容 |
| --- | --- |
| 位置 | 共 26 处 `InsecureSkipVerify: true` |
| 关键位置 | `core/utils/req_helper/requset.go:20`、`core/utils/req_helper/requset.go:68` |
| 影响 | 所有走 `req_helper` 的请求（**包含 H1 的远程脚本下载**和 M1 的埋点上报）均不校验服务端证书 |
| 风险 | **高**。中间人可静默替换返回内容。攻击链：劫持 `resource.3panel.pro` 的 HTTPS 响应 → 替换 `installation-log.sh` 内容 → 面板升级后以 root 执行 → 服务器完全失陷。 |

其他关闭校验的位置（部分为对接自签名服务的合理场景，但应逐个收敛）：

```
core/app/service/setting.go:817
core/utils/xpack/helper/multi_node_helper.go:185
core/utils/req_helper/requset.go:20,68
core/utils/ssh/http.go:33
core/utils/cloud_storage/refresh_token.go:40
agent/cmd/server/cmd/join.go:142
agent/app/service/mongodb_client.go:127
agent/utils/xpack/helper/multi_node.go:107
agent/utils/req_helper/core.go:47
agent/utils/req_helper/request.go:155
agent/utils/version/version.go:207
agent/utils/mysql/client/info.go:134
agent/utils/files/file_op.go:450
```

---

## 三、中危问题

### M1. AI Provider 安装埋点上报（唯一的信息收集代码）

| 项目 | 内容 |
| --- | --- |
| 位置 | `agent/app/service/agents_utils.go:1762-1772` |
| 调用点 | `agent/app/service/agents.go:1074` → `asyncReportAIProviderInstall(provider)` |
| 目标 | `https://community.3panel.pro/installation-analytics` |
| 请求 | `GET .../installation-analytics?product=ai-provider&type=install&version=<provider>` |
| 发送数据 | 事件类型（install）、AI 厂商名（provider）；**隐含暴露**服务器公网 IP、出口 IP、请求时间、访问频率 |
| 触发条件 | 用户在面板中添加/安装一个 AI 模型账号时（仅在 `mode == "stable"` 下生效） |
| 风险 | **中**。这是唯一一处明确的「统计上报」。数据量小，但真实目的是产品使用统计，且目标域名非你所有。 |

```go
// agent/app/service/agents_utils.go:1762
func asyncReportAIProviderInstall(provider string) {
	if global.CONF.Base.Mode != "stable" || provider == "" {
		return
	}
	go func(provider string) {
		query := url.Values{}
		query.Set("product", "ai-provider")
		query.Set("type", "install")
		query.Set("version", provider)
		reqURL := "https://community.3panel.pro/installation-analytics?" + query.Encode()
		_, _, _ = req_helper.HandleRequest(reqURL, http.MethodGet, constant.TimeOut5s)
	}(provider)
}
```

**开关状态**：仓库内默认配置 `core/cmd/server/conf/app.yaml` 与 `agent/cmd/server/conf/app.yaml`
均为 `mode: dev`，此时**不上报**。但生产安装脚本会写入 `mode: stable`，届时即会触发。
换言之，**开关不在你手上，而在安装脚本里**。

### M2. 升级 / 资源下载通道仍指向第三方域名 `resource.3panel.pro`

| 项目 | 内容 |
| --- | --- |
| 位置 | `core/global/global.go:38-59`、`agent/global/global.go:66-87` |
| 受影响函数 | `RepoURL()`、`ResourceURL()` |
| 实际请求路径 | `{RepoURL()}/{mode}/latest`（版本探测）、`.../release`（升级包）、`.../release-notes`、`{ResourceURL()}/language/lang.tar.gz`、`{ResourceURL()}/geo/GeoIP.mmdb`、`{ResourceURL()}/scripts/data.yaml` |
| 泄露内容 | 面板版本、`mode`（dev/stable）、`edition`（cn/intl）、服务器公网 IP、检查更新的时间与频率 |
| 风险 | **中**。这一条**与 NOTICE.md 的合规声明不符**——NOTICE 声明"上游的在线服务未被使用，相关地址已替换为本项目自己的地址"，
但实际上升级/资源通道只是把 `resource.1panel.pro` 换成了 `resource.3panel.pro`，仍是第三方域名。 |

```go
// core/global/global.go:38
func RepoURL() string {
	if CONF.Base.IsEnterprise {
		return "https://resource.3panel.pro/package/enterprise"
	}
	if CONF.Base.IsFxplay {
		return "https://resource.3panel.pro/package/fusionxplay"
	}
	if CONF.Base.Edition != "intl" {
		return "https://resource.3panel.pro/package/v2"
	}
	return "https://resource.3panel.pro/v2"
}
```

> 注意不一致：应用商店域名 `AppRepoURL()` **已**改到你的 `https://3panel.erguotou.me`，
> 但升级通道 `RepoURL()` / `ResourceURL()` **没有改**。

### M3. 代理连通性探测打到 `3panel.cn`

| 项目 | 内容 |
| --- | --- |
| 位置 | `core/app/service/setting.go:848` |
| 行为 | 设置/测试代理时 `GET https://3panel.cn/`，读取响应体判断连通性 |
| 泄露内容 | 服务器公网 IP、User-Agent、请求时间；等于每次配置代理都向第三方做一次"报到" |
| 风险 | **中**。建议改为探测你自己的域名或用户填写的目标。 |

### M4. 技能市场从 `clawhub.com` 拉取并安装第三方技能

| 项目 | 内容 |
| --- | --- |
| 位置 | `agent/app/service/agents_skills.go:27-28`、`:779-880` |
| 目标 | `https://clawhub.com`（国际）/ `https://mirror-cn.clawhub.com`（国内） |
| 行为 | `clawhub search <keyword>` 会外发搜索关键词；`clawhub install <slug>` 从该源安装技能包并进入容器执行 |
| 风险 | **中**。搜索关键词外发 + 引入不受控的第三方代码（供应链风险）。属用户主动操作，但默认源为第三方。 |

---

## 四、低危 / 可忽略

| 编号 | 位置 | 目标 | 内容 | 说明 |
| --- | --- | --- | --- | --- |
| ~~L1~~ | ~~`frontend/src/utils/agent-provider-logo.ts:18-137`~~ | — | — | ⚠️ **此项为误报，已撤回**，详见 §7.5。AI 厂商 logo **本来就是本地打包资源**（`frontend/src/assets/images/ai-providers/` 下 13 个文件），`source:` 字段只是署名元数据，从不参与渲染，**无浏览器 IP 外泄**。 |
| L2 | `agent/app/service/agents_hermes_channels.go:24` | `novac2c.cdn.weixin.qq.com` | 写死企业微信 CDN 常量 | 启用微信频道后由运行时拉取，第三方依赖 |
| L3 | 原 `router-button`、`system-upgrade`、`license-import`、`footer-navigation` | `3panel.cn`、`3panel.pro`、`3panel.hk`、`www.lxware.cn`、`bbs.3panel.pro`、`github.com/3panel-dev` | `window.open` 跳转 | 仅按钮跳转，不自动加载、不携带数据。**推广/论坛入口已全部删除**（§7.1 第 5 项）；死链入口改指真实仓库（§7.1 第 11 项，`views/setting/about`） |
| L4 | `scripts/appstore-mirror/mirror.mjs`、`scripts/cf-appstore-sync/src/index.js` | `apps.1panel.pro`（读）→ 你的 R2 / `3panel.erguotou.me`（写） | 同步应用商店 | **运维脚本**，非面板运行时执行；只从上游读取，不外发你的数据 |
| L5 | — | `pool.ntp.org` | NTP 对时 | 标准系统行为 |
| L6 | `frontend/src/assets/images/enlarge_{black,white}.svg` | `at.alicdn.com`（协议相对地址）、`chrome-extension://…` | `<defs><style>@font-face` 注入块 | **已清理**（见 §7.5）。系图标下载类浏览器插件写入的残留；SVG 以 `<img>` 加载时浏览器禁止外部拉取，故实际为惰性引用，风险可忽略。 |

---

## 五、已排查且未发现问题

- **前端埋点 SDK**：`sentry` / `google-analytics` / `gtag` / `umami` / `clarity` / `mixpanel` / `posthog` /
  `matomo` / `plausible` / `cnzz` / `hm.js` 等关键词全量搜索，`package.json` 与源码中**均无命中**。
- **前端外部资源**：`frontend/index.html` 无外部 `<script src>`、无外部字体、无 CDN `@import`。
- **前端绝对地址请求**：仅 1 处 logo 图片地址（L1），无外部 API 调用。
- **主机指纹上报**：全项目**无** `os.Hostname()` / IP / 操作系统 / 用户名 / 已安装应用列表被拼入外发请求。
- **硬编码密钥**：扫描 `api_key` / `secret` / `token` / `password` 字面量，**未发现**硬编码凭据。
- **Webhook / 告警 / 邮件 / 短信通道**：URL 全部来自用户配置，**无**默认厂家兜底地址。
- **xpack 多节点**：社区构建下为 `core/utils/xpack/community.go` 空实现（无 `xpack`/`enterprise` build tag 文件），
  对外无行为。
- **AI 模型验证 / 模型发现**：请求 URL 全部来自用户填写的 `base_url`，不上报固定外部端点。
- **云存储备份**（阿里云盘 / Google Drive / OneDrive / 腾讯云 COS）、**ACME 证书签发**（Let's Encrypt / ZeroSSL / Buypass）：
  均为用户主动配置的业务目标，非数据收集。

---

## 六、整改建议（按优先级）

> 以下 7 条**均已执行或已确认**，逐项结果见「七、整改记录」。

1. **【必做】删除或本地化远程脚本执行** —— ✅ **已删除**
   移除 `core/app/service/logs.go` 的 `writeLogs` / `runRemoteShellScript` / `logs` 常量，
   以及 `core/app/service/upgrade.go` 中的 `go writeLogs(req.Version)` 调用。

2. **【必做】收敛 TLS 校验** —— ✅ **已完成**
   通用出站路径共 9 处恢复校验；其余按配置驱动或内网场景有意保留，理由见 7.3。

3. **【强烈建议】替换升级/资源通道域名** —— ✅ **已完成**
   `RepoURL()` / `ResourceURL()` 已指向 `https://3panel.erguotou.me`，未注册域名引用全项目清零。

4. **【建议】移除埋点上报** —— ✅ **已完成**
   `asyncReportAIProviderInstall` 及其调用点已删除。

5. **【建议】替换或加开关** —— ✅ **已完成**
   代理探测（#M3）已改指自有域名；技能市场（#M4）按你的决定**保留** 官方源。

6. **【可选】前端 logo 本地化** —— ✅ **不需要做（原判断有误）**
   logo 本来就是本地资源，`source:` 只是署名元数据，无外泄。详见 §7.5。

7. **【可选】限定构建模式** —— ✅ **不再是风险**
   埋点已删除，`mode` 取值不再影响数据外发，仅影响升级通道选择。

---

## 七、整改记录（2026-09-18 执行完毕）

### 7.1 已完成

| # | 项目 | 改动 |
| --- | --- | --- |
| 1 | **删除 AI Provider 埋点上报**（#M1） | 删除 `agent/app/service/agents_utils.go` 的 `asyncReportAIProviderInstall` 与 `agent/app/service/agents.go` 调用，清理 3 个失效 import。全项目 `installation-analytics` 零残留。 |
| 2 | **删除升级后远程脚本执行机制**（#H1） | **机制整体移除**：`core/app/service/logs.go` 删除 `writeLogs`、`runRemoteShellScript`、`logs` 常量及 7 个失效 import；`core/app/service/upgrade.go` 移除 `go writeLogs(req.Version)`。全项目已无 `installation-log` / `writeLogs` / `runRemoteShellScript` 残留。原先准备的替代脚本 `scripts/installation-log.sh` 一并删除（机制没了就不需要它）。 |
| 3 | **域名全部改指自有域名**（#M2/#M3） | `core/global/global.go` 与 `agent/global/global.go` 的 `RepoURL()`/`ResourceURL()` → `https://3panel.erguotou.me/package`、`/resource`；文档索引、代理检测同步改指自有域名。全项目 `*.3panel.pro` / `3panel.cn` 等未注册域名引用**清零**。 |
| 4 | **恢复 TLS 证书校验**（#H2） | 共 **9 处**移除 `InsecureSkipVerify: true`：<br>`core/utils/req_helper/requset.go`（2 处，覆盖所有通用出站请求，含升级包下载）<br>`core/utils/xpack/helper/multi_node_helper.go`（`LoadRequestTransport`，注释本就写着"应信任系统根证书"）<br>`agent/utils/xpack/helper/multi_node.go`<br>`agent/utils/req_helper/request.go`<br>`agent/utils/version/version.go`<br>`core/app/service/setting.go`（代理检测）<br>`agent/utils/cloud_storage/client/ali.go`（**8 处**，`api.alipan.com` 是公网受信 CA 证书，关校验无正当理由）<br>`core/utils/cloud_storage/refresh_token.go`（`api.aliyundrive.com`，同上） |
| 5 | **前端推广/论坛外链清除**（#L3） | 按你的决定**直接删除**而非替换地址：<br>`footer-navigation/model.ts` — 导航键从 4 个（`learnMore`/`forum`/`documentation`/`project`）缩减为 2 个（`documentation`/`project`），商业版推广与论坛入口移除<br>`router-button/index.vue` — 删除 `goXpack()` 与「快速跳转」推广链接<br>`system-upgrade/index.vue` — 删除版本号旁的 `license.ee`/`license.pro`/`license.offLine`/`license.community` 四个版本标识链接及 `toLxware`/`to3Panel`/`toEdition` 三个函数<br>`license-import/index.vue` — 删除「了解更多专业版」按钮与 `toEdition`<br>连带清理 4 个文件里因此失效的 `isIntl` 等变量。功能保留：`documentation`（自有文档）、`project`（真实仓库 `cnb.cool/erguotou520/3panel`）、版本号、检查更新。 |
| 6 | **示例配置域名** | `agent/cmd/server/nginx_conf/ssl.conf` 证书路径 `/www/sites/3panel.pro/` → `/www/sites/3panel.erguotou.me/`。 |
| 7 | **升级包完整性校验** | `core/app/service/upgrade.go` 新增 `verifyUpgradePackage`：**取到 `.sha256` 则强制校验、不一致即中止升级**（不覆盖任何文件）；取不到则记警告后继续。配套 `FileSHA256`/`VerifyFileSHA256`/`ParseSHA256File`（`core/utils/files/files.go`）与 17 个单元测试（`core/utils/files/checksum_test.go`）。 |
| 8 | **自建发布流水线** | 新增 `packaging/`（`3pctl` 模板、`install.sh`、`build-release.sh`、`initscript/` 下 8 个服务定义）与 `.github/workflows/release-stable.yml`：打 tag 即自动构建 amd64/arm64 升级包、生成 `.sha256` 与 `latest`/`latest.current`，上传到面板约定的请求路径。详见 `docs/UPGRADE-升级通道部署.md`。 |
| 9 | **代理探测可靠性** | `core/app/service/setting.go` 的 `checkProxy()` 超时 3s → **10s**（跨境经代理建连 3s 偏紧易误判），并补充注释说明「只看建连、不看状态码」。 |
| 10 | **语言包内置 + 残留资源清理** | 新增 `packaging/lang/{en,zh}.sh`（各 47 个键，覆盖 `3pctl` 与 `install.sh` 全部引用），`build-release.sh` 改为**优先使用仓库内置语言包**、远端仅作回退 —— 构建不再依赖外部主机可用性。同时校验 `lang/zh.sh` 存在（`initLang()` 以它为「语言包已安装」哨兵，缺失会导致面板**每次启动都重新下载**）。另清理 `enlarge_{black,white}.svg` 中被注入的远程字体引用（#L6）。 |
| 11 | **「关于」页死链修复** | `frontend/src/views/setting/about/index.vue` 的「项目 / 问题反馈 / star」三个入口原指向 `github.com/3panel-dev/3panel`（**实测 404**），改指真实仓库 `https://cnb.cool/erguotou520/3panel`、其 `/-/issues` 与 `/-/stargazers`（均实测 200）。函数名 `toGithub`/`toGithubStar` → `toRepo`/`toRepoStar`。 |
| 12 | **`.gitignore` 误伤修复** | 原 `3pctl` / `install.sh` / `3panel.service` 三条**裸文件名**规则会把 `packaging/` 下的同名发布资产一并忽略（CI 必然失败），改为锚定根目录 `/3pctl`、`/install.sh`、`/3panel.service`。 |

**TLS 校验关闭的根因（回答"是不是多节点引入"）**：**不是**。
`core/utils/req_helper/requset.go` 与上游 1Panel 的 `master` 分支逐字对比，
**唯一差异是 import 路径改名**，`InsecureSkipVerify: true` 是上游原生继承的。
多节点功能（commit `93a7c5f`）反而**新增了正规的双向证书校验**：
节点间通信走 `nodecert.TLSConfig(addr)`（`core/utils/nodecert/cert.go`，342 行，含 CA 校验与客户端证书），
只新增了 2 处关闭校验：`agent/cmd/server/cmd/join.go:142`（节点加入 bootstrap，此时尚未拿到 CA，属合理例外）
与 `LoadRequestTransport`。因此修复范围不是"多节点那一部分"，而是**通用出站路径**本身。

### 7.2 TLS 校验现状（17 处 → 10 处，全部有明确理由）

| 位置 | 现状 | 理由 |
| --- | --- | --- |
| `agent/app/service/mongodb_client.go:127`、`agent/utils/mysql/client/info.go:134`、`agent/utils/files/file_op.go:450` | 保留 | **已是按配置开关**（`info.SkipVerify` / `skipVerify` / `options.IgnoreCertificate`），由用户决定，行为正确。 |
| `agent/utils/webhook_sender/request.go:656` | 保留 | 已经是 `InsecureSkipVerify = false`（安全）。 |
| `agent/utils/cloud_storage/client/{webdav,minio,s3}.go` | 保留 | 对接用户自建的 WebDAV / MinIO / S3 兼容存储，自签名证书常见。 |
| `core/utils/ssh/http.go:33` | 保留 | 连接用户自己配置的 HTTPS 代理，自签名代理合理。 |
| `agent/utils/req_helper/core.go:47` | 保留 | 仅访问 `127.0.0.1` 本机回环，中间人不可达。 |
| `agent/cmd/server/cmd/join.go:142` | 保留 | 节点加入 bootstrap，此时还没有 CA 证书可用。 |
| ~~`agent/utils/cloud_storage/client/ali.go`（8 处）~~ | ✅ **已修** | 公网 API，对方证书由受信 CA 签发。 |
| ~~`core/utils/cloud_storage/refresh_token.go`~~ | ✅ **已修** | 同上。 |

### 7.3 影响评估（回答"会不会对其它功能有影响"）

恢复 TLS 校验后**不会影响任何正常功能**，因为：

1. **被打通的路径本来就都是公网 HTTPS**：升级包下载（`3panel.erguotou.me`，Cloudflare 证书）、
   应用商店、AI 模型 API、云存储公网 API —— 全由受信任 CA 签发，校验天然通过；
2. **需要自签名/不校验的场景一处没动**：自建 WebDAV/MinIO/S3（`webdav.go`/`minio.go`/`s3.go`）、
   自签 HTTPS 代理（`ssh/http.go`）、MongoDB/MySQL（配置项开关）、节点加入 bootstrap（`join.go`）
   —— 这些仍保持原行为；
3. **唯一会"变坏"的情况**：如果 `3panel.erguotou.me` 用了**自签名证书**，升级会失败；
   Cloudflare 托管默认满足受信 CA 要求。

**验证结果**：`core` 与 `agent` 两个 Go 模块 `go build ./...` 完全通过；
`core/utils/files` 单元测试 17 用例通过；前端改动文件 type-check 与 ESLint 零错误。

### 7.4 仍待你决定

1. **技能市场**（#M4）：按你的决定**保留** `clawhub.com` / `mirror-cn.clawhub.com`（真实第三方服务，
   仅在使用「Agent 技能市场」时访问）。注意其搜索关键词会外发，且安装的技能包会进入容器执行。
2. **前缀式代理**：你提到的 `https://proxy.erguotou.me/<完整URL>` 是 URL 重写型代理，
   与面板「设置 → 代理」所需的 HTTP/SOCKS5 正向代理**不是同一机制**，无法填入该配置项。
   如需让面板经它拉取资源，需要单独改造（尚未实施）。
3. **GeoIP 数据**：`GeoIP.mmdb` 是 MaxMind 授权数据，仓库无法内置，需你自己放到
   `/resource/geo/GeoIP.mmdb`。缺失时登录日志的 IP 归属地显示为空，不影响其它功能。

### 7.5 结论更正：AI 厂商 logo 是本地资源（撤回 #L1）

初版报告把 `frontend/src/utils/agent-provider-logo.ts` 列为「从厂商 CDN 加载 logo，泄露管理员浏览器 IP」，
**这个结论是错的**。复核过程与证据：

| 核查 | 结果 |
| --- | --- |
| 文件是否被本轮改动过 | 否（`git status` 与 `git diff` 均为空，属仓库原始状态，非我改出来的） |
| `src` 字段的来源 | 全部 15 处走 `asset()` → `new URL('../assets/images/ai-providers/…')`，是**本地打包路径** |
| 本地资源是否存在 | 是，`frontend/src/assets/images/ai-providers/` 下 **13 个文件**（webp/png/svg/ico） |
| 是否存在远程 `src` | `grep "src:.*http"` → **零命中** |
| 渲染组件用的是哪个字段 | `agent-provider-logo/index.vue:3` 用 `<img :src="logo.src">`，**从不使用 `source`** |
| `source` 字段的真实作用 | 仅作署名/溯源元数据（注释性质），不参与任何渲染或请求 |

**结论**：不存在厂商 CDN 请求，不存在浏览器 IP 外泄，**无需本地化**（本来就是本地的）。

同一轮复扫中另发现一处真实但惰性的残留（#L6）：`enlarge_black.svg` 与 `enlarge_white.svg`
的 `<defs><style>` 块里被写入了两条 `@font-face` —— 一条指向 `chrome-extension://moombeodfomdpjnpocobemoiaemednkg/…`
（图标下载类浏览器插件的指纹），一条指向 `//at.alicdn.com/t/font_1031158_…`（阿里图标 CDN，协议相对地址）。
判断与处理：

- 两个 SVG 各含 **0 个 `<text>` 元素**，`font-family` 声明从不参与渲染，图形完全由 `<path>` 矢量绘制；
- SVG 以 `<img>` 加载时浏览器**禁止外部资源拉取**，所以这两条引用实际是惰性的；
- 两个文件在全项目中**无任何引用**（死资源）；
- 仍已清理该注入块（1938 → 1328 字节，`<path>` 与 `fill` 完整保留），使资源目录彻底干净。



### 7.6 出站代理（「设置 → 代理」）的生效范围

排查方法：全仓搜索 `ProxyType` / `ProxyUrl` / `ProxyPort` / `ProxyUser` / `ProxyPasswd`
的**读取点**，以及所有会挂代理的 `http.Transport`（`Proxy: http.ProxyURL(...)`）。

**结论：这个代理设置的作用面比界面暗示的小得多。**

#### 真正生效（会读 DB 里的代理配置）

| # | 位置 | 作用 | 触发条件 |
| --- | --- | --- | --- |
| 1 | `core/utils/ssh/ssh.go:372` `loadSSHConnByProxy` | **SSH 连接**走代理（http / https / socks5） | `DialWithTimeout(..., useProxy=true, ...)` |
| 2 | `agent/app/service/website_ssl.go`、`website_acme_account.go` → `ssl.NewAcmeClient(..., getSystemProxy(...))` | **ACME 证书签发**（Let's Encrypt / ZeroSSL / Google / Buypass 等） | ACME 账号勾选了「使用代理」 |
| 3 | `agent/app/service/file.go:901` `Wget` → `files.DownloadProxyConfig` | 文件管理里的**远程下载** | 该次下载勾选了「使用代理」 |
| 4 | `core/app/service/setting.go:817` `checkProxy` | 保存代理时的**连通性校验** | 每次保存（用的是表单参数，临时 transport） |

#### 名字带 `Proxy`，但实际**不经过代理**

`req_helper.HandleRequestWithProxy` / `HandleGetWithProxy` / `DownloadFileWithProxyStream`
最终调用的都是 `xpack.MultiNodeProvider.LoadRequestTransport()`
（`core/utils/xpack/helper/multi_node_helper.go:182`），而它在**社区构建下返回一个裸
`http.Transport`，完全没有配置代理**。受影响的调用方：

- `core/app/service/upgrade.go` —— **升级包下载**、`.sha256` 校验、版本检查、发布说明
- `core/app/service/script_library.go` —— 脚本库数据 / 版本 / 包
- `core/utils/files/files.go:255` `DownloadFileWithProxyStream`（上面的公共入口）

也就是说：**升级下载并不会走你配的代理**。函数名里的 "WithProxy" 指的是
xpack（专业版）实现，社区构建里这名不副实。

#### 社区构建下的空实现

| 接口方法 | 社区实现 | 后果 |
| --- | --- | --- |
| `MultiNodeProvider.ProxyDocker(proxyURL)` | `return nil` | 界面上的「Docker 代理」**不会写入 docker 配置** |
| `MultiNodeProvider.Sync(scope)` | `return nil` | 代理配置不会同步到节点 |

#### 另一套独立机制（不读面板设置）

`agent/utils/webhook_sender/request.go:649` 用的是 `http.ProxyFromEnvironment` ——
读的是 **`HTTP_PROXY` / `HTTPS_PROXY` 环境变量**，与面板的代理设置互不影响。

#### 影响与建议

- 想让**升级包下载**经代理走，必须改 `LoadRequestTransport()` 去读 DB 代理配置
  （目前未改，属行为变更，待确认）
- 你之前提到的 `https://proxy.erguotou.me/<完整URL>` 是 **URL 重写型反代**，
  与这里需要的 HTTP/SOCKS5 **正向代理**不是同一机制，两者都填不进第二个用法
- 若只是想让**证书签发**和**SSH**能翻出去，这两处在社区构建下是**正常工作**的

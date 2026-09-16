# 3Panel 品牌改造说明 / Rebrand notes

本文记录 1Panel → 3Panel 二次开发改造的**落地情况**与**必须由你自行接管的事项**。

## 已完成的改造

- **产品名 / 文案**：全部界面文案（16 种语言 i18n）、Swagger 标题、默认面板名（\`PanelName\`）、README 及文档均已改为 3Panel。
- **Go module**：\`github.com/1Panel-dev/1Panel/{core,agent}\` → \`github.com/3panel-dev/3panel/{core,agent}\`，所有 import 同步更新。
- **二进制 / 服务**：\`1panel-core\`/\`1panel-agent\` → \`3panel-core\`/\`3panel-agent\`，含 systemd unit 名。
- **默认安装目录**：\`/opt/1panel\` → \`/opt/3panel\`。
- **API 鉴权头**：\`1Panel-Token\`/\`1Panel-Timestamp\` → \`3Panel-Token\`/\`3Panel-Timestamp\`。
- **运行时标识**：容器名、日志文件名（\`3Panel.log\`/\`3Panel-Core.log\`）、CA 名称、nftables 表名、环境变量前缀（\`3PANEL_*\`）、\`.3panel_clash\` 等。
- **视觉资产**：主 Logo、侧边栏 Logo、\`favicon.svg\`、4 个 favicon PNG 均已基于原图形风格重绘为 3Panel（数字 1 → 3，字标 1Panel → 3Panel，笔画粗细与原字形对齐）。
- **合规**：新增 [NOTICE.md](../NOTICE.md)，GPLv3 许可证全文与上游版权信息完整保留。

## ⚠️ 必须自行接管的外部依赖

以下地址是改造时按命名规则**机械替换**出来的占位域名，目前**并不存在**。上线前必须替换为你自己真实的基础设施，否则对应功能会失效。

### 1. 在线安装 / 升级通道（高优先级）

| 占位地址 | 用途 | 原上游地址 |
| --- | --- | --- |
| \`https://resource.3panel.pro/v2/quick_start.sh\` | 一键安装脚本 | \`resource.1panel.pro\` |
| \`https://resource.3panel.pro/v2\` | 版本 / 升级元数据 | \`resource.1panel.pro\` |
| \`https://resource.3panel.pro/v2/resource\` | 资源包 | \`resource.1panel.pro\` |
| \`https://resource.fit2cloud.com/3panel/package/*\` | 安装包 / 离线包 | \`resource.fit2cloud.com/1panel\` |

### 2. 应用商店（高优先级）

| 占位地址 | 用途 |
| --- | --- |
| \`https://apps.3panel.pro\` | 应用商店索引 |

> 应用商店是 1Panel 的核心能力，需要你自己搭建并维护应用仓库。

### 3. 官网 / 文档 / 商业版入口（中优先级）

| 占位地址 | 用途 |
| --- | --- |
| \`https://3panel.pro\` / \`https://3panel.cn\` | 官网 |
| \`https://docs.3panel.pro\` / \`https://3panel.cn/docs\` | 文档站 |
| \`https://3panel.pro/pricing\` / \`https://3panel.hk/pricing\` | 商业版购买入口 |
| \`https://3panel.cn/versions.html\` | 版本说明 |
| \`http://3panel.oss-cn-hangzhou.aliyuncs.com\` | 图片 CDN |

### 4. 商业版（xpack）相关

本项目基于 OSS 版本构建（\`PANEL_XPACK=false\`）。代码中仍保留 xpack 扩展点与「升级到商业版」的提示文案；若你不打算提供商业版，建议后续把这些入口隐藏或移除。

## 其他产品自有标识的改名

| 标识 | 上游 | 本项目 | 说明 |
| --- | --- | --- | --- |
| 命令行工具 | `/usr/local/bin/1pctl` | `/usr/local/bin/3pctl` | 面板内所有调用点已同步；**你的安装脚本必须生成 `3pctl`**（上游的 `install.sh` 未包含在本仓库） |
| 回收站文件前缀 | `_1p_file_1p_...` | `_3p_file_3p_...` | 见 `agent/utils/re/re.go`、`agent/app/service/recycle_bin.go`；旧回收站文件不兼容 |
| 日志脚本参数 | `installation-log.sh` | 未改 | `https://resource.fit2cloud.com/installation-log.sh` 是上游外部脚本，参数 `"1p"` 是它的契约，改名会破坏行为 |

## 保留未改的内容（有意为之）

| 保留项 | 原因 |
| --- | --- |
| \`github.com/1Panel-dev/lego/v5\` | 第三方 Go 依赖（ACME 库），改名会导致依赖解析失败 |
| \`github.com/1Panel-dev/{MaxKB,KubePi,CordysCRM}\` 链接 | 上游组织的其他独立开源项目，改名会造成事实错误 |
| 登录页插图 \`3panel-login*.jpg/png\` | 装饰性图片，**建议人工确认是否残留上游视觉元素后自行替换** |
| WAF 数据目录 `1pwaf` | 由独立的 OpenResty WAF 动态模块创建（不在本仓库内），单改面板侧会导致 WAF 功能失联，需连同 WAF 模块一起改名 |

## 二次开发的合规要点（依据上游《社区软件许可协议》+ GPLv3）

1. 不得使用 1Panel 的商标、Logo、产品名称进行推广或暗示背书 —— 已全部替换。
2. 必须保留 GPLv3 许可证与版权声明 —— 已保留。
3. 分发时须提供完整对应源码 —— 本仓库即完整源码。
4. 需明确声明"基于 1Panel 二次开发" —— 见 [NOTICE.md](../NOTICE.md) 与各 README 顶部声明。

## 本地构建

\`\`\`bash
# 前端
cd frontend && npm install && npm run build:pro

# 后端（产物输出到 ./build）
make build_all
\`\`\`

> 注意：\`make build_all\` 会先构建前端并把产物放入 \`core/cmd/server/web/assets\`，
> 该目录在仓库中默认只有占位文件，属于正常现象。

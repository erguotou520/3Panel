# NOTICE / 二次开发声明

**3Panel** 是基于 [1Panel](https://github.com/1Panel-dev/1Panel) 二次开发（fork）产生的独立项目。

## 上游项目 / Upstream

- 上游项目：**1Panel** — https://github.com/1Panel-dev/1Panel
- 上游权利人：杭州飞致云信息科技有限公司（FIT2CLOUD）及 1Panel 项目贡献者
- 上游许可证：**GNU General Public License v3.0**（见本仓库 [LICENSE](./LICENSE)）

## 合规声明 / Statement

1. 本项目在 1Panel 源码基础上二次开发，并依据 **GPLv3** 开源发布；所有修改以源码形式公开于本仓库。
2. 本项目**完整保留**上游的 GPLv3 许可证文本（LICENSE）与相关版权信息，未做任何移除或篡改。
3. 依据上游《社区软件许可协议》关于商标、商号、Logo 与产品名称的约定，上述标识的权利归上游权利人所有，且未授权给衍生作品使用。因此本项目已将**产品名称、Logo、图标及界面文案中的品牌标识全部替换为 3Panel**，不再使用 1Panel 的任何商标或标识。
4. 本项目与上游 1Panel、FIT2CLOUD **不存在任何隶属、合作或背书关系**。本项目的问题反馈请提交至本项目自己的仓库，而非上游项目。
5. 本项目自行维护安装脚本、升级通道与应用商店等基础设施；**面板运行时（`core` / `agent`）不访问上游的任何在线服务**，
   相关地址（升级通道 `RepoURL()`、资源通道 `ResourceURL()`、应用商店 `AppRepoURL()`、文档索引等）
   均已替换为本项目自己的地址。唯一的例外是 `scripts/` 下的**可选运维工具**（`appstore-mirror`、`cf-appstore-sync`）：
   它们需要从上游商店源 `apps.1panel.pro` **只读**拉取应用元数据以生成自建镜像，仅由运维人员手动执行，
   不随面板运行，也不会向该源发送本项目的任何数据。

## 修改范围概要 / Scope of changes

| 类别 | 上游 | 本项目 |
| --- | --- | --- |
| 产品名称 | 1Panel | 3Panel |
| Go module | `github.com/1Panel-dev/1Panel/{core,agent}` | `github.com/3panel-dev/3panel/{core,agent}` |
| 二进制 / systemd 服务 | `1panel-core` / `1panel-agent` | `3panel-core` / `3panel-agent` |
| 默认安装目录 | `/opt/1panel` | `/opt/3panel` |
| API 请求头 | `1Panel-Token` / `1Panel-Timestamp` | `3Panel-Token` / `3Panel-Timestamp` |
| Logo / favicon | 1Panel 图形 | 基于 1Panel 图形风格重绘的 3Panel 图形 |

## 保留项 / Intentionally unchanged

- `github.com/1Panel-dev/lego/v5`：上游声明使用的第三方 Go 模块依赖（ACME 客户端），为保持依赖完整性未改名。

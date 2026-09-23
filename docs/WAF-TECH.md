# 3panel WAF 技术设计文档

> 配套文档：功能清单见 `docs/WAF-FEATURES.md`。本文描述实现方案与技术选型。

## 1. 总体架构

```
站点流量
   │
   ▼
┌─ Edge（OpenResty，L7）────────────────────────────┐
│  rewrite/access 阶段：                              │
│    1. 名单引擎（白→黑→TTL）                          │
│    2. CC 限流（共享内存计数器）                        │
│    3. 检测流水线（body 阶段执行）                     │
│       语义引擎 → ML 引擎 → 规则引擎（CRS 兼容）        │
│    4. 动作执行（deny / challenge / log-only）       │
│  log 阶段：日志异步落盘                                │
└──────────┬───────────────────────────────────────────┘
           ▼ 回源（proxy_pass 上游）
┌─ 控制面（agent 进程，Go）──────────────────────────┐
│  WAF 服务模块：配置下发 / 名单管理 / 日志聚合          │
│  DB：策略、名单、日志、基线模型                        │
└──────────┬───────────────────────────────────────────┘
           ▼
     前端 UI：站点页开关、策略编辑、日志检索、攻击统计
```

关键决策：

- **内核选 OpenResty，不自研反代**。3panel 站点本身就是 Nginx 配置生成器，WAF 以动态 Lua 模块形式挂到每个启用的站点 server 块，复用现有站点管理链路。
- **检测在 `access_by_lua_block` + `body_filter`/`content_by_lua` 阶段做**，请求体大的场景用流式读取，避免全量缓冲拖垮内存。
- **控制面与数据面分离**：agent(Go) 负责配置、名单、日志、模型；OpenResty 只做执行，通过共享字典 + 文件（规则/模型产物）同步，不直连 DB，防止 worker 阻塞拖垮站点。

## 2. 模块设计

### 2.1 名单引擎（第一优先级）

数据模型（agent DB）：

```sql
CREATE TABLE waf_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(128) NOT NULL,
    scope VARCHAR(16) NOT NULL,          -- global | site
    site_id INTEGER,                      -- scope=site 时关联
    priority INTEGER DEFAULT 100,         -- 数值越小越优先
    match_type VARCHAR(32) NOT NULL,      -- ip | cidr | path | ua | referer | header | cookie | method | expr
    match_value TEXT NOT NULL,            -- 匹配内容（expr 类型存表达式）
    match_op VARCHAR(16) DEFAULT 'exact', -- exact | contains | prefix | suffix | wildcard | regex
    action VARCHAR(16) NOT NULL,          -- allow | deny | log
    ttl INTEGER,                          -- 秒，NULL 表示永久
    expires_at DATETIME,                  -- 由 ttl 计算，定时清理
    enabled INTEGER DEFAULT 1,
    created_at DATETIME, updated_at DATETIME
);
```

执行链路（Lua）：

1. 名单按 `scope` 预编译两份（global / site），启动与变更时加载到 `lua_shared_dict`；
2. 请求进入先查白名单（任一维度命中 → 直接放行，跳过检测）；
3. 再查黑名单（命中 → 执行 action）；
4. 过期名单由后台 timer 惰性清理。

表达式匹配（`match_type=expr`）使用已沙箱化的 Lua 表达式求值（限制全局环境、禁 IO），支持组合条件，如：

```
ip in "1.2.3.0/24" and path matches "^/admin" and method in ["POST"]
```

**禁止直接使用未沙箱的 `loadstring`/`_ENV` 穿透，避免名单表达式变成 RCE 入口。**

### 2.2 检测引擎（三层流水线）

**层一：语义引擎（Lua + C 扩展）**

- SQL 注入：对参数值做 SQL 语法解析（开源实现参考 libinjection 的 token 化思路，自研增强版），识别语句结构合法性而非关键字匹配；
- XSS：对参数做 HTML/JS 上下文解析，识别事件注入与标签逃逸；
- RCE / LFI / SSRF：命令语法树 + 路径规范化分析（`../../`、编码嵌套、空字节截断）。

**层二：ML 异常引擎**

- 特征：参数数量/长度/字符分布、UA 簇、路径深度、Header 组合异常度；
- 冷启动：规则优先；积累 ≥7 天正常流量后开启混合评分；
- 实现：Go 侧离线训练（周期性任务），产物为轻量模型文件（如 ONNX / 自研线性模型），推送到 OpenResty 侧 Go Shared Dict 加载；Lua 只做推理打分。

**层三：规则引擎（CRS 兼容）**

- 引入 OWASP CRS 作为长尾兜底，规则文件编译为 Aho-Corasick 多模匹配 + PCRE；
- 规则支持热更新、按站点启用/禁用、单规则动作覆盖。

**层间短路**：任一层命中且动作为 deny → 直接拦截；动作为 log → 继续走后续层并记录。

### 2.3 CC 防护

- `lua_shared_dict` 滑动窗口计数器，维度：IP、IP+URL、站点全局；
- 阈值策略：超过 QPS → 挑战（JS Challenge）→ 仍超 → deny；
- 慢速攻击：基于连接时长与字节速率识别。

### 2.4 日志管道

- OpenResty 侧拦截/命中事件序列化为 JSON，写入本地缓冲文件（避免 worker 直接写 DB）；
- agent 后台任务批量读取缓冲 → 解析 → 入库（SQLite）；
- 日志表按时间分区，支持配置保留天数，超限自动清理；
- 高流量场景可配置切换为仅采样记录或外发（Webhook/Syslog），本地不全量落盘。

### 2.5 配置下发

- agent 变更名单/策略后：写共享字典文件 + `kill -HUP` 或 `nginx -s reload`（仅 reload 受影响站点配置，利用 Nginx 的 server 级重载）；
- 名单走 `lua_shared_dict`，无需 reload，秒级生效；
- 规则/模型文件走文件 + worker 定时检查 mtime 热加载。

## 3. 代码落点（现有仓库结构）

| 层 | 位置 | 说明 |
|---|---|---|
| 前端 | `frontend/src/views/website/` 下新增 WAF 页面 | 站点开关、策略、名单、日志 |
| API | `agent/app/api/` + `router/` | 新增 `waf` 路由组 |
| 业务 | `agent/app/service/waf*.go` | 名单/策略/日志/模型训练任务 |
| 数据 | `agent/app/model/waf*.go` | 表结构 |
| 数据面 | `agent/utils/waf/lua/`（新增） | OpenResty Lua 模块 + 语义引擎 + 规则编译 |
| Nginx 配置 | `agent/app/service/nginx.go` | 生成站点配置时注入 `access_by_lua_file` |
| 定时任务 | `agent/cron/` | 名单过期清理、日志归档、模型重训 |

## 4. 性能预算

- 目标：开启 WAF 后延迟增量 < 5%（P99）；
- 措施：
  - 名单/计数器全走共享内存，零 IPC；
  - 规则编译为多模匹配，避免逐条 PCRE；
  - 请求体按需读取，超过阈值（默认 1MB）的 body 只做抽样检测并标记；
  - 日志异步批量落盘，worker 永不阻塞；
  - ML 推理用轻量线性模型，单次推理 < 0.1ms。

## 5. 安全边界

- 名单表达式必须沙箱求值（见 2.1）；
- WAF 自身配置接口走 agent 鉴权，Lua 侧只读产物文件；
- 模型/规则文件校验签名或哈希，防止恶意篡改导致绕过；
- 拦截日志中的敏感字段（如 Cookie、Authorization）落库前脱敏。

## 6. 部署形态（需求冻结前必须定案）

WAF 依赖 OpenResty + Lua，而用户环境的 Nginx 不可控，这是整个方案的地基，必须在 M1 前定案：

**三种形态，按优先级验证：**

1. **捆绑 OpenResty（首选）**：3panel 在面板安装/升级时统一部署一个受管 OpenResty（面板站点体系专用），站点配置全部由它生成。WAF Lua 模块随 OpenResty 版本一起发布，环境与检测引擎严格匹配，不存在兼容性问题。
   - 检测路径：面板检查宿主机 OpenResty 版本与内置 WAF 模块版本是否匹配，不匹配则提示升级，不静默降级。
2. **用户自有 Nginx 探测降级**：若检测到站点运行在用户自装的纯 Nginx 上（无 lua 模块），WAF 开关置灰并提示，不假装生效。禁止在缺少 Lua 的环境下"启用"WAF。
3. **独立 WAF 容器（兜底形态）**：独立容器反向代理在站点前面，用于保护非面板管理的流量（差异化场景）。代价是失去"面板即入口"的低接入优势，仅作为 L4/外部资产场景的形态，不作为默认。

**定案标准**：M1 POC 结束时输出决策记录——选定默认形态、版本兼容矩阵（OpenResty 版本 × WAF 模块版本 × 面板版本）、以及不支持环境的用户告知方案。

## 7. 测试与验收体系

没有测试体系，"低误报"只是口号。以下随 M1 建立，此后每个里程碑全量回归：

- **攻击样本集（混淆绕过是重点）**
  - 基础集：OWASP Top 10 样本、社区公开集（如 `OWASP/wstg` 用例、GitHub 主流 WAF 测试集）
  - 绕过集（自研核心资产）：编码嵌套（URL 多解/Unicode/HTML 实体组合）、注释混淆、HTTP 参数污染、分块走私、大小写/等价语法变体——这部分决定"比雷池强"是否成立
  - 维护方式：样本入库（git 管理），新增绕过手法即补样本，CI 强制回归
- **误报集**：从真实站点流量采集正常请求（脱敏）构成基准集，每次规则/引擎改动必须重放，误报率劣化即阻断合并
- **CI 回归**：攻击样本集 + 误报集重放进流水线，输出检出率/误报率对比报告，与基线（CRS 默认配置 + 雷池社区版）同跑
- **压测**：`wrk`/`k6` 固定场景模型（读写混合、不同 body 大小档位、WebSocket 长连接），每版本对比无 WAF / 有 WAF 的 P99 延迟与吞吐，超预算 5% 阻断发布
- **验收门槛**：与功能文档第 4 节的指标一致；未达门槛的里程碑不合并

## 8. WAF 自身可观测性与告警

覆盖"日志管不了"的 WAF 自身健康面：

- **指标采集**（agent 周期性读取，存面板监控体系）：
  - OpenResty worker 存活数、异常退出计数（crash-loop 检测）
  - `lua_shared_dict` 各 dict 使用率（超 80% 告警：名单/计数器/连接状态打满会导致防护失效或请求失败）
  - 检测耗时分布（P50/P99），突增 2 倍以上告警——通常是某条规则或语义模块退化成线性扫描
  - 拦截率异常波动（骤降 = 可能引擎失效被绕过；骤升 = 可能误报风暴）
- **告警通道**：Webhook / 邮件 / 钉钉/企业微信机器人，可配置级别与静默时段
- **降级保护**：检测引擎自身异常（Lua 报错率超阈值）时自动切换为"名单 + CC 防护"保底模式并告警，绝不允许因为 WAF bug 把站点打挂

## 9. 里程碑拆解

1. **M1 POC**：OpenResty 挂载 Lua 模块 + libinjection 式 SQL 语义检测 + 基准测试（vs CRS 默认配置），验证误报率/延迟达标；
2. **M2 基础版**：名单引擎（全局/站点、TTL、多维匹配）、拦截/放行动作、日志管道、站点一键开关；
3. **M3 完整版**：语义引擎全量攻击类型、CC 防护、规则热更新、虚拟补丁；
4. **M4 进阶**：ML 异常检测、API 基线、L4 模式。

每一步都先在 POC 环境跑攻击样本集（含混淆绕过样本）回归，再合入。

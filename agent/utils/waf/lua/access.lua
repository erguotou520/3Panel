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
    local ct = ngx.var.content_type or ""
    local cl = tonumber(ngx.var.content_length) or 0
    if cl > 0 and cl <= config.BODY_LIMIT and (ct:find("urlencoded", 1, true) or ct:find("json", 1, true) or ct:find("multipart", 1, true)) then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body then
            if ct:find("multipart", 1, true) and semantic.detect_upload(body) then
                return "upload", "dangerous file upload"
            end
            local h = semantic.inspect(body, uri)
            if h then
                return h.type, h.value
            end
        end
    end
    return nil
end

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
    local bot_conf = state.site and state.site.bot
    local bot_verdict = nil
    if bot_conf then bot_verdict = bot.check(bot_conf) end
    if bot_verdict == "good" then
        return -- 善意 bot 直接放行，跳过检测
    elseif bot_verdict == "bad" then
        log_event("deny", "bot", "scanner", nil, "blocked scanner user-agent", start_ms)
        return deny()
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
    local atype, adetail = detect_request(start_ms)
    if atype then
        log_event("deny", "semantic", atype, nil, adetail, start_ms)
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

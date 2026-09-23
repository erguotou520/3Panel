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

local ngx_say = ngx.say
local ngx_exit = ngx.exit

local function client_ip()
    -- 优先 X-Forwarded-For 第一跳（面板反代场景）
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        return xff:match("^([^,%s]+)")
    end
    return ngx.var.remote_addr or ""
end

local function deny(attack_type, rule, detail)
    ngx.status = 403
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx_say("<html><body><h1>403 Forbidden</h1><p>Blocked by 3panel WAF</p></body></html>")
    return ngx_exit(403)
end

local function log_event(action, layer, attack_type, rule, detail, start_ms, body)
    local ok, err = pcall(waflog.emit, {
        websiteId = config.get_site_id(),
        ruleId = rule and rule.id or "",
        ruleName = rule and rule.name or "",
        layer = layer,
        attackType = attack_type or "",
        action = action,
        method = ngx.req.get_method(),
        path = ngx.var.uri or "",
        query = ngx.var.query_string or "",
        ip = client_ip(),
        userAgent = ngx.var.http_user_agent or "",
        detail = detail or "",
        requestBody = body or "",
        durationMs = math.floor((ngx.now() * 1000 - start_ms) * 100) / 100,
    })
    if not ok then
        ngx.log(ngx.ERR, "[waf] log emit failed: ", err)
    end
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
            local h = semantic.inspect(body, uri)
            if h then
                return h.type, h.value
            end
        end
    end
    return nil
end

local function access_main()
    local start_ms = config.now_ms()

    -- 1. 名单引擎
    local ok, res = pcall(rules.check)
    if ok and res then
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

    -- 2. 机器人识别（善意 bot 放行等同白名单；扫描器指纹拦截）
    local ok_bot, bot_verdict = pcall(bot.check, rules.get_bot_conf())
    if ok_bot and bot_verdict == "good" then
        return -- 善意 bot 直接放行，跳过检测
    elseif ok_bot and bot_verdict == "bad" then
        log_event("deny", "bot", "scanner", nil, "blocked scanner user-agent", start_ms)
        return deny()
    end

    -- 3. CC 防护（挑战已通过的请求直接放行）
    local cc_conf = rules.get_cc_conf()
    if cc_conf and not challenge.passed() then
        local ok3, verdict = pcall(cc.check, cc_conf)
        if ok3 and verdict == "deny" then
            log_event("deny", "cc", "cc", nil, "rate limit exceeded", start_ms)
            return deny()
        elseif ok3 and verdict == "challenge" then
            log_event("challenge", "cc", "cc", nil, "rate limit, issuing js challenge", start_ms)
            return challenge.respond()
        elseif ok3 and verdict == "log" then
            log_event("log", "cc", "cc", nil, "rate limit (monitor)", start_ms)
        end
    end

    -- 5. 扫描器行为指纹（URI 多样性 / 速率突增）
    local ok_probe, probe_hit = pcall(probe.check, rules.get_probe_conf())
    if ok_probe and probe_hit then
        log_event("deny", "probe", "scanner", nil, probe_hit, start_ms)
        return deny()
    end

    -- 6. HTTP 请求走私检测（在语义检测前，畸形请求不进流水线）
    local ok_smug, smug_hit = pcall(smug.detect)
    if ok_smug and smug_hit then
        log_event("deny", "smuggling", "smuggling", nil, smug_hit, start_ms)
        return deny()
    end

    -- 7. 语义检测
    local ok2, atype, adetail = pcall(detect_request, start_ms)
    if ok2 and atype then
        log_event("deny", "semantic", atype, nil, adetail, start_ms)
        return deny(atype)
    elseif not ok2 then
        -- 检测引擎异常：降级为放行（绝不让 WAF bug 打挂站点），并记录错误
        ngx.log(ngx.ERR, "[waf] detect error: ", tostring(atype))
    end
end

local ok_main, err_main = pcall(access_main)
if not ok_main then
    -- 兜底：入口本身异常一律放行并记录
    ngx.log(ngx.ERR, "[waf] access error: ", tostring(err_main))
end

return access_main

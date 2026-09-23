-- 名单引擎：白名单 > 黑名单 > TTL 过期惰性清理
-- 名单由 agent 从 DB 导出为 JSON 文件（见 waf_exporter），此处只读文件 + 缓存
local config = require("waf.config")
local iputils = require("waf.iputils")
local normalize = require("waf.normalize")
local _M = {}

local CACHE_TTL = 5 -- 秒，文件 mtime 轮询间隔

local cache = {
    data = nil,
    mtime = 0,
    checked = 0,
}

-- 名单文件格式：
-- {
--   global = { rules = { {id, name, priority, match_type, match_value, match_op, action}... } },
--   sites  = { ["1"] = { rules = {...} } },
-- }

local function load_rules()
    local now = ngx.now()
    if cache.data and now - cache.checked < CACHE_TTL then
        return cache.data
    end
    cache.checked = now
    local path = config.get_rules_path()
    local f = io.open(path, "r")
    if not f then
        return cache.data
    end
    local content = f:read("*a")
    f:close()
    local data = config.json_decode(content)
    if data then
        cache.data = data
    end
    return cache.data
end

local match_ops = {}

local PATTERN_MAGIC = {["^"] = true, ["$"] = true, ["("] = true, [")"] = true, ["%"] = true, ["."] = true, ["["] = true, ["]"] = true, ["+"] = true, ["-"] = true}

match_ops.exact = function(v, p) return v == p end
match_ops.contains = function(v, p) return v and v:find(p, 1, true) ~= nil end
match_ops.prefix = function(v, p) return v and v:sub(1, #p) == p end
match_ops.suffix = function(v, p) return v and v:sub(-#p) == p end
match_ops.wildcard = function(v, p)
    if not v then return false end
    -- 通配符转 Lua pattern：先转义 magic 字符，再 * -> .*，? -> .
    local pat = p:gsub(".", function(c)
        if PATTERN_MAGIC[c] then return "%" .. c end
        return c
    end)
    pat = pat:gsub("%*", ".*"):gsub("%?", ".")
    return v:match("^" .. pat .. "$") ~= nil
end
match_ops.regex = function(v, p)
    if not v then return false end
    local ok, res = pcall(function() return v:match(p) ~= nil end)
    return ok and res
end

-- 提取请求各维度当前值
-- 注意：真实 ngx.req.get_headers() 返回小写键名，做大小写兼容
local function build_dim_values()
    local headers = ngx.req.get_headers()
    local method = ngx.req.get_method()
    local ua = headers["user-agent"] or headers["User-Agent"] or ""
    local referer = headers["referer"] or headers["Referer"] or ""
    local uri = ngx.var.uri or ""
    local raw_uri = ngx.var.request_uri or ""
    local ip = ngx.var.remote_addr or ""
    local cookie = ngx.var.http_cookie or ""
    return {
        ip = ip,
        path = uri,
        raw_path = raw_uri,
        ua = ua,
        referer = referer,
        method = method,
        cookie = cookie,
        header = function(name)
            return headers[name:lower()]
        end,
    }
end

-- 单条规则是否命中
local function rule_hit(rule, dims)
    local mt, mv, mop = rule.match_type, rule.match_value, rule.match_op or "exact"
    local fn = match_ops[mop] or match_ops.exact
    if mt == "ip" or mt == "cidr" then
        return iputils.in_cidr(dims.ip, mv)
    elseif mt == "path" then
        return fn(dims.path, mv) or fn(dims.raw_path, mv)
    elseif mt == "ua" then
        return fn(dims.ua, mv)
    elseif mt == "referer" then
        return fn(dims.referer, mv)
    elseif mt == "cookie" then
        return fn(dims.cookie, mv)
    elseif mt == "method" then
        return fn(dims.method, mv)
    elseif mt == "header" then
        -- match_value 格式：Name:value 或 Name（仅判断存在）
        local name, val = mv:match("^(.-):(.*)$")
        if name and val then
            return fn(tostring(dims.header(name) or ""), val)
        end
        return dims.header(mv) ~= nil
    elseif mt == "expr" then
        -- 表达式走受限求值器
        local ok, res = pcall(require("waf.expr").eval, mv, dims)
        return ok and res == true
    end
    return false
end

-- 规则是否已过 expires_at（Go 导出的 RFC3339 时间），过期规则数据面直接跳过
local function rule_expired(rule)
    local exp = rule.expires_at
    if not exp or exp == "" then return false end
    local y, mo, d, h, mi, s = tostring(exp):match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)")
    if not y then return false end
    local t = os.time({
        year = tonumber(y), month = tonumber(mo), day = tonumber(d),
        hour = tonumber(h), min = tonumber(mi), sec = tonumber(s),
    })
    return ngx.time() >= t
end

-- 在单层名单内评估：命中 allow 立即返回；deny 类命中按 priority 取最小（数值越小越优先）
local function eval_list(list, dims)
    local deny_hit = nil
    for _, rule in ipairs(list) do
        if (rule.enabled == nil or rule.enabled == true) and not rule_expired(rule) then
            local ok, hit = pcall(rule_hit, rule, dims)
            if ok and hit then
                if rule.action == "allow" then
                    return {hit = true, action = "allow", rule = rule}
                elseif not deny_hit or (rule.priority or 100) < (deny_hit.rule.priority or 100) then
                    deny_hit = {hit = true, action = rule.action, rule = rule}
                end
            end
        end
    end
    return deny_hit
end

-- 返回命中的名单结果：
--   {hit=true, action="allow"|"deny"|"challenge"|"log", rule={...}}
-- 优先级：站点级名单整体覆盖全局名单；层内白名单(allow) > 黑名单(deny/challenge/log)
function _M.check()
    local rules = load_rules()
    if not rules then
        return nil
    end
    local dims = build_dim_values()
    local sid = tostring(config.get_site_id())
    -- 站点级优先：站点名单有任何命中（allow 或 deny 类）即返回，不再看全局
    if rules.sites and rules.sites[sid] then
        local site_res = eval_list(rules.sites[sid].rules or {}, dims)
        if site_res then
            return site_res
        end
    end
    return eval_list(rules.global and rules.global.rules or {}, dims)
end

-- 站点级扫描探测阈值：rules.json 中 sites[sid].probe = {enabled, maxURIs, window, maxRPS}
function _M.get_probe_conf()
    local data = load_rules()
    if not data then
        return nil
    end
    local sid = tostring(config.get_site_id())
    local site = data.sites and data.sites[sid]
    if site and site.probe and site.probe.enabled then
        return site.probe
    end
    return nil
end

-- 站点级机器人策略：rules.json 中 sites[sid].bot = {enabled, allowGoodBots, blockBadBots}
function _M.get_bot_conf()
    local data = load_rules()
    if not data then
        return nil
    end
    local sid = tostring(config.get_site_id())
    local site = data.sites and data.sites[sid]
    if site and site.bot and site.bot.enabled then
        return site.bot
    end
    return nil
end

-- 站点级 CC 配置：rules.json 中 sites[sid].cc = {limit, window, action, byUri}
-- 返回 nil 表示未配置
function _M.get_cc_conf()
    local data = load_rules()
    if not data then
        return nil
    end
    local sid = tostring(config.get_site_id())
    local site = data.sites and data.sites[sid]
    if site and site.cc and site.cc.limit and site.cc.limit > 0 then
        return site.cc
    end
    return nil
end

return _M

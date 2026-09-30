-- 名单引擎：白名单 > 黑名单 > TTL 过期惰性清理
-- 名单由 agent 从 DB 导出为 JSON 文件（见 waf_exporter），此处只读文件 + 缓存
local config = require("waf.config")
local iputils = require("waf.iputils")
local normalize = require("waf.normalize")
local _M = {}

local CACHE_TTL = 5 -- 秒，文件 mtime 轮询间隔

local cache = {
    data = nil,
    raw = nil,
}
local refresh_started = false
local state_cache = {}

-- 名单文件格式：
-- {
--   global = { rules = { {id, name, priority, match_type, match_value, match_op, action}... } },
--   sites  = { ["1"] = { rules = {...} } },
-- }

local function install_raw(raw)
    if not raw or raw == cache.raw then return cache.data ~= nil end
    local data = config.json_decode(raw)
    if not data then return false end
    cache.raw = raw
    cache.data = data
    state_cache = {}
    return true
end

local function refresh_rules(premature, path, content_key, lock_key)
    if premature then return end
    local f = io.open(path, "r")
    if f then
        local content = f:read("*a")
        f:close()
        if install_raw(content) then
            ngx.shared.waf_dict:set(content_key, content)
        end
    end
end

local function periodic_refresh(premature, path, content_key, lock_key)
    if premature then return end
    if ngx.shared.waf_dict:add(lock_key, true, CACHE_TTL) then
        refresh_rules(false, path, content_key, lock_key)
    else
        -- Another worker owns the file read. Copy its published snapshot into
        -- this worker's local Lua cache here, never from the request path.
        install_raw(ngx.shared.waf_dict:get(content_key))
    end
    local ok, err = ngx.timer.at(1, periodic_refresh, path, content_key, lock_key)
    if not ok then
        ngx.log(ngx.ERR, "[waf] cannot schedule rules refresh: ", err)
    end
end

function _M.start_refresh()
    if refresh_started then return true end
    refresh_started = true
    local path = config.get_rules_path()
    local content_key = "waf:rules:" .. path
    local lock_key = content_key .. ":refresh"
    -- Populate this worker before serving its first protected request. Later
    -- refreshes stay entirely on the timer path.
    refresh_rules(false, path, content_key, lock_key)
    local ok, err = ngx.timer.at(1, periodic_refresh, path, content_key, lock_key)
    if not ok then
        refresh_started = false
        ngx.log(ngx.ERR, "[waf] cannot start rules refresh: ", err)
        return false
    end
    return true
end

local function load_rules()
    _M.start_refresh()
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
    if ngx.re and ngx.re.find then
        local from = ngx.re.find(v, p, "jo")
        return from ~= nil
    end
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
    local text = tostring(exp)
    local y, mo, d, h, mi, s, zone = text:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)[%.%d]*(Z)$")
    if not y then
        y, mo, d, h, mi, s, zone = text:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)[%.%d]*([%+%-]%d%d:%d%d)$")
    end
    if not y then return false end
    y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
    h, mi, s = tonumber(h), tonumber(mi), tonumber(s)
    -- Gregorian civil date -> Unix epoch, independent of the server's local timezone.
    local adjusted_year = mo <= 2 and y - 1 or y
    local era = math.floor(adjusted_year / 400)
    local yoe = adjusted_year - era * 400
    local shifted_month = mo + (mo > 2 and -3 or 9)
    local doy = math.floor((153 * shifted_month + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local t = (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + s
    if zone ~= "Z" then
        local sign, zh, zm = zone:match("^([%+%-])(%d%d):(%d%d)$")
        local offset = (tonumber(zh) * 60 + tonumber(zm)) * 60
        t = t - (sign == "+" and offset or -offset)
    end
    return ngx.time() >= t
end

local function compiled_empty(compiled)
    return not compiled or (not next(compiled.ip or {}) and not next(compiled.path or {})
        and not next(compiled.method or {}) and not next(compiled.ua or {})
        and not next(compiled.referer or {}) and not next(compiled.cookie or {}))
end

function _M.get_site_state()
    load_rules()
    return _M.get_site_state_cached(config.get_site_id())
end

function _M.get_site_state_cached(site_id)
    local data = cache.data
    if not data then
        return nil
    end
    site_id = tostring(site_id or 0)
    local cached = state_cache[site_id]
    if cached and cached.data == data then
        return cached.state
    end
    local site = data.sites and data.sites[site_id]
    -- has_any 在此处算一次。早先每请求调用 has_rules() 都会对
    -- compiled 的 6 张表各做一次 next()，两层共 12 次；它对同一份
    -- state 恒定不变，缓存后每请求零成本。
    local global_rules_ = data.global and data.global.rules or {}
    local global_compiled_ = data.global and data.global.compiled or {}
    local site_rules_ = site and site.rules or {}
    local site_compiled_ = site and site.compiled or {}
    local state = {
        site = site,
        has_any = #site_rules_ > 0 or #global_rules_ > 0
            or not compiled_empty(site_compiled_) or not compiled_empty(global_compiled_),
        global_rules = global_rules_,
        global_compiled = global_compiled_,
        -- 订阅黑名单总开关。缺省为 false：老版本 rules.json 没有这个字段，
        -- 此时按「未启用」处理，不能因为升级遗漏就默认开始拦 IP。
        global_iplist_enabled = (data.global and data.global.ipListEnabled) == true,
    }
    state_cache[site_id] = { data = data, state = state }
    return state
end

function _M.site_enabled()
    local state = _M.get_site_state()
    if not state then return false end
    return state.site == nil or state.site.enabled ~= false
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

local function prefer_result(current, rule)
    if not rule then return current end
    local candidate = {hit = true, action = rule.action, rule = rule}
    if not current or candidate.action == "allow" then return candidate end
    if current.action == "allow" then return current end
    if (rule.priority or 100) < (current.rule.priority or 100) then return candidate end
    return current
end

local function eval_compiled(compiled, dims)
    if not compiled then return nil end
    local result
    local function take(group, value)
        if group and value then result = prefer_result(result, group[value]) end
    end
    take(compiled.ip, dims.ip)
    take(compiled.path, dims.path)
    take(compiled.path, dims.raw_path)
    take(compiled.method, dims.method)
    take(compiled.ua, dims.ua)
    take(compiled.referer, dims.referer)
    take(compiled.cookie, dims.cookie)
    return result
end

local function eval_layer(compiled, list, dims)
    local fast = eval_compiled(compiled, dims)
    local slow = eval_list(list, dims)
    if fast and fast.action == "allow" then return fast end
    if slow and slow.action == "allow" then return slow end
    if not fast then return slow end
    if not slow then return fast end
    return (fast.rule.priority or 100) <= (slow.rule.priority or 100) and fast or slow
end

function _M.has_rules(state)
    if not state then return false end
    -- get_site_state 已预计算；外部构造的 state（测试）走原逻辑。
    if state.has_any ~= nil then return state.has_any end
    local site_rules = state.site and state.site.rules or {}
    local site_compiled = state.site and state.site.compiled or {}
    local global_rules = state.global_rules or {}
    return #site_rules > 0 or #global_rules > 0
        or not compiled_empty(site_compiled) or not compiled_empty(state.global_compiled)
end

-- 返回命中的名单结果：
--   {hit=true, action="allow"|"deny"|"challenge"|"log", rule={...}}
-- 优先级：站点级名单整体覆盖全局名单；层内白名单(allow) > 黑名单(deny/challenge/log)
function _M.check(state)
    state = state or _M.get_site_state()
    if not state then return nil end
    local site_rules = state.site and state.site.rules or {}
    local site_compiled = state.site and state.site.compiled or {}
    local global_rules = state.global_rules or {}
    if not _M.has_rules(state) then
        return nil
    end
    local dims = build_dim_values()
    -- 站点级优先：站点名单有任何命中（allow 或 deny 类）即返回，不再看全局
    if state.site then
        local site_res = eval_layer(site_compiled, site_rules, dims)
        if site_res then
            return site_res
        end
    end
    return eval_layer(state.global_compiled, global_rules, dims)
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

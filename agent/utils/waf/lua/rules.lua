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

-- 把 rules.json 里各站点的可选防护模块显式记进日志。
--
-- 面板显示「CC 防护：已开启」而数据面实际不生效，是个静默失效：cc 段只在
-- ExportRules 写出 cc 字段时才存在，缺失时 access.lua 拿到 nil 直接跳过，
-- 既不拦截也不报错。这里在每 worker 首次加载后打一条汇总，日志里能直接
-- 看出「面板开了但 rules.json 里没有 cc」，省掉逐条 payload 复现的功夫。
local function report_protection_modules(data)
    if not data or type(data.sites) ~= "table" then return end
    for site_id, site in pairs(data.sites) do
        if type(site) == "table" then
            local cc = site.cc
            local probe = site.probe
            local bot = site.bot
            ngx.log(ngx.NOTICE, "[waf] site ", site_id,
                " enabled=", tostring(site.enabled ~= false),
                " cc=", cc and (tostring(cc.limit) .. "/" .. tostring(cc.window) .. "s/" .. tostring(cc.action))
                           or "absent(CC not enforced)",
                " bot=", bot and tostring(bot.enabled) or "absent",
                " probe=", probe and tostring(probe.enabled) or "absent")
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
    report_protection_modules(cache.data)
    require("waf.cc").selfcheck()
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

-- 负向（不等于）操作符：语义是「不满足正向条件时命中」。
--
-- 批量生成而不是逐个写：negate 把正向函数的返回值取反，
-- 保证 not_exact 与 exact 永远成对 —— 手写六遍很容易漏掉某个。
--
-- nil 的处理值得说明：正向函数对 nil 值一律返回 false（视为不匹配），
-- 取反后会变成 true，即「字段缺失」被算作「满足不等于」。这是刻意的 ——
-- allow 规则写 "not_contains" 时，请求没有这个 header 正是要放行的情况。
for _, base in ipairs({"exact", "contains", "prefix", "suffix", "wildcard", "regex"}) do
    local forward = match_ops[base]
    match_ops["not_" .. base] = function(v, p)
        return not forward(v, p)
    end
end

-- 提取请求各维度当前值（惰性）。
--
-- 早先这里是立即求值：每请求都调 get_headers()、构造 8 字段的表和一个闭包，
-- 哪怕规则只匹配 ip。get_headers() 要把全部请求头拷进 Lua 表，是名单查询
-- 路径上最贵的一步。改为按需取值后，只查 IP 的规则不再碰请求头。
local function build_dim_values()
    local headers = nil
    local cached = {}

    -- 取请求头：只在真的要匹配 header 维度时才拷贝。
    local function get_headers()
        if not headers then headers = ngx.req.get_headers() end
        return headers
    end

    local function dim(name)
        local v = cached[name]
        if v ~= nil then return v end
        if name == "ip" then
            v = ngx.var.remote_addr or ""
        elseif name == "path" then
            v = ngx.var.uri or ""
        elseif name == "raw_path" then
            v = ngx.var.request_uri or ""
        elseif name == "ua" then
            local h = get_headers()
            v = h["user-agent"] or h["User-Agent"] or ""
        elseif name == "referer" then
            local h = get_headers()
            v = h["referer"] or h["Referer"] or ""
        elseif name == "cookie" then
            v = ngx.var.http_cookie or ""
        elseif name == "method" then
            v = ngx.req.get_method()
        end
        cached[name] = v
        return v
    end

    return {
        ip = function() return dim("ip") end,
        path = function() return dim("path") end,
        raw_path = function() return dim("raw_path") end,
        ua = function() return dim("ua") end,
        referer = function() return dim("referer") end,
        method = function() return dim("method") end,
        cookie = function() return dim("cookie") end,
        header = function(name) return get_headers()[name:lower()] end,
    }
end

-- 单条规则是否命中
local function rule_hit(rule, dims)
    local mt, mv, mop = rule.match_type, rule.match_value, rule.match_op or "exact"
    local fn = match_ops[mop] or match_ops.exact
    if mt == "ip_group" then
        -- match_value 是组名。组不存在时返回 false（放行）——
        -- 这与「规则配错了但不该误拦流量」的取舍一致。
        -- 界面侧用下拉选组名、不允许手输，拼错的概率很低。
        --
        -- 组表挂在 dims 上而不是沿调用链逐层传 state：
        -- dims 已经在 rule_hit → eval_list → eval_layer → check 全链贯通，
        -- 挂上去就不用改四个函数的签名。
        local groups = dims.ip_groups
        local list = groups and groups[mv]
        if type(list) ~= "table" then return false end
        local ip = dims.ip()
        if not ip then return false end
        local hit = false
        for _, cidr in ipairs(list) do
            if iputils.in_cidr(ip, cidr) then hit = true break end
        end
        -- 负向操作符在这里同样要生效（与 ip/cidr 分支同一理由）：
        -- 「ip_group + not_exact」若仍按组内命中处理，
        -- 方向正好与界面选择相反。
        if mop:sub(1, 4) == "not_" then return not hit end
        return hit
    elseif mt == "geo" then
        -- match_value 是国家码，支持逗号分隔多个：CN,US
        local geo = dims.geo
        if not geo or geo.available ~= true then
            -- mmdb 不可用：不命中。allow 规则会因此不放行，
            -- deny 规则会因此不拦 —— 两个方向都不理想，
            -- 但"静默当成匹配一切"显然更危险。
            return false
        end
        local ranges = dims.geo_ranges
        local countries = geo.countries
        if type(ranges) ~= "table" and type(countries) ~= "table" then
            return false
        end
        local ip = dims.ip()
        if not ip then return false end
        local hit = false
        for code in mv:gmatch("[^,]+") do
            local key = code:upper():match("^%s*(.-)%s*$")
            local compiled = ranges and ranges[key]
            if compiled then
                -- 快路径：区间表二分，约 14 次比较搞定近万条 CIDR
                if iputils.in_ranges(ip, compiled) then hit = true break end
            else
                -- 兼容路径：没有预编译表时退回逐条判定（老版本 rules.json）
                local list = countries[key]
                if type(list) == "table" then
                    for _, cidr in ipairs(list) do
                        if iputils.in_cidr(ip, cidr) then hit = true break end
                    end
                end
            end
            if hit then break end
        end
        -- 负向操作符同样生效：与 ip/cidr、ip_group 分支同一理由，
        -- 否则「不属于某国」会被当成「属于某国」，方向正好相反。
        if mop:sub(1, 4) == "not_" then return not hit end
        return hit
    elseif mt == "ip" or mt == "cidr" then
        -- ip/cidr 走 CIDR 判定而非字符串匹配，match_op 原本被完全忽略。
        -- 但负向操作符必须在这里生效：用户给 IP 规则选 "not_exact" 时，
        -- 若仍按精确匹配执行，判定方向与界面选的**正好相反** ——
        -- 「不等于 1.2.3.4」变成「等于 1.2.3.4」，该放行的被拦。
        local hit = iputils.in_cidr(dims.ip(), mv)
        if mop:sub(1, 4) == "not_" then
            return not hit
        end
        return hit
    elseif mt == "path" then
        return fn(dims.path(), mv) or fn(dims.raw_path(), mv)
    elseif mt == "ua" then
        return fn(dims.ua(), mv)
    elseif mt == "referer" then
        return fn(dims.referer(), mv)
    elseif mt == "cookie" then
        return fn(dims.cookie(), mv)
    elseif mt == "method" then
        return fn(dims.method(), mv)
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

-- JSON null 兜底。Go 把 nil 切片/映射导出为 JSON null，cjson 解码后是
-- lightuserdata（cjson.null），它在 Lua 里是「真值」，`x or {}` 兜不住，
-- 紧接着 #/ipairs/next 会抛 "attempt to get length of ... a userdata value"。
local function table_of(v)
    if type(v) == "table" then return v end
    return {}
end

local function compiled_empty(compiled)
    if type(compiled) ~= "table" then return true end
    return not next(compiled.ip or {}) and not next(compiled.path or {})
        and not next(compiled.method or {}) and not next(compiled.ua or {})
        and not next(compiled.referer or {}) and not next(compiled.cookie or {})
end

-- 合并全局与站点的 IP 组：同名时站点覆盖全局。
-- 逐项拷贝而不是直接引用 rules.json 里的表 —— state 会被缓存，
-- 直接引用意味着上游改了表内容缓存也跟着变（虽然 5s TTL 下
-- 实际影响有限，但让缓存对象不可变更利于推理）。
local function merge_ip_groups(global_groups, site_groups)
    if type(global_groups) ~= "table" and type(site_groups) ~= "table" then
        return nil
    end
    local out = {}
    if type(global_groups) == "table" then
        for name, list in pairs(global_groups) do
            out[name] = list
        end
    end
    if type(site_groups) == "table" then
        for name, list in pairs(site_groups) do
            out[name] = list
        end
    end
    if next(out) == nil then return nil end
    return out
end

-- compile_geo_ranges 把「国家码 -> CIDR 字符串列表」预编译成区间表。
--
-- 为什么必须预编译：一次 geo 匹配要判定近万条 CIDR，若在请求路径上逐条
-- 交给 iputils.in_cidr，每条都要重新切分字符串、解析点分十进制；
-- 预编译后每请求只做 log2(1e4) ≈ 14 次比较。编译本身发生在 rules.json
-- 加载时（5 秒 TTL），不在请求路径上。
local function compile_geo_ranges(geo)
    if type(geo) ~= "table" or geo.available ~= true then
        return nil
    end
    local countries = geo.countries
    if type(countries) ~= "table" then
        return nil
    end
    local out = {}
    for code, list in pairs(countries) do
        out[code] = iputils.prepare_cidrs(list)
    end
    return out
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
    --
    -- 注意不能用 `x and x.y or {}`：Go 把 nil 切片导出成 JSON null，
    -- cjson 解出来是 lightuserdata，而它在 Lua 里是真值，`or` 兜不住，
    -- 随后 `#` / `ipairs` 会直接报错（"attempt to get length of ...
    -- a userdata value"）。统一走 table_of 兜底。
    local global_rules_ = table_of(data.global and data.global.rules)
    local global_compiled_ = table_of(data.global and data.global.compiled)
    local site_rules_ = table_of(site and site.rules)
    local site_compiled_ = table_of(site and site.compiled)
    local state = {
        site = site,
        has_any = #site_rules_ > 0 or #global_rules_ > 0
            or not compiled_empty(site_compiled_) or not compiled_empty(global_compiled_),
        global_rules = global_rules_,
        global_compiled = global_compiled_,
        -- 订阅黑名单总开关。缺省为 false：老版本 rules.json 没有这个字段，
        -- 此时按「未启用」处理，不能因为升级遗漏就默认开始拦 IP。
        global_iplist_enabled = (data.global and data.global.ipListEnabled) == true,
        -- IP 组：组名 -> CIDR 列表。本站组覆盖同名全局组
        --（与「站点名单优先于全局名单」的语义一致）。
        --
        -- 在这里合并而不是在 rule_hit 里现查：ip_group 是热路径上的
        -- 匹配类型，每次请求都重新遍历两张表合并会明显拖慢名单查询。
        -- state 有 5 秒 TTL 缓存，合并一次的代价可以忽略。
        ip_groups = merge_ip_groups(data.global and data.global.ip_groups,
            site and site.ip_groups),
        -- 地理规则的国家码 -> CIDR 列表。由 exporter 在导出时解析
        -- （Go 侧查 mmdb），数据面只需要做 CIDR 判定。
        --
        -- available=false 表示 mmdb 缺失或解析失败：此时 geo 规则
        -- 一律不命中。这不是"静默失效" —— 导出结果里带了这个标记，
        -- 前端会在规则列表上提示"地理数据缺失，规则当前不生效"。
        geo = data.geo,
        -- 预编译后的区间表（国家码 -> {v4=区间, v6=区间}）。
        -- 保留原 countries 字段是为了排查时能直接看到导出的 CIDR 原文。
        geo_ranges = compile_geo_ranges(data.geo),
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
    -- 「加白仍检测」的白名单：命中后不终止请求，而是把"继续检测"的决定
    -- 交回调用方（access.lua），由它放行但继续跑后续检测链、只记日志不拦截。
    -- 没有这一路时，用户点了误报反馈就等于让这段攻击彻底"看不见"了。
    local inspect_hit = nil
    for _, rule in ipairs(list) do
        if (rule.enabled == nil or rule.enabled == true) and not rule_expired(rule) then
            local hit = rule_hit(rule, dims)
            if hit then
                if rule.action == "allow" then
                    if rule.keep_inspecting or rule.keepInspecting then
                        -- 只记最高优先级的一条（数值越小越优先），
                        -- 免得日志里同一个请求刷出多条相同记录。
                        if not inspect_hit or (rule.priority or 100) < (inspect_hit.rule.priority or 100) then
                            inspect_hit = {hit = true, action = "allow", rule = rule, keep_inspecting = true}
                        end
                    else
                        return {hit = true, action = "allow", rule = rule}
                    end
                elseif not deny_hit or (rule.priority or 100) < (deny_hit.rule.priority or 100) then
                    deny_hit = {hit = true, action = rule.action, rule = rule}
                end
            end
        end
    end
    -- 普通 allow 已经在上面 return 了；走到这里说明要么无命中，要么只有
    -- keep_inspecting 型 allow。有 keep_inspecting 时它优先于黑名单返回，
    -- 否则"加白"就名存实亡。
    if inspect_hit then
        -- 把同层命中的 deny 一并带出去。
        -- 丢弃它的话，access.lua 只看到 action=allow，
        -- "命中了黑名单规则"这件事就彻底不可见 ——
        -- 而"既放行又让你看见"正是这个开关的全部价值。
        inspect_hit.deny_hit = deny_hit
        return inspect_hit
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
    -- 惰性：先看该维度有没有编译规则，有才取值。
    -- 若先 dims.ua() 再判断 group 非空，会为空的 ua/referer/cookie
    -- 白白拷贝一次全部请求头 —— 这正是早先每请求的开销来源。
    local function take(group, getter)
        if not group then return end
        local next_group = next(group)
        if not next_group then return end
        local value = getter()
        if value then result = prefer_result(result, group[value]) end
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
    -- keep_inspecting 优先于普通 allow。
    --
    -- compiled 表里只会有普通 allow（exporter 把带 keep_inspecting 的
    -- 规则挡在了表外），但同一维度上另一条普通 allow 仍可能优先级更高。
    -- 若直接 `if fast.action == allow then return fast`，keep_inspecting
    -- 标记会被整个丢掉 —— 开关"保存成功但完全失效"，且没有任何日志提示。
    if fast and fast.action == "allow" then
        if slow and slow.keep_inspecting then
            return slow
        end
        return fast
    end
    if slow and slow.action == "allow" then return slow end
    if not fast then return slow end
    if not slow then return fast end
    return (fast.rule.priority or 100) <= (slow.rule.priority or 100) and fast or slow
end

function _M.has_rules(state)
    if not state then return false end
    -- get_site_state 已预计算；外部构造的 state（测试）走原逻辑。
    if state.has_any ~= nil then return state.has_any end
    local site_rules = table_of(state.site and state.site.rules)
    local site_compiled = table_of(state.site and state.site.compiled)
    local global_rules = table_of(state.global_rules)
    return #site_rules > 0 or #global_rules > 0
        or not compiled_empty(site_compiled) or not compiled_empty(state.global_compiled)
end

-- 返回命中的名单结果：
--   {hit=true, action="allow"|"deny"|"challenge"|"log", rule={...}}
-- 优先级：站点级名单整体覆盖全局名单；层内白名单(allow) > 黑名单(deny/challenge/log)
function _M.check(state)
    state = state or _M.get_site_state()
    if not state then return nil end
    local site_rules = table_of(state.site and state.site.rules)
    local site_compiled = table_of(state.site and state.site.compiled)
    local global_rules = table_of(state.global_rules)
    if not _M.has_rules(state) then
        return nil
    end
    local dims = build_dim_values()
    -- IP 组与地理表挂在 dims 上，供 rule_hit 的 ip_group / geo 分支查。
    dims.ip_groups = state.ip_groups
    dims.geo = state.geo
    dims.geo_ranges = state.geo_ranges
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

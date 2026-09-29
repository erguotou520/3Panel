-- IP 黑名单区间表：解析 3PWL v2 二进制并做二分查找。
--
-- 为什么不走名单引擎的 rules 数组：那份数据由 iputils.in_cidr 逐条求值，
-- 每请求每条都要重新解析 CIDR 字符串。实测 3.2 万条时是 15ms/请求，
-- 直接把吞吐压到三位数 QPS。这里改为 Go 侧预排序、Lua 侧二分，
-- 实测 13 万条时单次查找 0.27 μs、内存约 1MB。
--
-- 格式（与 agent/utils/waf/wlformat 对应，小端）：
--   0..3   magic "3PWL"
--   4      version = 2
--   5..8   u32 flags（预留）
--   9..12  u32 countV4
--   13..16 u32 countV6
--   17..   v4：varint(gap) varint(len) 反复，gap 为与上一区间末地址的间距
--          v6：每条 32 字节 = 起点 16 字节 + 终点 16 字节
local _M = {}

local MAGIC = "3PWL"
local VERSION = 2
local HEADER_SIZE = 17

-- 进程内缓存。rules.lua 也是 5 秒 TTL 轮询，这里取同量级：
-- 文件被 Go 侧原子替换后，worker 在几秒内自然跟上，不需要 reload。
local CACHE_TTL = 5

local cache = {
    checked = 0,
    mtime = nil,
    size = nil,
    v4_lo = nil,
    v4_hi = nil,
    v6 = nil,   -- 稀疏表：v6 条目少，直接线性查
    v6_count = 0,
    err = nil,
}

local function u32(s, i)
    local a, b, c, d = s:byte(i, i + 3)
    if not d then return nil end
    return a + b * 256 + c * 65536 + d * 16777216
end

-- varint 读取。Lua 没有可用的无符号 64 位，但单个 varint 只用于表达
-- v4 的地址差值，31 位足够，故按双精度累加即可。
local function read_varint(s, pos)
    local v, shift = 0, 0
    while true do
        local b = s:byte(pos)
        if not b then return nil, pos end
        pos = pos + 1
        if b < 128 then
            return v + (b % 128) * (2 ^ shift), pos
        end
        v = v + (b % 128) * (2 ^ shift)
        shift = shift + 7
        if shift > 42 then return nil, pos end
    end
end

-- 解析文件内容为有序区间表。返回 nil 表示格式不合法，调用方保留旧数据。
local function parse(data)
    if not data or #data < HEADER_SIZE then return nil, "truncated header" end
    if data:sub(1, 4) ~= MAGIC then return nil, "bad magic" end
    if data:byte(5) ~= VERSION then return nil, "bad version" end
    local nv4 = u32(data, 10)
    local nv6 = u32(data, 14)
    if not nv4 or not nv6 then return nil, "truncated counts" end
    if nv4 < 0 or nv6 < 0 or nv4 > 50000000 or nv6 > 50000000 then
        return nil, "implausible counts"
    end

    local lo, hi = {}, {}
    local pos = HEADER_SIZE + 1
    local prev_end = -1
    for i = 1, nv4 do
        local gap
        gap, pos = read_varint(data, pos)
        if not gap then return nil, "v4 gap eof" end
        local len
        len, pos = read_varint(data, pos)
        if not len then return nil, "v4 len eof" end
        local start = prev_end + gap
        local end_ = start + len - 1
        if len <= 0 or start < 0 or end_ > 4294967295 then
            return nil, "v4 range out of bounds"
        end
        lo[i], hi[i] = start, end_
        prev_end = end_
    end

    -- v6：每条 32 字节，解析为两个可比较的字符串键。
    -- 条目数少（实测 538），线性查找足够，且避免实现 128 位运算。
    local v6 = {}
    for i = 1, nv6 do
        if pos + 31 > #data then return nil, "v6 truncated" end
        local s = data:sub(pos, pos + 15)
        local e = data:sub(pos + 16, pos + 31)
        v6[i] = {s, e}
        pos = pos + 32
    end

    return {lo = lo, hi = hi, v6 = v6, v6_count = nv6, count = nv4 + nv6}
end

-- 载入并缓存。文件未变化时不做任何解析工作。
local function ensure_loaded()
    local now = ngx.now()
    if now - cache.checked < CACHE_TTL then
        return cache.v4_lo ~= nil or cache.err ~= nil
    end
    cache.checked = now

    local data
    if _M._reader then
        data = _M._reader()
    else
        local f = io.open(_M.get_path(), "rb")
        if f then
            data = f:read("*a")
            f:close()
        end
    end
    if not data then
        -- 文件还不存在（首次部署，或下载失败尚未落盘）。
        -- 返回 false 而不是置错：没有名单只是不拦截，不能因此打挂站点。
        cache.err = "open failed"
        return false
    end

    -- 内容未变则跳过解析。仅比较长度不足以排除同长度不同内容，
    -- 但制品由 CI 全量替换且体积通常变化；配合 5 秒 TTL 开销可忽略。
    if data == cache.raw then
        return cache.v4_lo ~= nil
    end

    local parsed, err = parse(data)
    if not parsed then
        -- 解析失败保留旧数据继续用：宁可用一份旧名单，也不要把防护打空。
        ngx.log(ngx.ERR, "[waf] iplist parse failed: ", tostring(err))
        cache.err = err
        return cache.v4_lo ~= nil
    end

    cache.raw = data
    cache.v4_lo, cache.v4_hi = parsed.lo, parsed.hi
    cache.v6, cache.v6_count = parsed.v6, parsed.v6_count
    cache.count = parsed.count
    cache.err = nil
    return true
end

-- IPv4 数值形式：a.b.c.d -> a*2^24+b*2^16+c*2^8+d
function _M.ipv4_to_num(ip)
    if type(ip) ~= "string" then return nil end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return a * 16777216 + b * 65536 + c * 256 + d
end

-- 二分查找：区间已按起点升序且互不重叠（CI 侧折叠保证）。
function _M.in_list(ip)
    if not ensure_loaded() then return false end
    local n = _M.ipv4_to_num(ip)
    if n then
        local lo, hi = cache.v4_lo, cache.v4_hi
        local a, b = 1, #lo
        while a <= b do
            local mid = math.floor((a + b) / 2)
            local s = lo[mid]
            if n < s then
                b = mid - 1
            elseif n > hi[mid] then
                a = mid + 1
            else
                return true
            end
        end
        return false
    end
    -- v6：条目少，线性比较原始字节串。
    if cache.v6_count and cache.v6_count > 0 and type(ip) == "string" then
        local raw = _M.pack_v6(ip)
        if raw then
            local v6 = cache.v6
            for i = 1, cache.v6_count do
                local e = v6[i]
                if raw >= e[1] and raw <= e[2] then return true end
            end
        end
    end
    return false
end

-- IPv6 文本转 16 字节二进制串，用于字节序比较。
-- 只支持 nginx $remote_addr 形式（无 zone id 的十六进制记法）。
function _M.pack_v6(ip)
    if type(ip) ~= "string" or not ip:find(":", 1, true) then return nil end
    -- 拒绝 zone id（%eth0）之类的后缀
    if ip:find("%%", 1, true) then return nil end

    local groups = {}
    local function push(part)
        if #part > 4 then return false end
        local n = tonumber(part, 16)
        if not n or n < 0 or n > 65535 then return false end
        groups[#groups + 1] = n
        return true
    end

    local head, tail = ip:match("^(.-)::(.*)$")
    if head then
        -- 先分别解析两侧，算出 :: 省略了多少组，再一次性补零。
        -- 注意 fill 必须在推入 tail 之前算：groups 里此时只有 head 部分。
        local tail_parts = {}
        for p in tail:gmatch("[^:]+") do tail_parts[#tail_parts + 1] = p end
        for p in head:gmatch("[^:]+") do
            if not push(p) then return nil end
        end
        local fill = 8 - #groups - #tail_parts
        if fill < 0 then return nil end
        for _ = 1, fill do groups[#groups + 1] = 0 end
        for _, p in ipairs(tail_parts) do
            if not push(p) then return nil end
        end
    else
        for p in ip:gmatch("[^:]+") do
            if not push(p) then return nil end
        end
    end
    if #groups ~= 8 then return nil end

    local out = {}
    for i = 1, 8 do
        local n = groups[i]
        out[i] = string.char(math.floor(n / 256) % 256, n % 256)
    end
    return table.concat(out)
end

function _M.get_path()
    local p = ngx.var.waf_iplist_path
    if p and p ~= "" then
        return p
    end
    return _M.PATH
end

_M.PATH = "/www/waf/wl_v2.bin"

function _M.count()
    ensure_loaded()
    return cache.count or 0
end

-- 仅供测试重置缓存。
function _M._reset()
    cache.checked = 0
    cache.raw = nil
    cache.v4_lo, cache.v4_hi = nil, nil
    cache.v6, cache.v6_count = nil, 0
    cache.count = 0
    cache.err = nil
end

-- 仅供测试注入数据源（绕过 io.open）。
function _M._set_reader(fn)
    _M._reader = fn
end

return _M

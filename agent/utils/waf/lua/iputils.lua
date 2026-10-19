-- IPv4 / IPv6 与 CIDR 匹配（纯 Lua 实现，避免依赖外部库）
local _M = {}

-- 本地 split（不依赖 resty.string；跳过空段，适配 "::" 已单独处理的场景）
local function split(s, sep)
    local out = {}
    for part in string.gmatch(s, "([^" .. sep .. "]+)") do
        out[#out + 1] = part
    end
    return out
end

-- 展开为 8 组 16bit
local function expand_ipv6(ip)
    if ip:find(":", nil, false) == nil then
        return nil
    end
    local groups = {}
    if ip == "::" then
        for _ = 1, 8 do groups[#groups + 1] = 0 end
        return groups
    end

    -- 统一处理：按 :: 切左右，中段补零；IPv4 结尾转 2 组
    local left, right
    local double_colon_pos = ip:find("::", 1, true)
    if double_colon_pos then
        left = ip:sub(1, double_colon_pos - 1)
        right = ip:sub(double_colon_pos + 2)
    else
        left = ip
        right = nil
    end

    local lp, rp = {}, {}
    if left ~= "" then
        for _, s in ipairs(split(left, ":")) do lp[#lp + 1] = s end
    end
    if right ~= nil and right ~= "" then
        for _, s in ipairs(split(right, ":")) do rp[#rp + 1] = s end
    end

    -- IPv4 结尾（右段最后一项）转 2 组十六进制
    if #rp > 0 then
        local v4 = rp[#rp]:match("^%d+%.%d+%.%d+%.%d+$")
        if v4 then
            table.remove(rp)
            local a, b, c, d = v4:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
            if not a then return nil end
            rp[#rp + 1] = string.format("%x", tonumber(a) * 256 + tonumber(b))
            rp[#rp + 1] = string.format("%x", tonumber(c) * 256 + tonumber(d))
        end
    end
    if #lp > 0 then
        local v4 = lp[#lp]:match("^%d+%.%d+%.%d+%.%d+$")
        if v4 then return nil end -- IPv4 只允许出现在结尾
    end

    local total = #lp + #rp
    local missing = 8 - total
    if missing < 0 or (double_colon_pos == nil and missing ~= 0) then
        return nil
    end
    for i = 1, #lp do
        groups[i] = tonumber(lp[i], 16)
        if not groups[i] then return nil end
    end
    for i = 1, missing do
        groups[#lp + i] = 0
    end
    for i = 1, #rp do
        groups[#lp + missing + i] = tonumber(rp[i], 16)
        if not groups[#lp + missing + i] then return nil end
    end
    return groups
end

local function ipv4_to_num(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return a * 16777216 + b * 65536 + c * 256 + d
end

-- 判断 ip 是否落在 cidr 内；支持单 IP 与 CIDR
function _M.in_cidr(ip, cidr)
    if ip == cidr then return true end
    if cidr:find("/", 1, true) then
        local net, bits = cidr:match("^(.-)/(%d+)$")
        if not net then return false end
        bits = tonumber(bits)
        if net:find(":", 1, true) then
            local g, n = expand_ipv6(ip), expand_ipv6(net)
            if not g or not n then return false end
            if bits > 128 then return false end
            for i = 1, 8 do
                local group_bits = math.max(0, math.min(16, bits - (i - 1) * 16))
                if group_bits == 0 then break end
                local mask = 0xFFFF - (2 ^ (16 - group_bits) - 1)
                if (g[i] - g[i] % 2 ^ (16 - group_bits)) ~= (n[i] - n[i] % 2 ^ (16 - group_bits)) then
                    return false
                end
            end
            return true
        else
            local num, nnum = ipv4_to_num(ip), ipv4_to_num(net)
            if not num or not nnum or bits > 32 then return false end
            local mask = 0xFFFFFFFF - (2 ^ (32 - bits) - 1)
            return (num - num % 2 ^ (32 - bits)) == (nnum - nnum % 2 ^ (32 - bits))
        end
    end
    -- 纯 IP 相等
    if ip:find(":", 1, true) then
        local g1, g2 = expand_ipv6(ip), expand_ipv6(cidr)
        if not g1 or not g2 then return false end
        for i = 1, 8 do
            if g1[i] ~= g2[i] then return false end
        end
        return true
    end
    return ipv4_to_num(ip) == ipv4_to_num(cidr)
end

-- ============================================================================
-- 批量 CIDR 判定（geo 规则用）
--
-- 为什么需要这一套：geo 规则的国家段是从 mmdb 展开的，实测 CN 有近万条
-- IPv4 + 数千条 IPv6。若沿用 in_cidr 逐条判定，每个请求都要把近万条
-- CIDR 字符串重新解析一遍 —— 单是字符串分割就够把请求延迟拉高一个数量级。
--
-- 这里在 rules.json 加载时（5 秒 TTL，只在规则变化时发生）把 CIDR 预编译
-- 成 [起始, 结束] 区间并按起始值排序，请求路径上只做二分 + 数值/字典序比较。
-- ============================================================================

-- IPv6 的 8 组 16bit 转成固定 32 字符十六进制串：等长且按字节序比较，
-- 大小顺序与 128 位数值顺序一致，Lua 的字符串 `<` 可直接当数值比较用。
local function ipv6_to_hex(groups)
    local t = {}
    for i = 1, 8 do
        t[i] = string.format("%04x", groups[i])
    end
    return table.concat(t)
end

-- 返回该前缀的首地址与末地址（各 8 组）。
-- 原始 groups 未必已按前缀掩码，这里统一按 keep 位清零/置满。
local function ipv6_bounds(groups, bits)
    local start, stop = {}, {}
    local rem = bits
    for i = 1, 8 do
        local keep = math.max(0, math.min(16, rem))
        rem = rem - keep
        if keep == 0 then
            start[i] = 0
            stop[i] = 0xFFFF
        elseif keep == 16 then
            start[i] = groups[i]
            stop[i] = groups[i]
        else
            local size = 2 ^ (16 - keep)
            local base = groups[i] - groups[i] % size
            start[i] = base
            stop[i] = base + size - 1
        end
    end
    return start, stop
end

local function ipv4_bounds(num, bits)
    local size = 2 ^ (32 - bits)
    local base = num - num % size
    return base, base + size - 1
end

-- 排序并合并重叠区间。区间重叠会让二分退化成「只能找到最后一个起点」，
-- 嵌套段就会漏判，所以这里必须保证输出互不重叠。
local function normalize(items)
    table.sort(items, function(a, b)
        if a[1] == b[1] then return a[2] < b[2] end
        return a[1] < b[1]
    end)
    local out = {}
    for i = 1, #items do
        local it = items[i]
        local last = out[#out]
        if last and it[1] <= last[2] then
            if it[2] > last[2] then last[2] = it[2] end
        else
            out[#out + 1] = { it[1], it[2] }
        end
    end
    return out
end

-- prepare_cidrs 把 CIDR 字符串列表编译成区间表：{v4 = {...}, v6 = {...}}。
-- 解析失败的条目静默跳过（与 in_cidr 的容错一致）。
function _M.prepare_cidrs(list)
    local v4, v6 = {}, {}
    for _, cidr in ipairs(list or {}) do
        if type(cidr) == "string" then
            local net, bits = cidr, 32
            local slash = cidr:find("/", 1, true)
            if slash then
                net = cidr:sub(1, slash - 1)
                bits = tonumber(cidr:sub(slash + 1))
            end
            if net and net ~= "" and bits then
                if net:find(":", 1, true) then
                    if bits <= 128 then
                        local g = expand_ipv6(net)
                        if g then
                            local s, e = ipv6_bounds(g, bits)
                            v6[#v6 + 1] = { ipv6_to_hex(s), ipv6_to_hex(e) }
                        end
                    end
                elseif bits <= 32 then
                    local num = ipv4_to_num(net)
                    if num then
                        local s, e = ipv4_bounds(num, bits)
                        v4[#v4 + 1] = { s, e }
                    end
                end
            end
        end
    end
    return { v4 = normalize(v4), v6 = normalize(v6) }
end

local function in_sorted(list, key)
    local lo, hi = 1, #list
    while lo <= hi do
        local mid = math.floor((lo + hi) / 2)
        if list[mid][1] <= key then
            lo = mid + 1
        else
            hi = mid - 1
        end
    end
    -- hi 是最后一个 start <= key 的区间；只需再验证 key 没越过它的末尾
    if hi >= 1 and key <= list[hi][2] then
        return true
    end
    return false
end

-- in_ranges 判断 ip 是否落在 prepare_cidrs 产出的任一区间内。
function _M.in_ranges(ip, ranges)
    if not ranges or not ip then return false end
    if ip:find(":", 1, true) then
        local list = ranges.v6
        if not list or #list == 0 then return false end
        local g = expand_ipv6(ip)
        if not g then return false end
        return in_sorted(list, ipv6_to_hex(g))
    end
    local list = ranges.v4
    if not list or #list == 0 then return false end
    local num = ipv4_to_num(ip)
    if not num then return false end
    return in_sorted(list, num)
end

return _M

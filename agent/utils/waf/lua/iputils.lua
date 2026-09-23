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

return _M

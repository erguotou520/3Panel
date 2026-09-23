-- 受限表达式求值器（match_type=expr）
-- 支持语法：
--   ip in "1.2.3.0/24" and path matches "^/admin" and method in ["POST","PUT"]
--   ua contains "curl" or referer contains "spam.com"
-- 实现：白名单 token 解析 + 解释执行，绝不使用 loadstring，杜绝 RCE
local iputils = require("waf.iputils")
local _M = {}

local function tokenize(s)
    local tokens = {}
    local i, n = 1, #s
    while i <= n do
        local c = s:sub(i, i)
        if c == " " or c == "\t" then
            i = i + 1
        elseif c == '"' or c == "'" then
            local j = s:find(c, i + 1, true)
            if not j then return nil end
            tokens[#tokens + 1] = {t = "str", v = s:sub(i + 1, j - 1)}
            i = j + 1
        elseif c == "[" then
            tokens[#tokens + 1] = {t = "lbracket"}
            i = i + 1
        elseif c == "]" then
            tokens[#tokens + 1] = {t = "rbracket"}
            i = i + 1
        elseif c == "," then
            tokens[#tokens + 1] = {t = "comma"}
            i = i + 1
        elseif c:match("[%a_]") then
            local j = i
            while j <= n and s:sub(j, j):match("[%w_.]") do j = j + 1 end
            tokens[#tokens + 1] = {t = "word", v = s:sub(i, j - 1)}
            i = j
        else
            return nil -- 非法字符
        end
    end
    return tokens
end

local VARS = {ip = true, path = true, method = true, ua = true, referer = true, cookie = true}
local OPS = {"matches", "contains", "in", "eq"} -- 词序敏感，matches 先于 in
local KEYWORDS = {["and"] = true, ["or"] = true, ["not"] = true}

-- 解析单个比较：var op value-list
local function parse_cmp(tokens, pos, dims)
    local tk = tokens[pos]
    if not tk or tk.t ~= "word" or not VARS[tk.v] then
        return nil, pos
    end
    local var = tk.v
    pos = pos + 1
    local op = tokens[pos]
    if not op or op.t ~= "word" then return nil, pos end
    local opname = op.v
    pos = pos + 1
    -- 取值（字符串或字符串列表）
    local values = {}
    if tokens[pos] and tokens[pos].t == "lbracket" then
        pos = pos + 1
        while tokens[pos] do
            if tokens[pos].t == "str" then
                values[#values + 1] = tokens[pos].v
                pos = pos + 1
            elseif tokens[pos].t == "comma" then
                pos = pos + 1
            elseif tokens[pos].t == "rbracket" then
                pos = pos + 1
                break
            else
                return nil, pos
            end
        end
    elseif tokens[pos] and tokens[pos].t == "str" then
        values[#values + 1] = tokens[pos].v
        pos = pos + 1
    else
        return nil, pos
    end

    local val
    if var == "ip" then val = dims.ip
    elseif var == "path" then val = dims.path
    elseif var == "method" then val = dims.method
    elseif var == "ua" then val = dims.ua
    elseif var == "referer" then val = dims.referer
    elseif var == "cookie" then val = dims.cookie end
    val = val or ""

    local hit = false
    if opname == "in" then
        for _, v in ipairs(values) do
            if val == v or (var == "ip" and iputils.in_cidr(val, v)) then
                hit = true
                break
            end
        end
    elseif opname == "contains" then
        for _, v in ipairs(values) do
            if val:find(v, 1, true) then hit = true break end
        end
    elseif opname == "matches" then
        for _, v in ipairs(values) do
            local ok, res = pcall(function() return val:match(v) ~= nil end)
            if ok and res then hit = true break end
        end
    elseif opname == "eq" then
        hit = val == values[1]
    else
        return nil, pos
    end
    return hit, pos
end

-- 递归下降：or 表达式 = and 表达式 (or and 表达式)*
-- 前向声明（parse_and 定义在后）
local parse_and

local function parse_or(tokens, pos, dims)
    local left, np = parse_and(tokens, pos, dims)
    if left == nil then return nil, np end
    pos = np
    while tokens[pos] and tokens[pos].t == "word" and tokens[pos].v == "or" do
        pos = pos + 1
        local right
        right, np = parse_and(tokens, pos, dims)
        if right == nil then return nil, np end
        left = left or right
        pos = np
    end
    return left, pos
end

parse_and = function(tokens, pos, dims)
    local left, np = parse_cmp(tokens, pos, dims)
    if left == nil then return nil, np end
    pos = np
    while tokens[pos] and tokens[pos].t == "word" and tokens[pos].v == "and" do
        pos = pos + 1
        local right
        right, np = parse_cmp(tokens, pos, dims)
        if right == nil then return nil, np end
        left = left and right
        pos = np
    end
    return left, pos
end

function _M.eval(expr, dims)
    if type(expr) ~= "string" or #expr == 0 or #expr > 1024 then
        return false
    end
    local tokens = tokenize(expr)
    if not tokens or #tokens == 0 then
        return false
    end
    local res, pos = parse_or(tokens, 1, dims)
    -- 全部 token 必须被消费
    if res == nil or (pos and pos <= #tokens) then
        return false
    end
    return res == true
end

return _M

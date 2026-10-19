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
        elseif c == "(" then
            -- 括号支持条件嵌套：没有它 "(a and b) or c" 会因非法字符
            -- 整个 tokenize 返回 nil，规则静默永不命中。
            tokens[#tokens + 1] = {t = "lparen"}
            i = i + 1
        elseif c == ")" then
            tokens[#tokens + 1] = {t = "rparen"}
            i = i + 1
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
    -- dims 来自 rules.lua 时字段是惰性取值函数（避免无谓地拷贝请求头），
    -- 但单元测试直接传普通字符串表。两种都支持。
    local f = dims[var]
    val = type(f) == "function" and f() or f
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
            if ngx.re and ngx.re.find then
                local from = ngx.re.find(val, v, "jo")
                if from then hit = true break end
            else
                local ok, res = pcall(function() return val:match(v) ~= nil end)
                if ok and res then hit = true break end
            end
        end
    elseif opname == "eq" then
        hit = val == values[1]
    else
        return nil, pos
    end
    return hit, pos
end

-- 递归下降：
--   or      表达式 = and 表达式 (or and 表达式)*
--   and     表达式 = primary 表达式 (and primary 表达式)*
--   primary 表达式 = "(" or 表达式 ")" | "not" primary | 单个比较
--
-- primary 是递归的（括号里又是一个完整 or 表达式），所以支持任意层级嵌套。
-- 前向声明（parse_and / parse_or 定义在后面或前面）
local parse_and
local parse_or

-- primary：括号子表达式 / not 取反 / 单个比较
local function parse_primary(tokens, pos, dims)
    local tk = tokens[pos]
    if not tk then return nil, pos end
    if tk.t == "lparen" then
        local res, np = parse_or(tokens, pos + 1, dims)
        if res == nil then return nil, np end
        local close = tokens[np]
        if not close or close.t ~= "rparen" then
            return nil, np -- 缺右括号：判为非法表达式
        end
        return res, np + 1
    end
    if tk.t == "word" and tk.v == "not" then
        local res, np = parse_primary(tokens, pos + 1, dims)
        if res == nil then return nil, np end
        return (not res), np
    end
    return parse_cmp(tokens, pos, dims)
end

-- 必须是 `parse_or = function` 而不是 `local function parse_or`：
-- 后者等价于 `local parse_or = function`，会创建**新的** local，
-- 把上面 `local parse_or` 那句前向声明永远留在 nil，
-- 于是 parse_primary 里调用它报 "attempt to call a nil value"。
parse_or = function(tokens, pos, dims)
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
    local left, np = parse_primary(tokens, pos, dims)
    if left == nil then return nil, np end
    pos = np
    while tokens[pos] and tokens[pos].t == "word" and tokens[pos].v == "and" do
        pos = pos + 1
        local right
        right, np = parse_primary(tokens, pos, dims)
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

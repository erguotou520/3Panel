-- 请求规范化：URL 解码、HTML 实体、Unicode 归一、大小写，用于反混淆
local _M = {}

local function url_decode(s)
    if not s then return nil end
    s = s:gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return s
end

local HTML_ENTITIES = {
    ["&lt;"] = "<", ["&gt;"] = ">", ["&quot;"] = '"', ["&#34;"] = '"',
    ["&#39;"] = "'", ["&apos;"] = "'", ["&amp;"] = "&", ["&#x27;"] = "'",
    ["&#x2F;"] = "/", ["&#47;"] = "/", ["&nbsp;"] = " ",
}

local function decode_entities(s)
    for ent, ch in pairs(HTML_ENTITIES) do
        s = s:gsub(ent:gsub("([%[%]%(%)%.%%%+%-%*%?%$%^])", "%%%1"), ch)
    end
    -- 数字实体 &#NN; 与 &#xHH;
    s = s:gsub("&#x(%x+);", function(h) return string.char(tonumber(h, 16) % 256) end)
    s = s:gsub("&#(%d+);", function(d) return string.char(tonumber(d) % 256) end)
    return s
end

-- 多层解码直到稳定（防嵌套编码），上限 3 轮防死循环
function _M.normalize(s)
    if not s or s == "" then return "" end
    local prev = s
    for _ = 1, 3 do
        local cur = url_decode(prev)
        if cur then cur = decode_entities(cur) end
        if not cur or cur == prev then break end
        prev = cur
    end
    return prev:lower()
end

-- 路径规范化：解出 ../、// 等
function _M.normalize_path(p)
    if not p then return "" end
    local s = _M.normalize(p)
    s = s:gsub("%z", "")
    s = s:gsub("//+", "/")
    local changed = true
    while changed do
        local ns = s:gsub("/[^/]+/%.%./", "/")
        ns = ns:gsub("/%.%./", "/")
        changed = ns ~= s
        s = ns
    end
    return s
end

return _M

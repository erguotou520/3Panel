-- WAF 公共配置与工具
local _M = {}

-- 可由 nginx.conf env 或生成配置时注入的路径（access_by_lua_file 场景下用 ngx.var）
_M.RULES_PATH = "/www/waf/rules.json"
_M.LOG_PATH = "/www/waf/waf_events.log"
_M.BODY_LIMIT = 1024 * 1024 -- 超过 1MB 的 body 只抽样检测
_M.LOG_VALUE_LIMIT = 4096

local SENSITIVE_NAMES = {"password", "passwd", "pwd", "token", "secret", "authorization", "cookie", "session", "api_key", "apikey"}

function _M.sanitize_log_value(value)
    if not value or value == "" then return "" end
    local text = tostring(value)
    local lower = text:lower()
    for _, name in ipairs(SENSITIVE_NAMES) do
        if lower:find(name, 1, true) then
            return "[redacted]"
        end
    end
    if #text > _M.LOG_VALUE_LIMIT then
        return text:sub(1, _M.LOG_VALUE_LIMIT) .. "[truncated]"
    end
    return text
end

function _M.get_rules_path()
    local p = ngx.var.waf_rules_path
    if p and p ~= "" then
        return p
    end
    return _M.RULES_PATH
end

function _M.get_log_path()
    local p = ngx.var.waf_log_path
    if p and p ~= "" then
        return p
    end
    return _M.LOG_PATH
end

-- 站点标识：由生成配置时 set $waf_site_id <websiteId>
function _M.get_site_id()
    local sid = ngx.var.waf_site_id
    if sid and sid ~= "" then
        return tonumber(sid) or sid
    end
    return 0
end

function _M.json_encode(data, ok_nil)
    local ok, json = pcall(function()
        return require("cjson.safe").encode(data)
    end)
    if ok and json then
        return json
    end
    return ok_nil
end

function _M.json_decode(str)
    if not str or str == "" then
        return nil
    end
    local ok, data = pcall(function()
        return require("cjson.safe").decode(str)
    end)
    if ok then
        return data
    end
    return nil
end

function _M.now_ms()
    return ngx.now() * 1000
end

return _M

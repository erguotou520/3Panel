-- 日志管道：事件写入本地缓冲文件（按行 JSON），由 agent 后台批量入库
-- worker 不直连 DB；写文件失败不影响请求
local config = require("waf.config")
local _M = {}

local ngx_log = ngx.log
local ERR = ngx.ERR

-- event: {websiteId, websiteName, ruleId, ruleName, layer, attackType, action,
--         method, path, query, ip, userAgent, detail, requestBody, durationMs}
function _M.emit(event)
    event.time = ngx.time()
    local line = config.json_encode(event)
    if not line then
        return false
    end
    local path = config.get_log_path()
    local f = io.open(path, "a")
    if not f then
        ngx_log(ERR, "[waf] cannot open log file: ", path)
        return false
    end
    f:write(line, "\n")
    f:close()
    return true
end

return _M

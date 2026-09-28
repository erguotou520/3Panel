-- 日志管道：事件写入本地缓冲文件（按行 JSON），由 agent 后台批量入库
-- worker 不直连 DB；写文件失败不影响请求
local config = require("waf.config")
local _M = {}

local ngx_log = ngx.log
local ERR = ngx.ERR
local QUEUE_PREFIX = "waf:log:"
local SEQ_KEY = QUEUE_PREFIX .. "seq"
local CURSOR_KEY = QUEUE_PREFIX .. "cursor"
local SCHEDULED_KEY = QUEUE_PREFIX .. "scheduled"
local BATCH_SIZE = 500

local schedule_flush

local function flush(premature, path)
    if premature then return end
    local dict = ngx.shared.waf_dict
    local cursor = tonumber(dict:get(CURSOR_KEY)) or 0
    local last = tonumber(dict:get(SEQ_KEY)) or 0
    local stop = math.min(last, cursor + BATCH_SIZE)
    local lines = {}
    for i = cursor + 1, stop do
        local line = dict:get(QUEUE_PREFIX .. i)
        if line then lines[#lines + 1] = line end
    end
    if #lines > 0 then
        local f = io.open(path, "a")
        if not f then
            dict:delete(SCHEDULED_KEY)
            ngx_log(ERR, "[waf] cannot open log file: ", path)
            ngx.timer.at(1, flush, path)
            return
        end
        f:write(table.concat(lines, "\n"), "\n")
        f:close()
    end
    for i = cursor + 1, stop do
        dict:delete(QUEUE_PREFIX .. i)
    end
    dict:set(CURSOR_KEY, stop)
    dict:delete(SCHEDULED_KEY)
    if (tonumber(dict:get(SEQ_KEY)) or 0) > stop then
        schedule_flush(path)
    end
end

schedule_flush = function(path)
    local dict = ngx.shared.waf_dict
    if dict:add(SCHEDULED_KEY, true, 5) then
        local ok, err = ngx.timer.at(0.05, flush, path)
        if not ok then
            dict:delete(SCHEDULED_KEY)
            ngx_log(ERR, "[waf] cannot schedule log flush: ", err)
            return false
        end
    end
    return true
end

-- event: {websiteId, websiteName, ruleId, ruleName, layer, attackType, action,
--         method, path, query, ip, userAgent, detail, requestBody, durationMs}
function _M.emit(event)
    event.time = ngx.time()
    local line = config.json_encode(event)
    if not line then
        return false
    end
    local dict = ngx.shared.waf_dict
    local seq, err = dict:incr(SEQ_KEY, 1, 0)
    if not seq then
        ngx_log(ERR, "[waf] cannot allocate log queue sequence: ", err)
        return false
    end
    local ok, set_err = dict:set(QUEUE_PREFIX .. seq, line, 60)
    if not ok then
        ngx_log(ERR, "[waf] cannot enqueue log event: ", set_err)
        return false
    end
    return schedule_flush(config.get_log_path())
end

return _M

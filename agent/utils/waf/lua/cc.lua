-- CC 防护：基于 lua_shared_dict 的固定窗口计数器
-- 维度：IP（可扩展 IP+URL）；超限后按配置动作处置
local _M = {}

local dict = ngx.shared.waf_dict
local WINDOW = 60 -- 秒，固定窗口

-- cc_conf: {limit=100, window=60, action="deny"|"challenge"|"log", byUri=true/false}
-- 返回 nil（未超限）或 "deny"/"challenge"/"log"
-- 注意：ngx.shared 只接受 string/number/boolean，计数器必须 JSON 序列化后存储
function _M.check(cc_conf)
    if not cc_conf or not cc_conf.limit or cc_conf.limit <= 0 then
        return nil
    end
    if not dict then
        ngx.log(ngx.ERR, "[waf] shared dict waf_dict missing, cc disabled")
        return nil
    end
    local ip = ngx.var.remote_addr or ""
    if ip == "" then
        return nil
    end
    local window = cc_conf.window and cc_conf.window > 0 and cc_conf.window or WINDOW
    local now = math.floor(ngx.now())
    local bucket = math.floor(now / window)
    local key = "cc:" .. ip .. ":" .. bucket
    if cc_conf.byUri then
        key = key .. ":" .. (ngx.var.uri or "")
    end
    -- The bucket is part of the key, so an atomic shared-dict increment avoids
    -- JSON decode/encode on every request. init_ttl bounds stale buckets.
    local count, err = dict:incr(key, 1, 0, window * 2)
    if not count then
        ngx.log(ngx.WARN, "[waf] cc counter failed: ", tostring(err))
        return nil
    end
    if count > cc_conf.limit then
        return cc_conf.action or "deny"
    end
    return nil
end

-- 挑战通过标记
function _M.challenge_passed()
    local ok, passed = pcall(function()
        return ngx.var.cookie_waf_challenge == "ok"
    end)
    return ok and passed
end

return _M

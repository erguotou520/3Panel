-- CC 防护：基于 lua_shared_dict 的固定窗口计数器
-- 维度：IP（可扩展 IP+URL）；超限后按配置动作处置
-- IPv6 按 /64 前缀聚合（见 iputils.rate_key）；byUri 维度的 URI 走定长哈希分桶。
local _M = {}

local iputils = require("waf.iputils")

local dict = ngx.shared.waf_dict
local WINDOW = 60 -- 秒，固定窗口

-- byUri 维度：URI 用 crc32 取模分桶，而不是整串拼进 key。
-- 旧实现 key 里带完整 URI，唯一 URL 可以无限制造 shared-dict 键，把 32m 的
-- waf_dict（CC / probe / 攻击日志 / 规则快照共用）打满 —— 之后 incr 失败，
-- CC 静默放行、日志静默丢失。「不同 URI 分开计数」的语义保留，碰撞率 1/256，
-- 属于有界近似的可接受代价。
local URI_BUCKETS = 256

-- 取 URI 的定长桶号。生产环境用 ngx.crc32_short；单测 / 非 OpenResty 环境
-- 没有这个 API，退回 iputils.str_hash，保证分桶依然有界且确定性一致。
local function uri_bucket(uri)
    if ngx.crc32_short then
        return ngx.crc32_short(uri) % URI_BUCKETS
    end
    return iputils.str_hash(uri) % URI_BUCKETS
end

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
    -- IPv6 折叠到 /64 前缀，否则同一 /64 内换地址即可绕过计数（见 iputils.rate_key）
    local rate_key = iputils.rate_key(ip)
    if not rate_key then
        return nil
    end
    local window = cc_conf.window and cc_conf.window > 0 and cc_conf.window or WINDOW
    local now = math.floor(ngx.now())
    local bucket = math.floor(now / window)
    local key = "cc:" .. rate_key .. ":" .. bucket
    if cc_conf.byUri then
        key = key .. ":" .. uri_bucket(ngx.var.uri or "")
    end
    -- The bucket is part of the key, so an atomic shared-dict increment avoids
    -- JSON decode/encode on every request. init_ttl bounds stale buckets.
    local count, err = dict:incr(key, 1, 0, window * 2)
    if not count then
        -- dict 满 / incr 异常时仍然放行（fail-open：不能因为计数器坏了整站拒绝），
        -- 但升级为 ERR，让面板侧能靠 error_log 发现「限流静默失效」。
        ngx.log(ngx.ERR, "[waf] cc counter failed: ", tostring(err))
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

-- 启动自检：cc 计数器依赖 lua_shared_dict waf_dict。
--
-- waf.conf 里 `lua_shared_dict waf_dict 32m` 若被注释掉或改名，check() 会在
-- 每个请求上打一条 ERR —— 但 nginx 的 error_log 在面板默认配置下是 notice
-- 级别，ERR 之外也可能被采样丢弃，表现为「限流就是不生效」且毫无线索。
-- 这里在 worker 初始化阶段一次性把结论写进日志，让静默失效可被定位。
function _M.selfcheck()
    if not dict then
        ngx.log(ngx.ERR, "[waf] CC selfcheck FAILED: shared dict 'waf_dict' is not declared; ",
            "check lua_shared_dict waf_dict in waf.conf — rate limiting will NOT run")
        return false
    end
    local probe_key = "cc:selfcheck"
    local count, err = dict:incr(probe_key, 1, 0, 60)
    if not count then
        ngx.log(ngx.ERR, "[waf] CC selfcheck FAILED: dict incr error: ", tostring(err))
        return false
    end
    ngx.log(ngx.NOTICE, "[waf] CC selfcheck ok: shared dict 'waf_dict' usable")
    return true
end

return _M

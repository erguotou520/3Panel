-- 扫描器行为指纹：路径遍历探测节奏识别
-- access 阶段可测信号：同 IP 短窗口内访问的不同 URI 数量突增（目录爆破/扫描特征）。
-- IPv6 按 /64 前缀聚合（见 iputils.rate_key），否则同 /64 内换源地址即可把统计拆散。
-- 404 率需响应阶段统计，此处以「URI 多样性」等效替代，并叠加请求速率。
-- 阈值策略由 rules.json 的 sites[sid].probe = {enabled=true, maxURIs=60, window=60, maxRPS=120} 驱动
local _M = {}

local iputils = require("waf.iputils")

local dict = ngx.shared.waf_dict

-- 每-URI 子键的桶数：URI 只保留定长哈希桶，不再每个唯一 URI 建一个键。
-- 旧实现每个请求 uri 一个键，目录爆破/随机 URL 可以把 waf_dict（32m）打满，
-- 之后 incr/add 失败，指纹统计失真、攻击日志也一并丢失。
local URI_BUCKETS = 2048

local function uri_bucket(uri)
    if ngx.crc32_short then
        return ngx.crc32_short(uri) % URI_BUCKETS
    end
    return iputils.str_hash(uri) % URI_BUCKETS
end

-- 返回 nil（正常）或 描述字符串（命中指纹）
-- 注意：ngx.shared 只接受 string/number/boolean，记录必须 JSON 序列化后存储
function _M.check(conf)
    if not conf or not conf.enabled or not dict then
        return nil
    end
    local ip = ngx.var.remote_addr or ""
    if ip == "" then
        return nil
    end
    -- IPv6 折叠到 /64：否则同一 /64 内换地址就能把「同 IP 不同 URI」的
    -- 多样性/速率统计拆散（见 iputils.rate_key）。
    local rate_key = iputils.rate_key(ip)
    if not rate_key then
        return nil
    end
    local window = (conf.window and conf.window > 0) and conf.window or 60
    local bucket = math.floor(ngx.now() / window)
    local base = "probe:" .. rate_key .. ":" .. bucket
    local ttl = window * 2
    local count = dict:incr(base .. ":count", 1, 0, ttl) or 0

    -- 共享字典的 add 是 worker 间原子的；用 URI 哈希桶作键，避免每个请求
    -- JSON 序列化整个 URI 列表并线性扫描。桶数固定 => 每 IP 每窗口的键数有界。
    local uri = ngx.var.uri or "/"
    local slot = uri_bucket(uri)
    local is_new = dict:add(base .. ":uri:" .. slot, true, ttl)
    local uri_count = tonumber(dict:get(base .. ":uris")) or 0
    if is_new then
        uri_count = dict:incr(base .. ":uris", 1, 0, ttl) or uri_count
    end

    -- 指纹 1：窗口内不同 URI 数超过阈值（目录爆破节奏）
    local max_uris = conf.maxURIs or 60
    if uri_count > max_uris then
        return string.format("scanner fingerprint: %d distinct URIs in %ds", uri_count, window)
    end
    -- 指纹 2：请求速率突增
    local max_rps = conf.maxRPS or 120
    if count > max_rps then
        return string.format("scanner fingerprint: %d requests in %ds", count, window)
    end
    return nil
end

return _M

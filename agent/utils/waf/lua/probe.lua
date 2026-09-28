-- 扫描器行为指纹：路径遍历探测节奏识别
-- access 阶段可测信号：同 IP 短窗口内访问的不同 URI 数量突增（目录爆破/扫描特征）。
-- 404 率需响应阶段统计，此处以「URI 多样性」等效替代，并叠加请求速率。
-- 阈值策略由 rules.json 的 sites[sid].probe = {enabled=true, maxURIs=60, window=60, maxRPS=120} 驱动
local _M = {}

local dict = ngx.shared.waf_dict

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
    local window = (conf.window and conf.window > 0) and conf.window or 60
    local bucket = math.floor(ngx.now() / window)
    local base = "probe:" .. ip .. ":" .. bucket
    local ttl = window * 2
    local count = dict:incr(base .. ":count", 1, 0, ttl) or 0

    -- 共享字典的 add 是 worker 间原子的；用 URI 哈希作键，避免每个请求
    -- JSON 序列化整个 URI 列表并线性扫描。
    local uri = ngx.var.uri or "/"
    local uri_hash = ngx.crc32_short and ngx.crc32_short(uri) or uri
    local is_new = dict:add(base .. ":uri:" .. tostring(uri_hash), true, ttl)
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

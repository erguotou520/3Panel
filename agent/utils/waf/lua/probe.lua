-- 扫描器行为指纹：路径遍历探测节奏识别
-- access 阶段可测信号：同 IP 短窗口内访问的不同 URI 数量突增（目录爆破/扫描特征）。
-- 404 率需响应阶段统计，此处以「URI 多样性」等效替代，并叠加请求速率。
-- 阈值策略由 rules.json 的 sites[sid].probe = {enabled=true, maxURIs=60, window=60, maxRPS=120} 驱动
local cjson = require("cjson.safe")
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

    local uri = ngx.var.uri or "/"
    local rec = nil
    local raw = dict:get(base)
    if raw then
        rec = cjson.decode(raw)
    end
    if not rec then
        rec = {count = 0, uris = {}}
    end

    rec.count = rec.count + 1
    -- URI 集合去重（容量封顶防内存膨胀；命中封顶后只计数）
    local seen = false
    if #rec.uris < 256 then
        for _, u in ipairs(rec.uris) do
            if u == uri then
                seen = true
                break
            end
        end
        if not seen then
            rec.uris[#rec.uris + 1] = uri
        end
    end
    dict:set(base, cjson.encode(rec), window * 2)

    -- 指纹 1：窗口内不同 URI 数超过阈值（目录爆破节奏）
    local max_uris = conf.maxURIs or 60
    if #rec.uris > max_uris then
        return string.format("scanner fingerprint: %d distinct URIs in %ds", #rec.uris, window)
    end
    -- 指纹 2：请求速率突增
    local max_rps = conf.maxRPS or 120
    if rec.count > max_rps then
        return string.format("scanner fingerprint: %d requests in %ds", rec.count, window)
    end
    return nil
end

return _M

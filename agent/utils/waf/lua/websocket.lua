-- WebSocket 检测：升级请求的语义检查
--
-- 技术边界（务必理解，否则会误判"实现了却没生效"）：
--   WebSocket 握手发生在 HTTP Upgrade 阶段，此时连接**还没升级**，
--   access 阶段能读到的只有握手请求本身。之后的数据帧走的是
--   独立的 WebSocket 协议通道，**access_by_lua 完全读不到**。
--
--   所以本模块负责的是「握手请求」这一层：URL /参数 / Header 里的攻击载荷。
--   数据帧要检测必须换机制（body_filter 或 stream_lua），且代价不小：
--   要按 RFC 6455 解帧、处理分片与掩码，还要处理二进制消息。
--
-- 为什么这层仍有价值：实测（2026-10-09）握手请求里的 URL 载荷、
-- 自定义Header 载荷、扫描器 UA 全部能被拦住；漏的只是连接建立之后的帧内容。
local _M = {}

-- 是否 WebSocket 升级请求
function _M.is_upgrade()
    local upgrade = ngx.var.http_upgrade
    return type(upgrade) == "string" and upgrade:lower():find("websocket", 1, true) ~= nil
end

-- 握手阶段的安全检查。
-- 只查攻击载荷，不做协议合规性校验（那些交给后端）。
-- 返回描述字符串（命中）或 nil。
function _M.inspect_handshake(semantic, uri)
    -- 1. URI 与参数：升级请求的 URL 同样可以携带攻击载荷
    --    （例：/ws?q=' OR 1=1--），走与其他请求同一套检测
    local hit = semantic.inspect(uri, uri)
    if hit then
        return "websocket upgrade uri: " .. hit.type
    end

    local ok, params = pcall(ngx.req.get_uri_args, 100)
    if ok and params then
        for k, vs in pairs(params) do
            local vals = type(vs) == "table" and vs or {vs}
            for _, v in ipairs(vals) do
                if type(v) == "string" then
                    local h = semantic.inspect(v, uri)
                    if h then
                        return "websocket upgrade param: " .. h.type
                    end
                end
            end
        end
    end

    -- 2. Sec-WebSocket-Protocol：客户端在协商子协议时可以塞任意字符串，
    --    这是个容易忽略的注入位（有些实现会把它回显或用于路由）。
    local proto = ngx.var.http_sec_websocket_protocol
    if type(proto) == "string" and proto ~= "" then
        local h = semantic.inspect(proto, uri)
        if h then
            return "websocket subprotocol: " .. h.type
        end
    end

    -- 3. Sec-WebSocket-Extensions：同理，扩展协商串也可能被携带载荷
    local ext = ngx.var.http_sec_websocket_extensions
    if type(ext) == "string" and ext ~= "" then
        local h = semantic.inspect(ext, uri)
        if h then
            return "websocket extensions: " .. h.type
        end
    end

    return nil
end

return _M
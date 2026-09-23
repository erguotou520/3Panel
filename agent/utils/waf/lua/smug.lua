-- HTTP 请求走私识别：CL/TE 不一致、畸形 Transfer-Encoding、重复/冲突头
-- 在 access 阶段检查原始请求头，不读 body
local _M = {}

-- 返回 nil（未检出）或 描述字符串
function _M.detect()
    local headers, err = ngx.req.get_headers(100)
    if not headers then
        return nil
    end

    local has_cl, cl_val = false, nil
    local has_te, te_val = false, nil
    local dup_te = false

    for k, v in pairs(headers) do
        local lk = k:lower()
        if lk == "content-length" then
            if has_cl and tostring(v) ~= tostring(cl_val) then
                return "duplicate conflicting Content-Length"
            end
            has_cl = true
            cl_val = v
        elseif lk == "transfer-encoding" then
            if has_te and tostring(v):lower() ~= tostring(te_val):lower() then
                dup_te = true
            end
            has_te = true
            te_val = v
        elseif lk == "content-type" and type(v) == "table" then
            -- 多值 content-type 是混淆信号，但可能合法，忽略
        end
    end

    -- CL 与 TE 同时出现：走私的经典前奏（TE 优先时 CL 是干扰，反之亦然）
    if has_cl and has_te then
        local tel = tostring(te_val):lower()
        -- TE: chunked + 非零 CL
        if tel:find("chunked") then
            local n = tonumber(cl_val)
            if n == nil or n > 0 then
                return "both Content-Length and Transfer-Encoding present (CL=" .. tostring(cl_val) .. ")"
            end
        end
    end

    -- 畸形 Transfer-Encoding：非 chunked 的未知编码组合
    if has_te then
        local tel = tostring(te_val):lower()
        if not tel:find("chunked") and (tel:find("gzip") or tel:find("deflate") or tel:find("identity") or tel == "") then
            return "malformed Transfer-Encoding: " .. tostring(te_val)
        end
    end

    if dup_te then
        return "duplicate Transfer-Encoding headers"
    end

    -- 非法 CL 值：非数字 / 带符号
    if has_cl then
        local s = tostring(cl_val)
        if not s:match("^%d+$") then
            return "malformed Content-Length: " .. s
        end
    end

    return nil
end

return _M

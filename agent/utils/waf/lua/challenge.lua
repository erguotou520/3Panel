-- JS 挑战：服务端签发短期 Cookie，客户端回访时验证签名与有效期
-- 说明：这是轻量级挑战（挡住简单脚本与 CC bot），不是完整反爬方案
local _M = {}

local CHALLENGE_COOKIE = "waf_challenge"

function _M.passed()
    local token = ngx.var["cookie_" .. CHALLENGE_COOKIE]
    local secret = ngx.var.waf_challenge_secret
    if not token or not secret or secret == "" then
        return false
    end
    local expires, signature = token:match("^(%d+)%.([%w_%-]+)$")
    if not expires or tonumber(expires) < ngx.time() then
        return false
    end
    local payload = expires .. "|" .. (ngx.var.remote_addr or "") .. "|" .. (ngx.var.http_user_agent or "")
    local expected = ngx.encode_base64(ngx.hmac_sha1(secret, payload), true):gsub("=+$", "")
    return signature == expected
end

function _M.respond()
    local expires = tostring(ngx.time() + 3600)
    local secret = ngx.var.waf_challenge_secret or ""
    local payload = expires .. "|" .. (ngx.var.remote_addr or "") .. "|" .. (ngx.var.http_user_agent or "")
    local signature = ngx.encode_base64(ngx.hmac_sha1(secret, payload), true):gsub("=+$", "")
    local token = expires .. "." .. signature
    ngx.status = 200
    ngx.header.content_type = "text/html; charset=utf-8"
    -- Cookie is server-issued and never needs to be readable by page scripts.
    local attributes = "; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax"
    if ngx.var.scheme == "https" then attributes = attributes .. "; Secure" end
    ngx.header["Set-Cookie"] = CHALLENGE_COOKIE .. "=" .. token .. attributes
    ngx.say('<!DOCTYPE html><html><body>')
    ngx.say('<script>location.reload();</script>')
    ngx.say('<noscript>Enable JavaScript to continue.</noscript>')
    ngx.say('</body></html>')
    return ngx.exit(200)
end

return _M

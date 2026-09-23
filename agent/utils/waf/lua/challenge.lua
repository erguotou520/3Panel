-- JS 挑战：返回一段计算 Cookie 的 JS，客户端回访携带 waf_challenge=ok 即放行
-- 说明：这是轻量级挑战（挡住简单脚本与 CC bot），不是完整反爬方案
local _M = {}

local CHALLENGE_COOKIE = "waf_challenge"

function _M.passed()
    return ngx.var["cookie_" .. CHALLENGE_COOKIE] == "ok"
end

function _M.respond()
    local token = "ok"
    ngx.status = 200
    ngx.header.content_type = "text/html; charset=utf-8"
    -- 设置挑战 Cookie（有效期 1 小时）
    ngx.header["Set-Cookie"] = CHALLENGE_COOKIE .. "=" .. token .. "; Path=/; Max-Age=3600"
    ngx.say('<!DOCTYPE html><html><body>')
    ngx.say('<script>document.cookie="' .. CHALLENGE_COOKIE .. '=' .. token .. '; path=/";location.reload();</script>')
    ngx.say('<noscript>Enable JavaScript to continue.</noscript>')
    ngx.say('</body></html>')
    return ngx.exit(200)
end

return _M

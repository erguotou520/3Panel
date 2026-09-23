-- 机器人识别：善意 bot 白名单 + 扫描器指纹拦截
-- 策略由 rules.json 的 bot 配置驱动：{enabled=true, allowGoodBots=true, blockBadBots=true}
local _M = {}

-- 善意 bot（搜索引擎等）：UA 关键字 -> 名称
local GOOD_BOTS = {
    {kw = "googlebot", name = "Google"},
    {kw = "bingbot", name = "Bing"},
    {kw = "baiduspider", name = "Baidu"},
    {kw = "sogou", name = "Sogou"},
    {kw = "360spider", name = "360"},
    {kw = "yisouspider", name = "Yisou"},
    {kw = "yandexbot", name = "Yandex"},
    {kw = "duckduckbot", name = "DuckDuckGo"},
    {kw = "slurp", name = "Yahoo"},
    {kw = "applebot", name = "Apple"},
}

-- 扫描器/攻击工具指纹（默认拦截）
local BAD_BOTS = {
    "sqlmap", "nikto", "nmap%s+scripting", "masscan", "zgrab", "nuclei",
    "dirbuster", "dirb", "gobuster", "wfuzz", "ffuf", "feroxbuster",
    "acunetix", "nessus", "openvas", "wpscan", "havij", "hydra",
    "arachni", "w3af", "whatweb", "ospython-requests%s*/", "python%-requests",
    "go%-http%-client", "java/", "scrapy", "libwww%-perl", "httrack",
}

-- 客户端 bot 类型：nil = 普通 UA，"good" = 善意 bot，"bad" = 扫描器
function _M.classify(ua)
    if not ua or ua == "" then
        return nil
    end
    local s = ua:lower()
    for _, b in ipairs(GOOD_BOTS) do
        if s:find(b.kw, 1, true) then
            return "good", b.name
        end
    end
    for _, kw in ipairs(BAD_BOTS) do
        if s:find(kw) then
            return "bad", kw
        end
    end
    return nil
end

-- 按策略处置：返回 nil（放行）或 "good" / "bad"（命中类型，由 access 决定动作）
function _M.check(conf)
    if not conf or not conf.enabled then
        return nil
    end
    local ua = ngx.var.http_user_agent
    local kind = _M.classify(ua)
    if kind == "good" and conf.allowGoodBots then
        return "good"
    elseif kind == "bad" and conf.blockBadBots then
        return "bad"
    end
    return nil
end

return _M

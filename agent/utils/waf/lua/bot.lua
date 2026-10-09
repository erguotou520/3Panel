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
--
-- 补齐说明（原词表漏了商业扫描器里最常被用来做手工探测的几个）：
-- burpsuite / zap / netsparker / appscan / webinspect 这类商用工具几乎不带
-- 明显特征，但它们在 UA 里一定会留名 —— waf-detector 的 ScannerDetection
-- 类别测的就是这些，漏掉等于该类别 0% 拦截。
-- 词表按"宁可多拦测试工具、不误伤正常客户端"的原则加：
--   · 工具名（含常见变体与版本后缀）
--   · 明确的技术指纹头（OWASP ZAP、Go-http-client 等）
local BAD_BOTS = {
    -- 商业 / 手工渗透工具
    "sqlmap", "nikto", "acunetix", "nessus", "openvas", "netsparker",
    "burpsuite", "burp%s+suite", "burp", "zaproxy", "owasp%s*zap", "zap/",
    "%f[%w]zap%f[^%w]", "zap%s+2%.",
    "appscan", "webinspect", "qualys", "nmap%s+scripting", "masscan",
    "zgrab", "nuclei", "wpscan", "havij", "arachni", "w3af",
    "grabber", "zgrab", "vega", "skipfish", "wapiti", "paros",
    -- 目录/参数爆破
    "dirbuster", "dirb", "gobuster", "wfuzz", "ffuf", "feroxbuster",
    "dirsearch", "dirsearch", "wfuzz", "medusa", "patator", "brutus",
    -- 爬虫 / 采集 / 转换
    "whatweb", "httrack", "scrapy", "libwww%-perl", "wget%s*/",
    "archiver", "webcopier", "site%sdigger",
    -- HTTP 客户端库指纹（脚本化流量）
    "ospython-requests%s*/", "python%-requests", "go%-http%-client",
    "java/", "okhttp", "axios/", "node%-fetch", "guzzlehttp",
    -- 已知漏洞扫描器
    "log4j%s*scan", "jndi%s*lookup", "ysoserial", "marshalsec",
    "log4shell", "pwntest", "s2tomcat",
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

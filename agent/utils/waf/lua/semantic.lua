-- 语义检测引擎：SQL 注入 / XSS / RCE / LFI / SSRF
-- 思路参考 libinjection：token 化 + 语法结构特征，而非单纯关键字匹配
local normalize = require("waf.normalize")
local _M = {}

-- ============ SQL 注入 ============
-- SQL 语法结构指纹：识别「输入能构成合法 SQL 片段」而非命中关键字
local SQL_LOGIC_OPS = {["or"]=true, ["and"]=true, ["xor"]=true}

local function looks_like_sql_tautology(s)
    -- ' OR '1'='1 / " OR 1=1 -- 等结构
    if s:find("1%s*=%s*1") or s:find("a%s*=%s*a") or s:find("1%s*=%s*'1'") then
        if s:find("%f[%w]or%f[^%w]") or s:find("%f[%w]and%f[^%w]") or s:find("==") or s:find("--") or s:find(";'") then
            return true
        end
    end
    -- 存在引号闭合 + or + 注释 的组合
    if s:match("['\"]%s*or%s*['\"]") or s:match("['\"]%s*or%s+1") then
        if s:find("--") or s:find("#") or s:find(";%s*$") then
            return true
        end
    end
    return false
end

local function looks_like_sql_union(s)
    -- UNION [ALL] SELECT 结构（Lua pattern 不支持 ? 与 |，逐条写）
    if s:find("%f[%w]union%f[^%w]%s*all%s+%f[%w]select%f[^%w]") then return true end
    return s:find("%f[%w]union%f[^%w]%s*%f[%w]select%f[^%w]") ~= nil
end

local function looks_like_sql_injection_expr(s)
    -- SELECT <列表> FROM：列表需含 *、逗号、数字或函数调用，避免误杀自然语言（"select your seats from the map"）
    local list = s:match("%f[%w]select%s+(.-)%s+%f[%w]from%f[^%w]")
    if list and (list:find("%*") or list:find(",") or list:find("%d") or list:find("%f[%w]count%s*%(")) then return true end
    if s:find("%f[%w]insert%f[^%w]") and s:find("%f[%w]into%f[^%w]") then return true end
    if s:find("%f[%w]update%f[^%w]") and s:find("%f[%w]set%f[^%w]") then return true end
    if s:find("%f[%w]delete%f[^%w]") and s:find("%f[%w]from%f[^%w]") then return true end
    if s:find("%f[%w]drop%s+table%f[^%w]") or s:find("%f[%w]drop%s+database%f[^%w]") or s:find("%f[%w]drop%s+schema%f[^%w]") then return true end
    if s:find("%f[%w]sleep%s*%(") or s:find("%f[%w]benchmark%s*%(") or s:find("%f[%w]load_file%s*%(") then return true end
    if s:find("%f[%w]information_schema%f[^%w]") or s:find("%f[%w]pg_sleep%s*%(") then return true end
    return false
end

function _M.detect_sqli(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    if #s < 4 then return false end
    return looks_like_sql_tautology(s) or looks_like_sql_union(s) or looks_like_sql_injection_expr(s)
end

-- ============ XSS ============
local XSS_EVENT_ATTRS = {"onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur", "onmouseenter", "onanimationstart", "ontoggle", "onpointerdown", "onstart"}

function _M.detect_xss(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    -- 标签注入 <script / <img on...= / <svg onload / <iframe src=javascript:
    if s:find("<%s*script") or s:find("<%s*iframe") or s:find("<%s*svg") or s:find("<%s*object") or s:find("<%s*embed") then
        return true
    end
    if s:find("<%f[%w]%s*img[^>]+onerror") or s:find("<%f[%w]%s*body[^>]+onload") then
        return true
    end
    for _, ev in ipairs(XSS_EVENT_ATTRS) do
        if s:find("<[^>]+%s" .. ev) or s:find(ev .. "%s*=") and s:find("<") then
            return true
        end
    end
    -- javascript: 协议（要求危险上下文：引号/=/括号后或串首，避免误杀 "learn javascript: basics"）
    local jspos = s:find("javascript%s*:")
    if jspos then
        local before = jspos > 1 and s:sub(jspos - 1, jspos - 1) or ""
        if jspos == 1 or before:find("[\"'=(>]") or (before:find("[^%w]") and not before:find("%s")) then
            return true
        end
    end
    if s:find("vbscript%s*:") then return true end
    if s:find("data%s*:%s*text/html") then return true end
    -- document.cookie / eval( / expression(
    if s:find("document%s*%.%s*cookie") or s:find("%f[%w]eval%s*%(") or s:find("expression%s*%(") then
        return true
    end
    return false
end

-- ============ RCE ============
-- Lua pattern 不支持 | 交替，逐条列出
local RCE_CMDS = {"cat%s+/etc/passwd", "cat%s+/etc/shadow", "wget%s+http", "curl%s+http", "nc%s+%-e", "bash%s+%-i", "chmod%s+777", "whoami", "uname%s+%-a", "/bin/bash", "/bin/sh", "powershell", "cmd%.exe"}

local function shell_meta_present(s)
    -- 命令注入通常需要 ; | ` $() && 包装
    return s:find(";") or s:find("|") or s:find("`") or s:find("%$%b()") or s:find("%$%(") or s:find("&&")
end

function _M.detect_rce(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    if not shell_meta_present(s) and not s:find("%$%{") then return false end
    for _, pat in ipairs(RCE_CMDS) do
        if s:find(pat) then return true end
    end
    -- 反引号或 $() 中带命令词（Lua pattern 不支持 |，词表循环）
    if s:find("`[^`]+`") or s:find("%$%([^)]*%)") then
        for _, w in ipairs({"cat", "ls", "id", "pwd", "wget", "curl", "rm", "nc", "bash", "sh"}) do
            if s:find("%f[%w]" .. w .. "%f[^%w]") then
                return true
            end
        end
    end
    return false
end

-- ============ LFI / 路径穿越 ============
local function looks_like_lfi(s)
    -- Windows 反斜杠归一为 / 后统一检测
    s = s:gsub("\\", "/")
    local p = normalize.normalize_path(s)
    if p:find("%.%./") or p:find("/%.%.") then return true end
    if p:find("/etc/passwd") or p:find("/etc/shadow") or p:find("/etc/hosts") or p:find("/proc/self") or p:find("/root/%.ssh") then return true end
    if p:find("/windows/system32") or p:find("/winnt/system32") then return true end
    return false
end

function _M.detect_lfi(value, uri)
    local targets = {value, uri and normalize.normalize_path(uri) or ""}
    for _, raw in ipairs(targets) do
        if raw ~= "" then
            local decoded = normalize.normalize(raw)
            -- 协议类特征先于路径折叠检测（php:// 的 // 会被路径归一化折叠）
            if decoded:find("php://filter") or decoded:find("php://input") or decoded:find("file://") then return true end
            -- 空字节 / 控制字符截断（在去除 %z 前检查）
            if decoded:find("[%z\1-\8\14-\31]") or raw:find("[%z\1-\8\14-\31]") then return true end
            local s = decoded:gsub("%z", "")
            if looks_like_lfi(s) or looks_like_lfi(raw) then return true end
        end
    end
    return false
end

-- ============ SSRF ============
local SSRF_HOSTS = {"169%.254%.169%.254", "metadata%.google%.internal", "100%.100%.100%.200", "127%.0%.0%.1", "localhost", "0%.0%.0%.0", "%[::1%]", "169%.254%.169%.254:latest"}

function _M.detect_ssrf(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    if not (s:find("^http") or s:find("^gopher") or s:find("^dict") or s:find("^file") or s:find("^ftp")) then return false end
    for _, h in ipairs(SSRF_HOSTS) do
        if s:find(h) then return true end
    end
    -- 内网网段
    local ip = s:match("^https?://([%d%.]+)")
    if ip then
        local a, b = ip:match("^(%d+)%.(%d+)")
        a = tonumber(a)
        if a == 10 or a == 127 or a == 0 or (a == 192 and b == "168") or (a == 172 and tonumber(b) and tonumber(b) >= 16 and tonumber(b) <= 31) then
            return true
        end
    end
    return false
end

-- 对单个「参数值或 URI」跑全套检测，返回 {type=..., value=...} 或 nil
function _M.inspect(value, uri)
    local checks = {
        {"sqli", _M.detect_sqli},
        {"xss", _M.detect_xss},
        {"rce", _M.detect_rce},
        {"lfi", function(v) return _M.detect_lfi(v, uri) end},
        {"ssrf", _M.detect_ssrf},
    }
    for _, c in ipairs(checks) do
        local ok, hit = pcall(c[2], value)
        if ok and hit then
            return {type = c[1], value = value}
        end
    end
    return nil
end

_M.attack_types = {"sqli", "xss", "rce", "lfi", "ssrf", "upload"}

return _M

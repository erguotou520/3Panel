-- 语义检测引擎：SQL 注入 / XSS / RCE / LFI / SSRF
-- 思路参考 libinjection：token 化 + 语法结构特征，而非单纯关键字匹配
local normalize = require("waf.normalize")
local _M = {}

-- ============ SQL 注入 ============
-- SQL 语法结构指纹：识别「输入能构成合法 SQL 片段」而非命中关键字
local SQL_LOGIC_OPS = {["or"]=true, ["and"]=true, ["xor"]=true}

-- SQL 注释剥离：/**/、/*!50000*/、-- 与 # 是最常见的绕过手段。
-- 剥离后 SQL 关键字重新贴合，前沿断言 %f[%w] 才能成立。
-- MySQL 版本注释 /*!50000union*/ 本身是攻击证据，由调用方在剥离前单独判定。
local function strip_sql_comments(s)
    -- 注意 Lua pattern 没有正则的惰性分组：/ %* . - %* / 中 . - 是"惰性重复任意字符"，
    -- 对 /**/ 会匹配空串再吃掉 **/，对 /*!50000select*/ 则吃到第一个 */。
    s = s:gsub("/%*.-%*/", " ")   -- /**/ 与 /*!50000xxx*/
    s = s:gsub("%-%-[^\n]*", " ")   -- 行注释 --
    s = s:gsub("#.*$", "")         -- MySQL 行注释 #
    return s
end

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
    -- 引号紧贴逻辑运算符与引号等式：N'And 'N'='N / desc'AND '1'='1
    -- 攻击者常省略空格，%s+ 版本覆盖不到，这里允许 %s* 并区分单词边界
    if s:find("['\"]%s*and%s+['\"]?%w+['\"]?%s*=%s*['\"]?%w+") then return true end
    if s:find("['\"]%s*or%s+['\"]?%w+['\"]?%s*=%s*['\"]?%w+") then return true end
    -- 裸布尔盲注探针：1 AND 1=2 / 2 or 3=4
    if s:match("^%s*%d+%s+and%s+%d+%s*=%s*%d+%s*$") or s:match("^%s*%d+%s+or%s+%d+%s*=%s*%d+%s*$") then return true end
    -- 引号内同构数字等式：'1'='2' / 'a'='a'
    if s:find("['\"%d]%s*=%s*['\"]?%w+['\"]?%s*and%s+") then return true end
    -- Oracle 字符串拼接比较：createTime'||1/0||'，用 1/0 强制报错做布尔盲注
    if s:find("['\"]%s*|%|%s*%d+%s*/%s*%d+%s*|%|%s*['\"]") then return true end
    if s:find("['\"]%s*|%|%s*[%w%s]-%s*/%s*%d+%s*|%|") then return true end
    -- 空引号配对：""or""="" / ''or''=''，双引号闭合后紧跟 or/and
    if s:find('""%s+or%s+""%s*=') or s:find("''%s+or%s+''%s*=") then return true end
    -- 布尔探针包在引号内：2147483647 or 1=2
    if s:find("^%s*%-?%d+%s+or%s+%d+%s*=%s*%d+") or s:find("^%s*%-?%d+%s+and%s+%d+%s*=%s*%d+") then return true end
    -- 算术化盲注：-7140 OR 1418*1418=1418 —— 等式一侧是乘积而非字面数字。
    -- 覆盖 /%s* 与引号前缀的变体：-1" OR 1337*1337=1337 -- 、N' OR N*N=N
    if s:find("or%s+%d+%s*%*%s*%d+%s*=%s*%d+") or s:find("and%s+%d+%s*%*%s*%d+%s*=%s*%d+") then return true end
    if s:find("or%s+%d+%s*%+%s*%d+%s*=%s*%d+") or s:find("and%s+%d+%s*%+%s*%d+%s*=%s*%d+") then return true end
    if s:find("or%s+%d+%s*%-%s*%d+%s*=%s*%d+") or s:find("and%s+%d+%s*%-%s*%d+%s*=%s*%d+") then return true end
    -- 被参数名或引号包裹的算术盲注：cls_mode_login expr 111+111 前的 expr 变体
    if s:find("%f[%w]expr%s+%d+%s*[%+%-*]%s*%d+") then return true end
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
    if s:find("%f[%w]union%f[^%w]%s*%f[%w]select%f[^%w]") then return true end
    -- 括号包裹形态：)union(select(...),null)  —— 前面是 -1) 而非空白/注释，前沿不成立
    if s:find("union%s*%(%s*select") or s:find("union%s+all%s*%(%s*select") then return true end
    if s:find("union%s*%(%s*%(") or s:find("union%s+all%s*%(%s*%(") then return true end
    return false
end

local function looks_like_sql_injection_expr(s)
    -- SELECT <列表> FROM：列表需含 *、逗号、数字或函数调用，避免误杀自然语言（"select your seats from the map"）
    --
    -- 但仅有结构仍不足以定性：`select * from users where id=1` 是最普通的
    -- 查询语句（日志、导出接口、前端调试都会带上），因为列表含 * 就被判注入，
    -- 站点日志里全是这种误伤。追加要求：必须同时存在注入证据 ——
    -- 引号、注释符，或 where 里出现恒真式（1=1 / 'a'='a'）。
    local list = s:match("%f[%w]select%s+(.-)%s+%f[%w]from%f[^%w]")
    if list and (list:find("%*") or list:find(",") or list:find("%d") or list:find("%f[%w]count%s*%(")) then
        local has_injection_evidence =
            s:find("['\"]") -- 字符串常量
            or s:find("%-%-") -- 行注释
            or s:find("/%*") -- 块注释
            or s:find("#") -- MySQL 行注释
            or s:find("%d%s*=%s*%d") -- where id=1
            or s:find("['\"]%s*=%s*['\"]") -- where 'a'='b'
        if has_injection_evidence then return true end
    end
    -- 括包子查询：(SELECT md5(2014346458)) / (select user from users)
    if s:find("%(%s*select%s") and (s:find("md5%s*%(") or s:find("%f[%w]from%f[^%w]") or s:find(",") or s:find("%d")) then return true end
    -- select 后紧跟括号：select(N)、union(select(...))
    if s:find("%f[%w]select%s*%(%s*%a+") then return true end
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
    -- concat(9876*9876,0x3a,9876*9876)：算术结果拼接，JimuReport getTotalData 注入
    if s:find("concat%s*%(%s*%d+%s*%*%s*%d+") then return true end
    -- GROUP BY ... HAVING 报错注入：GROUP BY CONCAT(0x7e,md5(N),0x7e,FLOOR(RAND(0)*2)) HAVING
    if s:find("group%s+by%s+concat") or (s:find("group%s+by") and s:find("having%s+min")) then return true end
    if s:find("floor%s*%(%s*rand") then return true end
    -- Oracle decode(length(N),a,b,c) 函数式盲注
    if s:find("decode%s*%(%s*length%s*%(") then return true end
    -- H2 CREATE ALIAS sleepN FOR "java.lang.Thread.sleep"; CALL sleepN(0)
    if s:find("create%s+alias") and s:find("java%.lang%.thread%.sleep") then return true end
    if s:find("create%s+alias%s+sleep%w*%s+for") then return true end
    if s:find("call%s+sleep%w*%s*%(") then return true end
    -- INTO OUTFILE 写文件：');select ... into outfile 'C:\\Program Files...'
    if s:find("into%s+outfile") or s:find("into%s+dumpfile") or s:find("into%s+outdir") then return true end
    -- 序列化容器里嵌 SQL：<hash>aads|a:2:{s:3:\"num\";s:107:\"*/SELECT ...
    if s:find("|a:%d+:{s:%d+:") and s:find("select", 1, true) then return true end
    if s:find("|a:%d+:{") and (s:find("0x2d3127") or s:find("union", 1, true)) then return true end
    -- Oracle DBMS_PIPE 时间盲注
    if s:find("dbms_pipe%.receive_message") then return true end
    -- CHAR()/CHR() 拼接 + IN/SELECT：' AND 5094 IN (SELECT (CHAR(113)...)
    if s:find("char%s*%(%d+%)") and (s:find("%f[%w]in%s*%(%s*select") or s:find("%f[%w]concat%s*%(")) then return true end
    -- IF(...)=... SELECT ... ELSE DROP / CAST('~'||(SELECT (CASE WHEN
    if s:find("cast%s*%(%s*['\"]~['\"]") or (s:find("%f[%w]case%s+when%f[^%w]") and s:find("%f[%w]select%f[^%w]")) then return true end
    -- cast(md5(N)as int) 强制类型转换报错注入；剥离 /**/ 后 as 前后都有空格
    if s:find("cast%s*%(%s*%a+%s*%(%s*%d+") or s:find("cast%s*%(%s*md5%s*%(") then return true end
    if s:find("md5%s*%(%s*%d+%s*%)%s*as%s+%a+") then return true end
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
    if looks_like_sql_tautology(s) or looks_like_sql_union(s) or looks_like_sql_injection_expr(s) then
        return true
    end
    -- 注释绕过（/**/ 拼接、MySQL 版本注释）：先在原串上判，再对剥离注释后的串重跑。
    -- 剥离后关键字重新贴合，%f[%w] 前沿才成立，否则 9/**/and 6955=6955 这类全部漏检。
    --
    -- 门槛只要求串里出现过任一注释符，位置不限。原实现要求 find 命中后才继续，
    -- 而 admin'-- / ') OR ('1'='1 的注释符就在探测串自身里，首段规则本已能判中，
    -- 却在进下一段前被这道门槛挡回去 —— 拦的是探测串，不是"带注释的上下文"。
    if s:find("/%*") or s:find("%-%-") or s:find("#") then
        local stripped = strip_sql_comments(s)
        if looks_like_sql_tautology(stripped)
            or looks_like_sql_union(stripped)
            or looks_like_sql_injection_expr(stripped) then
            return true
        end
    end
    -- 无注释符时也要覆盖「引号闭合 + or/and + 等式」这类自闭合恒真式：
    -- ') OR ('1'='1 不含 -- 也不含 #，靠首段的 %s*or%s+ 引号等式规则判定。
    if s:find("['\"]%s*or%s+['\"]?%w+['\"]?%s*=%s*['\"]?%w+")
        or s:find("['\"]%s*and%s+['\"]?%w+['\"]?%s*=%s*['\"]?%w+") then
        return true
    end
    -- 带引号的数字等式：') OR ('1'='1 里的比较双方是 '1' 与 '1'，
    -- 上面的模式要求 or 紧跟引号，这里 or 与引号之间还夹着 '('，匹配不到。
    -- 要求等式两侧都是"单引号+数字+单引号"或"单引号+字母+单引号"，
    -- 加上 and/or 同时出现才判，避免 "value='a'='b'" 这类正常赋值被误杀。
    if (s:find("%f[%w]or%f[^%w]") or s:find("%f[%w]and%f[^%w]")) then
        if s:find("['\"]%w['\"]%s*=%s*['\"]%w['\"]")
            or s:find("['\"]%d['\"]%s*=%s*['\"]%d['\"]")
            or s:find("%d%s*=%s*%d") then
            return true
        end
    end
    -- 标识符 + 引号闭合 + 行注释：admin'-- / user'-- / name'#
    -- 这是登录/搜索框最常见的探测形态：拿一个已知列名去试引号能否闭合。
    -- 要求引号紧贴 -- 或 #（中间无空白），避免 "it's -- fine" 这类正常文本命中。
    if s:find("%a['\"]%s*%-%-") or s:find("%a['\"]%s*#") then
        return true
    end
    -- 带引号的等式：') OR ('1'='1 里比较双方是 '1' 与 '1'，
    -- 上一条要求 or 紧跟引号，这里 or 与引号之间夹着 '('，匹配不到。
    -- 注意 Lua 的 %w 只匹配字母，数字必须用 %d 单独写一条 ——
    -- 写成 %w 会让 '1'='1 整条落空（实测踩过）。
    if s:find("%f[%w]or%f[^%w]") or s:find("%f[%w]and%f[^%w]") then
        -- 左半：'1' / 'a' 与 = 之间允许空白；右半单独从左半结束处往后找。
        -- 合成一个模式（['\"]%d['\"]%s*=%s*['\"]%d['\"]）是匹配不到的 ——
        -- 它要求两段紧邻，而 ') OR ('1'='1 的右半已经吃到字符串结尾，
        -- Lua 的 %d['\"] 需要引号后还有一个字符。拆成两步才成立（实测）。
        -- ) OR ('1'='1 的结构是 引号 1 引号 = 引号 1（末尾无闭合引号），
        -- 所以右半不能用 ["']%d["'] 去匹配 —— 它要求引号后还有字符，必然落空。
        -- 改为：or/and 存在，且串里出现两次「引号+字母或数字」（即两次引号包裹的值），
        -- 再叠加 %d%s*=%s*%d 这类等号关系即可。
        local q = 0
        local pos = 1
        while true do
            local p1 = s:find("['\"]%w", pos)
            if not p1 then break end
            q = q + 1
            pos = p1 + 1
        end
        if q >= 2 and (s:find("=%s*['\"]") or s:find("['\"]%s*=")) then
            return true
        end
        if s:find("%d%s*=%s*%d") then
            return true
        end
    end
    -- 标识符 + 引号闭合 + 行注释：admin'-- / user'-- / name'#
    -- 登录/搜索框最常见的探测形态。要求引号紧贴 -- 或 #（中间无空白），
    -- 避免 "it's -- fine" 这类正常文本命中。
    if s:find("%a['\"]%s*%-%-") or s:find("%a['\"]%s*#") then
        return true
    end
    -- ORDER BY 枚举：1' ORDER BY 10-- 末尾注释已由上面覆盖，
    -- 无注释形态（?id=1 ORDER BY 10）靠「引号/数字 + ORDER BY + 数字」识别，
    -- 数字超过 1 即为列枚举探针。
    if s:find("order%s+by%s+%d+") and #s:match("order%s+by%s+(%d+)") >= 1
        and tonumber(s:match("order%s+by%s+(%d+)")) >= 2 then
        return true
    end
    return false
end

-- ============ XSS ============
local XSS_EVENT_ATTRS = {"onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur", "onmouseenter", "onanimationstart", "ontoggle", "onpointerdown", "onstart"}

-- 事件属性里可直接执行的浏览器函数。用于识别 onerror=alert(1) 这类裸赋值 ——
-- 只收浏览器确实存在且能产生副作用的函数，避免把 onchange=format(x) 之类的
-- 正常模板表达式误判成攻击。
local XSS_CALLABLE_FNS = {
    "alert", "eval", "prompt", "confirm", "print", "fetch", "xmlhttprequest",
    "write", "writeln", "execscript", "settimeout", "setinterval",
}

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
        -- 事件属性直接绑定函数调用：onerror=alert(1) / onload=eval(x) / onclick=f(1)。
        -- 上一条要求引号或 javascript: 才命中，于是最常见的裸赋值写法
        -- （探针常把标签剥掉只留属性名）反而从缺口漏过去。
        -- 用函数名白名单而不是任意括号：alert/eval/prompt 之外的 "onx=f(y)" 可能是
        -- 正常模板拼接，全量匹配误伤面太大。
        if s:find(ev .. "%s*=%s*%(?s*[%a_]*%s*%(?") then
            for _, fn in ipairs(XSS_CALLABLE_FNS) do
                if s:find("%f[%w]" .. fn .. "%s*%(") then
                    return true
                end
            end
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
    if s:find("alert%s*%(%s*document%.domain%s*%)") then return true end
    if (s:find("['\"]%s*%-?%s*prompt%s*%(") or s:find(";%s*alert%s*%(")) then return true end
    return false
end

-- ============ RCE ============
-- Lua pattern 不支持 | 交替，逐条列出
local RCE_CMDS = {"cat%s+/etc/passwd", "cat%s+/etc/shadow", "wget%s+http", "curl%s+http", "nc%s+%-e", "bash%s+%-i", "chmod%s+777", "whoami", "uname%s+%-a", "/bin/bash", "/bin/sh", "powershell", "cmd%.exe"}

-- 命令名白名单：只要 shell 元字符（; | && ` $()）后面跟着这些命令之一即判定注入。
--
-- 为什么要这张表：原先只靠 RCE_CMDS 里的紧凑模式，`;id` 能命中 `/bin/id` 之外的
-- 字面量，但 `; ls -la`（分号后有空格 + 带参数的 ls）、`; sleep 5` 这类"命令名 + 参数"
-- 变体全部漏网 —— 攻击者只要在分隔符后加一个空格就绕过了。
-- 这里不匹配参数，只看命令名本身，配合 shell_meta_present 已有的 gate 使用。
local RCE_CMD_NAMES = {
    "id", "whoami", "uname", "ls", "dir", "cat", "tail", "head", "pwd", "cd",
    "sleep", "ping", "curl", "wget", "nc", "ncat", "netcat", "python", "python3",
    "perl", "ruby", "php", "bash", "sh", "zsh", "ksh", "ash", "dash",
    "chmod", "chown", "rm", "mv", "cp", "touch", "mkdir", "find", "grep",
    "awk", "sed", "cut", "tr", "ps", "top", "kill", "killall", "ifconfig",
    "ipconfig", "netstat", "ss", "ifconfig", "hostname", "uname", "env",
    "printenv", "set", "export", "base64", "xxd", "openssl", "gdb", "strace",
    "systemctl", "service", "crontab", "at", "nohup", "setsid", "screen", "tmux",
    "who", "last", "history", "alias", "type", "hash", "umask", "id", "sudo", "su",
}

local function shell_meta_present(s)
    -- 命令注入通常需要 ; | ` $() && 包装
    return s:find(";") or s:find("|") or s:find("`") or s:find("%$%b()") or s:find("%$%(") or s:find("&&")
end

-- 元字符之后是否紧跟命令名。分隔符与命令名之间允许任意空白（含 ${IFS} 归一后的空格），
-- 也允许 & —— `;& id`、`&& whoami` 都是等价写法。
--
-- 字符类写法说明：`$` `%` `(` `)` 在 Lua 模式里必须转义（用 %$ %% %( %)）。
-- 换行/回车不放进字符类：normalize 已把它们折成空格，由后面的 %s* 统一覆盖。
-- 把模式提为常量，避免在 C 风格字符串里反复处理转义（踩过 % 被二次解析的坑）。
local META_CLASS = "[;|&`%$%(]%s*"

local function meta_then_cmd(s)
    -- %f[^%w] 后置边界避免把 "idx" 里的 "id"、"wait" 里的 "ai" 当命令名。
    for _, name in ipairs(RCE_CMD_NAMES) do
        if s:find(META_CLASS .. name .. "%f[^%w]") then
            return true
        end
    end
    return false
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
    -- 参数名在前的 expr 变体：cls_mode_login expr 927+927 / Published expr 1+1
    if s:find("%f[%a]expr%s+%d+%s*[%+%-*]%s*%d+") or s:find("%f[%a]expr%s+%d+%s+%d+") then return true end
    if s:find("%$%(expr") or s:find("`expr") then return true end
    -- echo md5(N);  —— 命令执行后的回显校验
    if s:find("echo%s+md5%s*%(%s*%d+") then return true end
    if s:find("%f[%w]touch%s+/") or s:find("%f[%w]sh%s+%-c%s+") or s:find("%f[%w]cmd%s+/c%s+") then return true end
    if s:find("xp_cmdshell", 1, true) or s:find("type%s+c:[/\\]windows[/\\]win%.ini") then return true end
    if s:find("ping%s+%d+%.%d+%.%d+%.%d+%s*|") then return true end
    if s:find("%f[%w]ping%s+%-c%s+%d+") or (s:find("%f[%w]ping%s+") and s:find("dnslog", 1, true)) then return true end
    if s:find("^%s*curl%s+https*://") or s:find("^%s*wget%s+https*://") then return true end
    -- 交互式 shell 反连：`bash -i >& /dev/tcp/1.2.3.4/4444`。
    -- 不能只靠 RCE_CMDS 里的 "bash%s+%-i"：那条规则在 shell_meta_present
    -- 的 gate 之后，而反连串常常整体作为参数值传入（前面没有 ; | &&），
    -- 于是恰好是最典型的反弹 shell 写法反而从 gate 漏了过去。
    if s:find("/dev/tcp/", 1, true) then return true end
    if (s:find("%f[%w]bash%s+%-i") or s:find("%f[%w]sh%s+%-i")) and s:find("%s*[%d%.]") then return true end
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
    -- /bin/sleep、Shellshock 变形：() { _; } >_[$($())] { echo; /bin/sleep 5; }
    if s:find("/bin/sleep") or s:find("/bin/date") then return true end
    if s:find("%(%s*%)%s*{[^}]*;[^}]*}%s*{") then return true end
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
    -- 分隔符 + 命令名（允许分隔符与命令名之间有空格）：覆盖 `; ls -la`、
    -- `; sleep 5`、`&& id`、`| whoami` 等"命令名 + 参数"变体。
    if meta_then_cmd(s) then return true end
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
-- JNDI 混淆展开：把内层表达式求值成最终字符串，再查 jndi:
--
-- 覆盖三类变形（Log4Shell 绕过的手写变体，不需要求值器也能判定）：
--   ${ivd::-m}            → m          默认值语法
--   ${${lower:j}ndi:...}  → ${jndi:...}  Lookahead 递归取首字母
--   ${${::-j}ndi:...}     → ${jndi:...}  同样是首字母提取
--
-- 第二类只需剥掉 ${...} 外壳、把字面量取出来即可：${lower:j} 里的 lower 是格式化
-- 关键字，参数 j 就是要还原的字符。安全做法是"展开后必须出现 jndi:"才判定，
-- 不因为出现 ${ 就拦 —— 普通应用里 ${} 是合法的模板占位符。
local JNDI_LOOKAHEAD = {
    -- ${${lower:j}ndi:...} / ${${upper:j}ndi:...} / ${x:l} 之类的首字母提取
    "%${%${[^%}]*%b()%}?%s*([%a])%}?ndi%s*:",
    -- ${${::-j}ndi:...} 形式
    "%${%${%s*:%-([%a])%}?ndi%s*:",
    -- ${${env:J}ndi:...}（无括号的格式化关键字变体）
    "%${%${[^%}]*%s*([%a])%}?ndi%s*:",
}

local function expand_jndi_obfuscation(s)
    -- 默认值语法 ${x:-y} → y，迭代直到不动点
    for _ = 1, 6 do
        local expanded = s:gsub("%${([^{}]-):%-([^{}]-)}", function(_, default)
            return default
        end)
        if expanded == s then break end
        s = expanded
    end
    -- Lookahead 变形：把 ${...<char>}ndi: 折叠成 <char>ndi:，字符取自捕获组。
    -- 用函数作替换值（而非 "%1ndi:"），避免捕获内容里的 % 被当成替换指令。
    for _ = 1, 6 do
        local before = s
        for _, pat in ipairs(JNDI_LOOKAHEAD) do
            s = s:gsub(pat, function(ch) return ch .. "ndi:" end)
        end
        -- 折叠后再跑一轮默认值展开，处理 ${${x:-y}:-z} 这类双层嵌套
        s = s:gsub("%${([^{}]-):%-([^{}]-)}", function(_, default)
            return default
        end)
        if s == before then break end
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
    -- (SELECT md5(2014346458)) 校验型探测，select 的列表里只有函数调用
    if s:find("%(%s*select%s+md5%s*%(%s*%d+%s*%)%s*%)") then return true end
    -- sql= 'select md5(N)' 形态（Discuz! 风格）
    if s:find("sql%s*=%s*['\"]%s*select%s+md5") or s:find("['\"]%s*select%s+md5%s*%(%s*%d+") then return true end
    -- md5(N),password,salt：凭据字段外泄的联合查询
    if s:find("md5%s*%(%s*%d+%s*%)%s*,%s*password") or s:find("password%s*,%s*salt") then return true end
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
    -- 裸 Java 类名作为 gadget 探针：java.lang.Comparable / java.util.PriorityQueue
    -- 单独一个类名证据弱，但配合 gadget 链类名即为反序列化探测
    if s:match("^java%.lang%.comparable$") or s:match("^java%.lang%.%a+$")
        or s:match("^java%.util%.%a+$") then return true end
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
    -- PHP assert(base64_decode('...'))：ThinkPHP 一句话木的经典变体
    if s:find("assert%s*%(%s*base%d*_decode%s*%(") then return true end
    -- NodeJS 原型链逃逸：this.constructor.constructor('return process')().mainModule.require
    if s:find("this%.constructor%.constructor") and s:find("mainmodule") then return true end
    if s:find("constructor%s*%(%s*['\"]return%s+process") then return true end
    -- PowerShell webshell 下载执行：$a("http://1.2.3.4/wp.txt","moshou.php")
    if s:find("%$%a%s*%(%s*['\"]%a+://[^'\"]+['\"]%s*,") then return true end
    -- JSP EL 注入：test".system(id)."
    if s:match("['\"]%s*%.%s*%a+%s*%(%s*%a+") and s:find("['\"]%s*%.%s*['\"]") then return true end
    return false
end

-- 模板引擎属性链穿越：即使不带算术运算符，读取类/全局对象本身即可完成 RCE
-- 取信息（Jinja2 `__class__.__init__.__globals__`、Ruby `binding.local_variable_get`、
-- Java EL `T(java.lang.Runtime)`、FreeMarker `?new` / `Execute`）。
--
-- Twig 单独说明：它的沙箱逃逸不走 `__globals__` 那条路，而是通过模板自带的
-- `_self` 引用（对应模板上下文对象）一路点到运行环境。waf-detector 的
-- PrototypePollution/SSTI 类里 `{{_self.env.registerUndefinedFilterCallback("x")}}`
-- 这类探测此前 4 个变种全部漏网 —— 原因是它们既不含双下划线键、也不含算术运算符，
-- 前面每条规则都不命中，只能靠下面的 `_self` + 危险方法名兜住。
local SSTI_CHAINS = {
    -- Python / Jinja2 系
    "__class__", "__mro__", "__subclasses__", "__globals__", "__builtins__",
    "__init__", "__getattribute__", "__reduce__", "__reduce_ex__",
    "local_variable_get", "instance_variable_get", "global_variables",
    -- Java EL / SpEL
    "t(java.lang.runtime", "t(runtime", "class.forName", "runtime.getruntime",
    -- FreeMarker
    "?new", "?exec", "freemarker.templateutility",
}

-- Twig 的沙箱逃逸方法名。与 SSTI_CHAINS 分开是因为它需要和 "_self" 同时出现
-- 才算攻击：模板里单独写 {{ _self }} 是合法用法（取模板上下文），
-- 只有 "_self" 后面跟着这些会改写运行环境的方法时才是攻击探测。
local TWIG_ESCAPE_METHODS = {
    "registerundefinedfiltercallback", "getruntime", "settemplateengine",
    "getfiltersets", "addfilter", "getattribute", "setcache", "loadtemplate",
}

function _M.detect_twig_escape(s)
    if not s:find("_self", 1, true) then
        return false
    end
    for _, m in ipairs(TWIG_ESCAPE_METHODS) do
        if s:find(m, 1, true) then
            return true
        end
    end
    return false
end

function _M.detect_ssti(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    -- ---- Jinja2 / Twig / Python 系：{{ ... }} ----
    if s:find("{{[^}]-[%+%*%-/][^}]-}}") then return true end
    -- normalize 会把 + 归一为空白：{{数字 数字}} 也是算术探针
    if s:find("{{%s*%d+%s+[%d%.]+%s*}}") then return true end
    -- ---- ERB / JSP / Velocity / Thymeleaf：<% ... %> 与 <% ... %> ----
    -- 用 [^>]- 而不是 .+ ：. 会跨过 ">" 把两个不同 scriptlet 拼成一个匹配。
    -- 模式里的字面 % 写成 %%（%% 匹配一个字面 %，%s 才是空白类）。
    if s:find("<%%[^>]-%%>") or s:find("<%%[^>]-%%}") then return true end
    -- ---- Ruby ERB / Sinatra / JSP 输出表达式：<%= ... %> ----
    if s:find("<%%%s*=[^>]-%%>") then return true end
    -- ---- Ruby：#{expr} / #{{expr}}。要求 # 紧跟 { 或字母，避免命中 CSS 色值 #fff 与锚点 ----
    if s:find("#%s*{") and s:find("}") then return true end
    if s:find("#{%s*[%w@(]") and not s:find("#%s*[0-9a-f]%s*;") then return true end
    -- ---- Java EL / SpEL / JS 模板：${expr}。要求 $ 后紧跟 { 且内部不是纯数字 ----
    if s:find("%${%s*[%w_(]") then return true end
    -- ---- 模板引擎属性链 / 静态方法调用 ----
    for _, chain in ipairs(SSTI_CHAINS) do
        if s:find(chain, 1, true) then return true end
    end
    -- ---- Twig 沙箱逃逸：_self + 危险方法名（两者同时出现才算攻击）----
    if _M.detect_twig_escape(s) then return true end
    return false
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
    -- log4shell 之外的 Java 反序列化 gadget：TemplatesImpl / JNDI 工厂 / logback JDBC
    for _, gadget in ipairs({
        "com.sun.org.apache.xalan.internal.xsltc.trax.templatesimpl",
        "com.newrelic.agent.deps.ch.qos.logback.core.db.drivermanager",
        "org.apache.tomcat.util.net.jsynapsefactory",
        "com.mchange.v2.c3p0.impl.pocimpl.serializer",
    }) do
        if s:find(gadget, 1, true) then return true end
    end
    if s:find("hexasciiserializedmap", 1, true) or s:find("hashasciiserializedmap", 1, true) then return true end
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
    -- ASPX/JSP 木马（Behinder /  Godzilla / 冰蝎 命名习惯）
    "/(jsp|aspx|ashx|jspx)%.[a]sp?x?$", "/(shell|webshell|cmd|upfile)%.[a]sp?x?$",
    "/(jsp|aspx)%s*%.%s*jspx?$",
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
    -- ASPX/JSP 木马与探针文件
    for _, stem in ipairs({"shell", "webshell", "cmd", "upfile", "jspspy", "phpspy", "godzilla", "behinder", "c99shell", "c99", "r57", "antSword", "wso"}) do
        if s:find("/" .. stem .. "[%w_%-]*%.jsp") or s:find("/" .. stem .. "[%w_%-]*%.aspx")
            or s:find("/" .. stem .. "[%w_%-]*%.ashx") or s:find("/" .. stem .. "[%w_%-]*%.jspx") then
            return true
        end
    end
    if s:find("/%x%x%.asp") or s:find("/%x%x%.jsp") or s:find("/%x%x%.aspx") then return true end
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
    -- 新增三类检测的候选词同样要在这里放行，否则会在快速筛被提前 return nil：
    --   · 原型污染：__proto__ / constructor（含 query 与 JSON 两种形态）
    --   · GraphQL："query" / "mutation" 键，或 {__schema 直接出现
    --   · 敏感路径：/.env / /.git/ / /wp-config.php 这类高危文件
    -- 这些串本身不含任何 SQL/XSS/命令元字符，是各自类别唯一的证据来源。
    if lower:find("__proto__", 1, true) or lower:find("constructor", 1, true)
        or lower:find("__schema", 1, true) or lower:find("__type", 1, true)
        or lower:find("%\"query\"", 1, true) or lower:find("'query'", 1, true)
        or lower:find("%\"mutation\"", 1, true) or lower:find("'mutation'", 1, true)
        or lower:find("/.env", 1, true) or lower:find("/.git", 1, true)
        or lower:find("/.svn", 1, true) or lower:find("/.aws", 1, true)
        or lower:find("/.ssh", 1, true) or lower:find("wp-config", 1, true)
        or lower:find("phpinfo", 1, true) or lower:find("phpmyadmin", 1, true)
        or lower:find("actuator", 1, true) or lower:find("server-status", 1, true)
        -- 备份/编辑器残留后缀：只有这些后缀、没有任何攻击特征时，
        -- 上面的候选词一个都命中不了，会被这里提前 return nil 漏掉。
        or lower:find("%.bak", 1, true) or lower:find("%.old", 1, true)
        or lower:find("%.orig", 1, true) or lower:find("%.swp", 1, true)
        or lower:find("%.swo", 1, true) or lower:find("%.save", 1, true)
        or lower:find("%f[%w]id_rsa") or lower:find("%f[%w]credentials") then
        return true
    end
    -- 可执行扩展名必须在这里放行：?file=shell.php / /uploads/x.jsp 这类请求
    -- 不含任何 SQL/XSS/命令元字符，原本会被下面的快速筛直接 return nil，
    -- 根本到不了 detect_dangerous_ext。用 %a%d%_%-%s 组成的模式匹配
    -- ".php" ".jsp" ".pHp"（lower 之后）等 18 种危险扩展名。
    if ngx and ngx.re and ngx.re.find then
        if ngx.re.find(lower, [[\.(?:php\d*|phtml|phar|jspx?|asp[x]?|cgi|pl|py|sh|bash|exe|dll|so)(?:$|[^a-z0-9])]]) then
            return true
        end
    elseif lower:find("%.php", 1, true) or lower:find("%.jsp", 1, true)
        or lower:find("%.asp", 1, true) or lower:find("%.phtml", 1, true)
        or lower:find("%.phar", 1, true) or lower:find("%.py", 1, true)
        or lower:find("%.pl", 1, true) or lower:find("%.sh", 1, true)
        or lower:find("%.cgi", 1, true) or lower:find("%.exe", 1, true) then
        return true
    end
    if ngx and ngx.re and ngx.re.find then
        local from = ngx.re.find(lower, [[[%<'"`;|$\\{}]|\.\.|://|\b(?:union|select|insert|update|delete|drop|sleep|waitfor|gtid_subset|hashbytes|concat|javascript|jndi|phpinfo|printf|print_r|var_dump|md5|processbuilder|ognlcontext|groovyshell|file_put_contents|base64_decode|expr|echo|touch|ping|xp_cmdshell|alert|prompt|eval|onmouseover)\b|@@|(?:javax\.naming|sun\.awt\.datatransfer|jdk\.nashorn|org\.apache\.commons\.beanutils)|/(?:etc|proc|usr/bin)/|/actuator/(?:env|heapdump|gateway/routes)|/phpmyadmin|/druid/(?:login\.html|websession\.html)|/apisix/admin/routes|/\.git/(?:config|head)|/\.env|/server-status|/swagger-ui|/web\.config|/web-inf/web\.xml|/jmx-console|/manager/html|/\.ds_store|/meta-inf/maven/|/bsh\.servlet\.bshservlet|/phpunit/phpunit/src/util/php/eval-stdin\.php|/(?:shell[\w-]*|webshell[\w-]*|phpspy|c99|r57)\.php|/[^/?]+\.sql$|/(?:backup|db|database|root|site|test|web|webapps|website|www|wwwroot)\.(?:zip|rar)$|/(?:config|db)\.php\.bak$|/[^/?]+\.config\.bak$|/wls-wsat/|/mgmt/tm/util/bash|/jmreport/testconnection|device\.rsp|s=captcha|/actuator;/|/center/api/session(?:[/?]|$)|/excu_shell|invokefunction|__construct|__destruct|call_user_func|memberaccess|classloader|updatexml|extractvalue|os\.execute|print\s*\(|system\s*\(|passthru|shell_exec|initialcontext|defineclass|%3c|%3e|%27|%24\{|\{\{|\band\s+\d+\s*[=<>]|\bor\s+\d+\s*=|__class__|__mro__|[?&]cmd=|dbms_pipe|char\(\d|/%*!|case\s+when|cast\(|sh\s+-c\s+\S|nc\s+-e|md5sum|nslookup|oast|interactsh|dnslog|windows/win\.ini|program files|documents and settings|appdata|sys_user|java\.lang\.[a-z]+|java\.util\.[a-z]+|templatesimpl|logback\.core|this\.constructor\.constructor|assert\s*\(\s*base\d*_decode|/bin/sleep|create\s+alias|\.aspx|\.ashx|\.jspx|\.jsp|\|a:\d+:\{|group\s+by|decode\s*\(\s*length|/\*\*]], "jo")
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
        or lower:find("java.lang.", 1, true)
        or lower:find("java.util.", 1, true)
        or lower:find("templatesimpl", 1, true)
        or lower:find("logback.core", 1, true)
        or lower:find("this.constructor.constructor", 1, true)
        or lower:find("assert(base", 1, true)
        or lower:find("/bin/sleep", 1, true)
        or lower:find("create alias", 1, true)
        or lower:find(".aspx", 1, true)
        or lower:find(".ashx", 1, true)
        or lower:find(".jsp", 1, true)
        or lower:find("|a:", 1, true)
        or lower:find("group by", 1, true)
        or lower:find("decode(length", 1, true)
        or lower:find("/**/", 1, true)
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

-- 任意位置的可执行扩展名探测（不限于 multipart）。
--
-- detect_upload 只在 body 里按 filename= 抽取，查不到 GET 参数 / 路径里的
-- `?file=shell.php`、`/uploads/x.jsp` 这类形态，于是可执行文件上传形似"正常请求"
-- 被放行。站点级 fileExt 开关又只存在于镜像模板的 config.json，
-- 运行时 rules.json 里并没有这个字段（面板从未把它导出），所以不能依赖配置 ——
-- 语义层自带的这份表是唯一真正生效的兜底。
--
-- 大小写：先 lower() 再匹配表，`shell.pHp` 与 `shell.php` 等价。
function _M.detect_dangerous_ext(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    -- 只在含点号时才算扩展名，避免把正常句子里的点当文件名
    if not s:find("%.") then return false end
    for ext in s:gmatch("%.([%a][%w]*)") do
        if DANGEROUS_UPLOAD_EXTENSIONS[ext] then
            return true
        end
        -- 版本号后缀：shell.php5 / x.jsp4 / a.aspx0 在 IIS 与部分面板上同样可执行。
        -- 表里存的是 php/jsp/asp，这里把尾部数字剥掉再查一次。
        local base = ext:match("^([%a]+)%d+$")
        if base and DANGEROUS_UPLOAD_EXTENSIONS[base] then
            return true
        end
    end
    -- 双扩展名：shell.php.jpg / shell.jsp;.jpg —— 取最后一个点前的部分再判一次
    local stem = s:match("([^/%;]+)%.[%w]+$")
    if stem then
        for ext in stem:gmatch("%.([%a][%w]*)") do
            if DANGEROUS_UPLOAD_EXTENSIONS[ext] then
                return true
            end
        end
    end
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
        {"upload", _M.detect_dangerous_ext},
        {"prototype_pollution", _M.detect_prototype_pollution},
        {"graphql", _M.detect_graphql},
        {"sensitive_path", _M.detect_sensitive_path},
        {"lfi", function(v) return _M.detect_lfi(v, uri) end},
        {"ssrf", _M.detect_ssrf},
    }
    -- 不逐个 pcall：LuaJIT 无法跨 pcall 编译，这里是整个引擎最热的循环，
    -- 逐个包一层会把 detect_* 全部拖回解释器。检测器的异常由 access.lua
    -- 入口那一层统一兜底，行为等价。
    for _, c in ipairs(checks) do
        local hit = c[2](value)
        if hit then
            return {type = c[1], value = value}
        end
    end
    return nil
end

-- URI-only fast gate for requests without query/body. Token lookup is cheaper
-- than crossing into the large PCRE candidate matcher on every ordinary page
-- and API path. Any encoded or syntax-bearing path still uses the full engine.
local URI_PLAIN_FIRST_SEGMENT = {
    actuator=true, phpmyadmin=true, ["swagger-ui"]=true, ["server-status"]=true,
    druid=true, apisix=true, ["jmx-console"]=true, manager=true,
    ["wls-wsat"]=true, mgmt=true, jmreport=true, center=true,
    etc=true, proc=true, usr=true, windows=true, winnt=true,
    shell=true, webshell=true, excu_shell=true, invokefunction=true,
}

function _M.inspect_uri(value)
    if not value or value == "" or value == "/" then return nil end
    -- A plain path cannot express encoding, traversal, SQL/XSS syntax or shell
    -- metacharacters. Scan bytes in JIT-compiled Lua instead of invoking a
    -- pattern engine; only known high-risk first segments need deeper work.
    local plain = value:byte(1) == 47 -- '/'
    local first_end
    for i = 2, #value do
        local b = value:byte(i)
        local allowed = (b >= 48 and b <= 57) or (b >= 65 and b <= 90)
            or (b >= 97 and b <= 122) or b == 47 or b == 95 or b == 45
        if not allowed then plain = false; break end
        if b == 47 and not first_end then first_end = i - 1 end
    end
    if plain then
        local first = value:sub(2, first_end or -1):lower()
        if URI_PLAIN_FIRST_SEGMENT[first] then
            return _M.inspect(value, value)
        end
        -- 无点号的敏感路径（/etc/passwd / /actuator/env）走不到下面的模式分支，
        -- 必须在这里单独判一次，否则字节扫描的"plain 快速路径"会把它们直接放过。
        if _M.detect_sensitive_path(value) then
            return {type = "sensitive_path", value = value}
        end
        return nil
    end
    local lower = value:lower()
    if lower:find("[%%<'\"`;|$\\{}:?&=]") or lower:find("..", 1, true) then
        return _M.inspect(value, value)
    end
    -- Executable/server-side and backup artefacts need the full exposure rules;
    -- common static suffixes such as .js/.css/.png stay on the fast path.
    if lower:find("/%.git/") or lower:find("/%.env")
        or lower:find("%.php") or lower:find("%.jsp") or lower:find("%.asp")
        or lower:find("%.sql$") or lower:find("%.bak$") or lower:find("%.config") then
        -- 注意：这里不要直接返回 _M.inspect(value, value) 作为敏感路径的判定结果。
        -- inspect() 内部先过 has_attack_candidate，而 /a.bak 这类"只有后缀、
        -- 没有任何攻击特征"的串不在候选词表里，会被提前 return nil ——
        -- 于是 /a.bak 漏网、/config.php.bak 却能拦（它含 .php，过得了筛）。
        -- 先各自问一次专用的敏感路径检测器，再决定是否交给 inspect 深挖。
        if _M.detect_sensitive_path(value) then
            return {type = "sensitive_path", value = value}
        end
        return _M.inspect(value, value)
    end
    -- 敏感路径探测走查表：.env / .git/config / wp-config.php / id_rsa 这类，
    -- 多数含 '.' 所以已经落到这里；但 /etc/passwd（无点）会被上面的 plain
    -- 分支提前 return nil，所以那一类要在 plain 分支里也放行。
    if _M.detect_sensitive_path(value) then
        return {type = "sensitive_path", value = value}
    end
    return nil
end

-- ============ 原型污染 / GraphQL / 敏感路径枚举 ============
-- 这三类此前完全不在检测范围内：waf-detector 的 PrototypePollution 与
-- GraphQLInjection 两类各 5 个样本全部 200 放行。语义层没有对应检测器。

-- 待改写的原型键。Node/Express 生态里这些属性会改写 Object.prototype，
-- 一旦被污染，全站逻辑（鉴权判定、模板变量）都可能失效。
--
-- 模式写法说明（实测踩坑，别照抄直觉写法）：
--   · Lua pattern 不支持 | 交替，也**没有"宽松空白"概念**，只能靠 %s* 显式覆盖分隔符；
--   · JSON 形态的 constructor 与 prototype 之间是 `": {"`（键名+冒号+空白+新括号），
--     不是点号也不是方括号 —— 所以要点号模式，另配一个"宽松"模式：
--     constructor[^%w]{1,6}prototype，中间最多允许 6 个非字母数字字符。
--   · query 形态是 `?constructor[prototype]`，点号/方括号模式都覆盖不到，
--     单独用 %[ 转义方括号来匹配。
local PP_POLLUTION_KEYS = {
    "__proto__",
    "constructor%s*%.%s*prototype",
    "constructor[\"':%s%[%{]*prototype",
}

function _M.detect_prototype_pollution(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    if not s:find("__proto__", 1, true) and not s:find("constructor", 1, true) then
        return false
    end
    for _, pat in ipairs(PP_POLLUTION_KEYS) do
        if s:find(pat) then
            return true
        end
    end
    -- query 形态：?__proto__[admin]=true / ?__proto__[a][b]=c
    -- %[%s*__proto__%[ 要求 __proto__ 后紧跟另一个方括号，
    -- 这样 "?__proto__[admin]=true" 命中，而 "new constructor(1)" 不会。
    if s:find("%[%s*__proto__%[") then
        return true
    end
    -- JSON 形态里 __proto__ 与"赋值为 true"同时出现，语义更明确
    if s:find("__proto__", 1, true) and s:find(":", 1, true) then
        return true
    end
    return false
end

-- GraphQL 内省与注入。
--
-- 不拦所有 GraphQL 查询 —— 那会把正常的 GraphQL 应用整片打掉。
-- 只拦三类明确的探测/滥用形态：
--   1. 内省查询（__schema / __type / __directive 元数据遍历）
--   2. 别名批量枚举：`alias1: user(id:1){...} alias2: user(id:2){...}`
--      这是 GraphQL 特有的探测手法 —— 用 alias 在一个请求里重复同一字段，
--      一次性把整表数据拉出来。正常前端不会这么写。
--   3. 查询里出现文件系统/命令字面量（那是注入而非合法查询）
function _M.detect_graphql(value)
    if not value or value == "" then return false end
    local s = normalize.normalize(value)
    -- 必须像 GraphQL。
    --
    -- 判定放宽的原因：真实请求里的 query 键有三种写法 ——
    --   JSON 包装 {"query": "..."}   → 匹配 "query"
    --   GraphQL over GET  ?query={...} → 匹配 "query"
    --   URL 编码/紧凑形态 query={...}  → 上面两个都不匹配（query 后面既不是引号也不是冒号）
    -- 之前漏了第三种，导致 "query { alias1: ... }" 这类标准 GraphQL 请求
    -- 在 looks_graphql 处就return false，后面的别名枚举判据根本没机会跑。
    -- 用 %f 前沿保证 query 是独立词，避免命中 "enquery" 之类。
    local looks_graphql = s:find("\"query\"") or s:find("'query'")
        or s:find("\"mutation\"") or s:find("'mutation'")
        or s:find("[\"']query[\"']%s*[:%]") or s:find("[\"']mutation[\"']%s*[:%]")
        or s:find("%f[%w]query%f[^%w]") or s:find("%f[%w]mutation%f[^%w]")
        or s:find("{%s*__schema") or s:find("{%s*__type")
    if not looks_graphql then return false end
    -- 内省字段：schema / type 元数据遍历
    if s:find("__schema") or s:find("__type%s*%(") or s:find("__typename")
        or s:find("introspectiontype") or s:find("__directive") then
        return true
    end
    -- 别名批量枚举：同一个字段名被 alias 前缀重复引用。
    -- Lua pattern 无"反向引用"，改用"统计片段出现次数"来判定：
    -- 把花括号内的内容抓出来，数其中 "字段名(" 的出现次数，>=2 即为枚举。
    local body = s:match("{%b{}}")
    if body then
        for field in body:gmatch("([%a_][%w_]*)%s*%(") do
            local n = 0
            for _ in body:gmatch(field .. "%s*%(") do
                n = n + 1
                if n >= 2 then break end
            end
            if n >= 2 then
                return true
            end
        end
    end
    -- alias 前缀叠加字段选择：alias1: user / a1: user
    local _, aliases = s:gsub("([%a][%w_]*%d)%s*:%s*[%a][%w_]*%s*%(", "")
    if aliases and aliases >= 2 then
        return true
    end
    -- 注入形态：查询里带文件系统或命令痕迹
    if s:find("/etc/passwd", 1, true) or s:find("__typename%s*{") then
        return true
    end
    if s:find("%b{}") and (s:find("%$\\{") or s:find("sleep%s*%(") or s:find("benchmark%s*%(")) then
        return true
    end
    return false
end

-- 敏感路径 / 字典探测。
--
-- 只覆盖"文件本身就是攻击目标"的高危清单，不做通用字典暴力破解 ——
-- 后者需要状态关联（同一 IP 连续命中多个 404），那是 probe.lua 的职责。
-- 这里只拦单个请求就足以判定的敏感文件。
local SENSITIVE_PATHS = {
    "/%.env$", "/%.env%.", "/%.git/config", "/%.git/head", "/%.svn/entries",
    "/wp%-config%.php", "/configuration%.php", "/config%.inc%.php",
    "/web%.config$", "/database%.yml", "/credentials", "/id_rsa",
    "/%.aws/credentials", "/%.ssh/id_rsa", "/etc/passwd", "/etc/shadow",
    "/phpinfo%.php", "/info%.php", "/test%.php", "/shell%.php",
    "/cmd%.php", "/c99%.php", "/r57%.php", "/webshell",
    "/manager/html", "/jmx-console", "/actuator/env", "/actuator/heapdump",
    "/solr/admin", "/druid/login", "/phpmyadmin", "/adminer%.php",
    "/.aws/", "/.dockerenv", "/server%-status", "/.svn/",
}

-- 备份/编辑器残留产物：config.php.bak / db.sql / web.xml.swp
--
-- 写法说明（踩过的坑）：Lua pattern **不支持 | 交替**，
-- `%.(bak|old|orig|save|swp)$` 里的竖线是字面量，永远匹配不到。
-- 必须逐个后缀走表或分开 if。
local BACKUP_EXTS = { "bak", "old", "orig", "save", "swp", "swo", "tmp", "dist" }

local function ends_with_backup_ext(s)
    -- 取最后一个点之后的部分（斜杠也要排除，避免 "a.b/c" 误判）
    local tail = s:match("([^/]+)$")
    if not tail then return false end
    local ext = tail:match("%.([%a%d]+)$")
    if not ext then return false end
    for _, e in ipairs(BACKUP_EXTS) do
        if ext == e then
            return true
        end
    end
    return false
end

function _M.detect_sensitive_path(value)
    if not value or value == "" then return false end
    local s = normalize.normalize_path(value)
    for _, pat in ipairs(SENSITIVE_PATHS) do
        if s:find(pat) then
            return true
        end
    end
    if ends_with_backup_ext(s) then
        return true
    end
    -- 数据库导出：db.sql / dump.sql.gz / backup.sql
    if s:match("/[^/]+%.sql$") or s:match("/[^/]+%.sql%.gz$")
        or s:match("/[^/]+%.sql%.zip$") or s:match("/[^/]+%.dump$") then
        return true
    end
    return false
end

_M.attack_types = {"sqli", "xss", "rce", "lfi", "ssrf", "upload", "log4shell", "code_injection", "ssti", "deserialization", "xxe", "exposure", "prototype_pollution", "graphql", "sensitive_path"}

return _M

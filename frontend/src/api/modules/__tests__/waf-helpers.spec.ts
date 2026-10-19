import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { WAF_IP_GROUP_NAME_PATTERN } from '@/api/modules/waf';
import {
    buildCurlCommand,
    buildLogSortParam,
    formatDuration,
    layerLabelKey,
    shellQuote,
    WAF_LOG_SORT_OPTIONS,
    type WAFLogSortKey,
    WAF_DETECTORS,
    WAF_MODES,
    parseDisabledDetectors,
    formatDisabledDetectors,
    isInvalidPageColor,
    WAF_LEVELS,
    normalizeLevel,
} from '@/api/modules/waf-helpers';

// 带 bash 往返断言的 describe 全部用 describeWithBash：原生 Windows 上
// 没有 bash，execFileSync 报ENOENT 会让整个文件挂掉。
// 纯字符串断言的 describe 保持正常，在所有平台都跑。
const describeWithBash = process.platform === 'win32' ? describe.skip : describe;

describeWithBash('shellQuote：单引号转义', () => {
    it('纯安全字符不加引号', () => {
        expect(shellQuote('abc123')).toBe('abc123');
        expect(shellQuote('/api/v1/users')).toBe('/api/v1/users');
    });

    it('含空格时包单引号', () => {
        expect(shellQuote('hello world')).toBe("'hello world'");
    });

    it('含美元符、反引号、分号时必须引号包裹', () => {
        // 命令注入载荷含这些字符，未加引号会被本地 shell 执行
        expect(shellQuote('$(whoami)')).toBe("'$(whoami)'");
        expect(shellQuote('`id`')).toBe("'`id`'");
        expect(shellQuote('a;b|c&d')).toBe("'a;b|c&d'");
    });

    it('空串返回两个引号而不是裸空', () => {
        // 裸空会被 shell 吃掉，两个引号才表示"空参数"
        expect(shellQuote('')).toBe("''");
    });

    /**
     * 关键用例：断言的不是字符串长什么样，而是「真 shell 解析后能否还原成原值」。
     *
     * 之前这里写死预期字符串，结果自己的预期算错了一个引号，
     * 差点把正确的实现改坏。引号转义这种事不能靠肉眼看 —— 唯一可靠的判据是
     * 交给 bash 自己拆参数。
     */
    const roundTripThroughShell = (value: string): string => {
        const script = `set -- ${shellQuote(value)}; printf '%s' "$1"`;
        return execFileSync('bash', ['-c', script], { encoding: 'utf8' });
    };

    const PAYLOADS = [
        "' OR '1'='1",
        '$(whoami)',
        '`id`',
        'a;b|c&d',
        'hello world',
        'C:\\windows\\system32',
        'a b"c',
        '<script>alert(1)</script>',
        '{{7*7}}',
        '../../../etc/passwd',
    ];

    it.each(PAYLOADS)('shell 能把 %j 还原为原值', (payload) => {
        expect(roundTripThroughShell(payload)).toBe(payload);
    });

    it('载荷里的命令替换不会被执行', () => {
        // 若转义失效，$(echo pwned) 会被 shell 求值成 pwned
        const evil = '$(echo pwned)';
        expect(roundTripThroughShell(evil)).toBe('$(echo pwned)');
    });
});

describeWithBash('buildCurlCommand：生成可复现命令', () => {
    it('GET 请求不带 --data', () => {
        const cmd = buildCurlCommand({ method: 'GET', path: '/login', websiteName: 'a.com' });
        expect(cmd).toContain('-X GET');
        expect(cmd).toContain('http://a.com/login');
        expect(cmd).not.toContain('--data');
    });

    it('有 query 时拼进 URL', () => {
        const cmd = buildCurlCommand({
            method: 'GET',
            path: '/search',
            query: "q=' OR '1'='1",
            websiteName: 'a.com',
        });
        expect(cmd).toContain('/search?');
        // URL 里的单引号必然被转义（否则 shell 拆参数就错了），
        // 所以不能断言"载荷原样出现"，要断言的是「shell 还原后仍等于原 URL」。
        const expectUrl = "http://a.com/search?q=' OR '1'='1";
        const restored = execFileSync(
            'bash',
            ['-c', `set -- ${cmd}; for a in "$@"; do case "$a" in http*) printf '%s' "$a"; break ;; esac; done`],
            { encoding: 'utf8' },
        );
        expect(restored).toBe(expectUrl);
    });

    it('POST 带请求体时加 --data-raw', () => {
        const cmd = buildCurlCommand({
            method: 'POST',
            path: '/api',
            requestBody: '{"user":"bob"}',
            websiteName: 'a.com',
        });
        expect(cmd).toContain('-X POST');
        expect(cmd).toContain('--data-raw');
        expect(cmd).toContain('{"user":"bob"}');
    });

    it('无 UA 时不生成 UA 头', () => {
        const cmd = buildCurlCommand({ method: 'GET', path: '/', websiteName: 'a.com' });
        expect(cmd).not.toContain('User-Agent');
    });

    it('有 UA 时作为头', () => {
        const cmd = buildCurlCommand({
            method: 'GET',
            path: '/',
            userAgent: 'Mozilla/5.0 Chrome/120.0',
            websiteName: 'a.com',
        });
        expect(cmd).toContain('User-Agent: Mozilla/5.0 Chrome/120.0');
    });

    it('无站点名时退化为相对路径而非拼出坏 URL', () => {
        const cmd = buildCurlCommand({ method: 'GET', path: '/login' });
        expect(cmd).toContain('/login');
        // 没有域名就不能拼 http:// 前缀，否则复制出去是条错命令
        expect(cmd).not.toContain('http://');
    });

    it('缺 method 时默认 GET', () => {
        expect(buildCurlCommand({ path: '/' })).toContain('-X GET');
    });

    it('含反斜杠的 Windows 路径 payload 不破坏命令', () => {
        const cmd = buildCurlCommand({
            method: 'GET',
            path: '/x',
            query: 'a=C:\\windows\\system32',
            websiteName: 'a.com',
        });
        expect(cmd).toContain('C:\\windows\\system32');
    });
});

describe('buildLogSortParam：排序参数组装', () => {
    it('每个选项都能映射到存在的列名', () => {
        for (const opt of WAF_LOG_SORT_OPTIONS) {
            const { orderBy, order } = buildLogSortParam(opt.value);
            expect(orderBy, `${opt.value} 缺少 orderBy`).toBeTruthy();
            expect(['asc', 'desc']).toContain(order);
        }
    });

    it('时间排序用 created_at 列', () => {
        expect(buildLogSortParam('time_asc')).toEqual({ orderBy: 'created_at', order: 'asc' });
        expect(buildLogSortParam('time_desc')).toEqual({ orderBy: 'created_at', order: 'desc' });
    });

    it.each([
        ['time_asc', 'created_at', 'asc'],
        ['time_desc', 'created_at', 'desc'],
        ['ip_asc', 'ip', 'asc'],
        // 下面三个原来只被「非空 + 是 asc/desc」的循环覆盖，
        // 把列名拼错（如 attackType）测试也会全绿，后端则静默退回按时间排。
        ['ip_desc', 'ip', 'desc'],
        ['type_asc', 'attack_type', 'asc'],
        ['type_desc', 'attack_type', 'desc'],
        ['duration_desc', 'duration_ms', 'desc'],
    ] as [WAFLogSortKey, string, string][])('%s -> %s %s', (key, col, dir) => {
        expect(buildLogSortParam(key)).toEqual({ orderBy: col, order: dir });
    });

    // 契约测试：前端能产生的每个 orderBy 都必须在后端白名单里。
    // 后端是 wafLogSortableColumns（agent/app/service/waf.go），
    // 对不上时它会退回 created_at —— 不报错，只是静默排错。
    const BACKEND_SORTABLE = [
        'created_at',
        'ip',
        'attack_type',
        'action',
        'duration_ms',
        'path',
        'website_id',
        'false_positive',
    ];
    it.each(WAF_LOG_SORT_OPTIONS.map((o) => o.value))('%s 的 orderBy 在后端白名单内', (key) => {
        const { orderBy } = buildLogSortParam(key);
        expect(BACKEND_SORTABLE).toContain(orderBy);
    });

    it('耗时排序用 duration_ms 列', () => {
        expect(buildLogSortParam('duration_desc')).toEqual({ orderBy: 'duration_ms', order: 'desc' });
    });

    it('缺省与 undefined 都退回时间倒序', () => {
        expect(buildLogSortParam(undefined)).toEqual({ orderBy: 'created_at', order: 'desc' });
    });
});

describe('layerLabelKey：拦截层名称映射', () => {
    it('已知层返回对应 i18n 键', () => {
        expect(layerLabelKey('rules')).toBe('website.wafLayerRules');
        expect(layerLabelKey('cc')).toBe('website.wafLayerCC');
        expect(layerLabelKey('semantic')).toBe('website.wafLayerSemantic');
    });

    it('未知层不泄漏原始字符串', () => {
        expect(layerLabelKey('something-new')).toBe('website.wafLayerUnknown');
    });

    it('空值按未知处理', () => {
        expect(layerLabelKey('')).toBe('website.wafLayerUnknown');
        expect(layerLabelKey(null)).toBe('website.wafLayerUnknown');
    });
});

describe('formatDuration：耗时展示', () => {
    it('正常值取整', () => {
        expect(formatDuration(12.4)).toBe(12);
        expect(formatDuration(12.6)).toBe(13);
    });

    it('缺失/非法值显示 0 而不是 NaN', () => {
        // 表格里显示 NaN 会让整行看起来像渲染坏了
        expect(formatDuration(undefined)).toBe(0);
        expect(formatDuration(null)).toBe(0);
        expect(formatDuration(NaN)).toBe(0);
        expect(formatDuration(-5)).toBe(0);
    });
});

// ==================== 防护模式与检测器开关 ====================

describe('WAF_MODES：防护模式取值', () => {
    it('三种模式的 value 与后端 model / Lua 字面量一致', () => {
        // 后端 model.WAFOption.Mode 默认 "block"；Lua access.lua 判的是
        // "observe" / "maintenance"。拼错任何一个，Lua 会静默走默认分支。
        expect(WAF_MODES.map((m) => m.value)).toEqual(['block', 'observe', 'maintenance']);
    });

    it('每个模式都有 label 与 desc 的 i18n 键', () => {
        for (const m of WAF_MODES) {
            expect(m.labelKey).toMatch(/^website\.wafMode/);
            expect(m.descKey).toMatch(/^website\.wafMode.*Desc$/);
        }
    });
});

describe('WAF_DETECTORS：检测器清单', () => {
    /**
     * 契约测试：前端能关的检测器必须与 Lua semantic.lua 的 checks 数组
     * 键名 + attack_types 完全一致。
     *
     * 名字对不上 = 界面上能关、能保存，实际关不掉，且**不报任何错**。
     * 这正是本轮修掉的 exposure / sensitive_path 那类问题。
     */
    it('与 Lua semantic.lua 的 attack_types 一一对应', () => {
        // 来源：agent/utils/waf/lua/semantic.lua 的 _M.attack_types
        const LUA_ATTACK_TYPES = [
            'sqli',
            'xss',
            'rce',
            'lfi',
            'ssrf',
            'upload',
            'log4shell',
            'code_injection',
            'ssti',
            'deserialization',
            'xxe',
            'exposure',
            'prototype_pollution',
            'graphql',
            'sensitive_path',
        ];
        expect(WAF_DETECTORS.map((d) => d.name).sort()).toEqual([...LUA_ATTACK_TYPES].sort());
    });

    it('清单里没有重复项', () => {
        const names = WAF_DETECTORS.map((d) => d.name);
        expect(new Set(names).size).toBe(names.length);
    });

    it('每个检测器都有 i18n 键', () => {
        for (const d of WAF_DETECTORS) {
            expect(d.labelKey).toMatch(/^website\.wafDetector/);
        }
    });
});

describe('parseDisabledDetectors / formatDisabledDetectors', () => {
    it('空值解析成空集合', () => {
        expect(parseDisabledDetectors('').size).toBe(0);
        expect(parseDisabledDetectors('   ').size).toBe(0);
        expect(parseDisabledDetectors(null).size).toBe(0);
        expect(parseDisabledDetectors(undefined).size).toBe(0);
    });

    it('解析时去掉空白与空项', () => {
        // 后端存的是逗号分隔字符串，用户手工编辑可能带上空格或尾逗号
        expect([...parseDisabledDetectors(' sqli , , xss ,')]).toEqual(['sqli', 'xss']);
    });

    it('已是固定顺序的输入往返保持原样', () => {
        // 注意：输出**按清单顺序排序**，所以只有本身就有序的输入才往返相等。
        // 若断言"任意输入往返相等"，等于否定了排序这个设计本身。
        for (const raw of ['', 'sqli', 'sqli,xss', 'sqli,xss,exposure']) {
            expect(formatDisabledDetectors(parseDisabledDetectors(raw))).toBe(raw);
        }
    });

    it('输出顺序固定，不随用户点击顺序变化', () => {
        // 按清单顺序输出：否则每次保存后顺序都可能不同，
        // 用户 diff 配置时看不出真正改了什么。
        expect(formatDisabledDetectors(['xss', 'sqli'])).toBe('sqli,xss');
        expect(formatDisabledDetectors(['exposure', 'sensitive_path', 'rce'])).toBe('rce,exposure,sensitive_path');
    });

    it('空集合序列化成空串（后端据此走全部启用）', () => {
        expect(formatDisabledDetectors([])).toBe('');
        expect(formatDisabledDetectors(new Set())).toBe('');
    });

    it('忽略纯空白的名字', () => {
        expect(formatDisabledDetectors(['sqli', '  ', ''])).toBe('sqli');
    });
});

describe('isInvalidPageColor：拦截页颜色校验', () => {
    it('接受 #RRGGBB', () => {
        expect(isInvalidPageColor('#123456')).toBe(false);
        expect(isInvalidPageColor('#abcdef')).toBe(false);
    });

    it('接受少量具名色', () => {
        expect(isInvalidPageColor('black')).toBe(false);
        expect(isInvalidPageColor('White')).toBe(false);
        expect(isInvalidPageColor(' blue ')).toBe(false);
    });

    it('空串视为未设置（合法）', () => {
        expect(isInvalidPageColor('')).toBe(false);
    });

    it('拒绝 CSS 注入载荷', () => {
        // 颜色会拼进 style 属性；这些在老浏览器上能执行脚本
        expect(isInvalidPageColor('red;background:url(javascript:alert(1))')).toBe(true);
        expect(isInvalidPageColor('expression(alert(1))')).toBe(true);
        expect(isInvalidPageColor('#fff;behavior:url(x.htc)')).toBe(true);
    });

    it('拒绝短格式与非十六进制', () => {
        // 后端 safe_color 只认 #RRGGBB 与具名色，#fff 这种短格式会被拒
        expect(isInvalidPageColor('#fff')).toBe(true);
        expect(isInvalidPageColor('#12345')).toBe(true);
        expect(isInvalidPageColor('#1234567')).toBe(true);
        expect(isInvalidPageColor('rebeccapurple')).toBe(true);
    });
});

// ==================== i18n 键存在性 ====================
// 本轮手写驼峰键名出过错（code_injection 写成了 Codeinjection），
// 界面表现为「标签位置显示 website.wafDetectorCodeinjection」——
// 这种错误肉眼很难发现，但正则一查就出来。所以固化成测试。

describe('i18n 键存在性', () => {
    const readKeys = (file: string): Set<string> => {
        const src = readFileSync(file, 'utf8');
        return new Set([...src.matchAll(/^\s+(waf[A-Za-z0-9_]*):/gm)].map((m) => m[1] ?? ''));
    };

    const zhKeys = readKeys('src/lang/modules/zh.ts');
    const enKeys = readKeys('src/lang/modules/en.ts');

    /** 代码里引用到的所有 i18n 键 */
    const referenced = new Set<string>();
    const collect = (src: string) => {
        for (const m of src.matchAll(/website\.(waf[A-Za-z0-9_]*)/g)) referenced.add(m[1] ?? '');
    };
    collect(readFileSync('src/api/modules/waf-helpers.ts', 'utf8'));
    collect(readFileSync('src/views/website/website/waf/index.vue', 'utf8'));
    collect(readFileSync('src/views/website/website/waf/rule-dialog.vue', 'utf8'));

    it.each([...referenced].sort())('键 %s 在 zh 与 en 里都有定义', (key) => {
        expect(zhKeys.has(key)).toBe(true);
        expect(enKeys.has(key)).toBe(true);
    });

    it('WAF_DETECTORS 的 15 个 labelKey 全部有定义', () => {
        for (const d of WAF_DETECTORS) {
            const key = d.labelKey.replace('website.', '');
            expect(zhKeys.has(key)).toBe(true);
            expect(enKeys.has(key)).toBe(true);
        }
    });

    it('WAF_MODES 的 label 与 desc 键全部有定义', () => {
        for (const m of WAF_MODES) {
            for (const k of [m.labelKey, m.descKey]) {
                expect(zhKeys.has(k.replace('website.', ''))).toBe(true);
                expect(enKeys.has(k.replace('website.', ''))).toBe(true);
            }
        }
    });
});

// ==================== 保护强度分档 ====================

describe('WAF_LEVELS：强度分档取值', () => {
    it('四档的 value 与后端 model / Lua 字面量一致', () => {
        // 后端 model 默认 "balanced"；Lua semantic.lua / bot.lua 判的是
        // "off" / "observe" / "high"。拼错任何一个都会归一到 balanced，
        // 界面上选了却没效果。
        expect(WAF_LEVELS.map((l) => l.value)).toEqual(['off', 'observe', 'balanced', 'high']);
    });

    it('每一档都有 label 与 desc 的 i18n 键', () => {
        for (const l of WAF_LEVELS) {
            expect(l.labelKey).toMatch(/^website\.wafLevel/);
            expect(l.descKey).toMatch(/^website\.wafLevel.*Desc$/);
        }
    });

    it('没有重复档位', () => {
        const values = WAF_LEVELS.map((l) => l.value);
        expect(new Set(values).size).toBe(values.length);
    });
});

describe('normalizeLevel：空值归一', () => {
    it('合法值原样返回', () => {
        expect(normalizeLevel('off')).toBe('off');
        expect(normalizeLevel('observe')).toBe('observe');
        expect(normalizeLevel('balanced')).toBe('balanced');
        expect(normalizeLevel('high')).toBe('high');
    });

    it('空值归一到 balanced（与 Lua setter 行为一致）', () => {
        // 老数据没有这两列时后端返回空串。若界面显示空而实际跑 balanced，
        // 用户会以为"没配"，排查时对不上。
        expect(normalizeLevel('')).toBe('balanced');
        expect(normalizeLevel(null)).toBe('balanced');
        expect(normalizeLevel(undefined)).toBe('balanced');
    });

    it('脏数据也归一到 balanced，不会静默变成 off', () => {
        // 归一成 off 会让整层防护消失，比显示错更危险
        expect(normalizeLevel('OFF')).toBe('balanced');
        expect(normalizeLevel('high ')).toBe('balanced');
        expect(normalizeLevel('block')).toBe('balanced');
    });
});

// ==================== 匹配操作符契约 ====================
// matchOp 有三处必须同步：前端下拉、Lua rules.lua 的 match_ops、
// 后端 DTO 的 oneof 白名单。任何一处漏改，用户就会遇到
// 「界面上选不到」或「保存被拒」或「配了不生效」。

describe('matchOp 三处同步', () => {
    const dialogSrc = readFileSync('src/views/website/website/waf/rule-dialog.vue', 'utf8');

    /** 从 rule-dialog.vue 的 matchOps 数组里解析出操作符列表 */
    const frontendOps = ((): string[] => {
        const m = dialogSrc.match(/const matchOps = \[([\s\S]*?)\];/);
        if (!m?.[1]) return [];
        return [...m[1].matchAll(/'([a-z_]+)'/g)].map((x) => x[1] ?? '');
    })();

    /** 从后端 DTO 的 oneof 白名单里解析 */
    const dtoSrc = readFileSync('../agent/app/dto/request/waf.go', 'utf8');
    const backendOps = ((): string[] => {
        const m = dtoSrc.match(/MatchOp\s+string[^\n]*oneof=([a-z_ ]+)/);
        if (!m?.[1]) return [];
        return m[1].trim().split(/\s+/);
    })();

    /** 从 Lua rules.lua 的批量生成循环里解析基名 */
    const luaSrc = readFileSync('../agent/utils/waf/lua/rules.lua', 'utf8');
    const luaBaseOps = ((): string[] => {
        const m = luaSrc.match(/for _, base in ipairs\(\{\s*((?:"[a-z_]+"\s*,?\s*)+)\}\)/);
        if (!m?.[1]) return [];
        return [...m[1].matchAll(/"([a-z_]+)"/g)].map((x) => x[1] ?? '');
    })();

    it('前端解析到 12 个操作符', () => {
        expect(frontendOps).toHaveLength(12);
    });

    it('后端 DTO 解析到 12 个操作符', () => {
        expect(backendOps).toHaveLength(12);
    });

    it('Lua 批量生成 6 个基名', () => {
        expect(luaBaseOps).toEqual(['exact', 'contains', 'prefix', 'suffix', 'wildcard', 'regex']);
    });

    it('前端与后端完全一致', () => {
        expect([...frontendOps].sort()).toEqual([...backendOps].sort());
    });

    it('Lua 基名 + 派生的 not_ 前缀 == 前后端列表', () => {
        const derived = [...luaBaseOps, ...luaBaseOps.map((b) => `not_${b}`)].sort();
        expect(derived).toEqual([...frontendOps].sort());
    });

    it('每个负向操作符都有对应的正向（不会只生成一半）', () => {
        for (const op of frontendOps.filter((o) => o.startsWith('not_'))) {
            const base = op.slice(4);
            expect(frontendOps).toContain(base);
        }
    });
});

// ==================== IP 组：组名契约 ====================
// 组名会直接成为 rules.json 里的 map key。填错一个字符就是
// 「组不存在」且 Lua 侧静默放行 —— 界面上看不出任何异常。
// 所以前后端的组名规则必须逐字符一致。

describe('IP 组组名规则前后端一致', () => {
    const svcSrc = readFileSync('../agent/app/service/waf.go', 'utf8');

    // Go 源码里的正则字面量就是前端这条正则的来源。
    // 直接断言「Go 源码包含前端这条正则」——比解析 Go 语法取出来更稳，
    // 也不会因为 Go 侧的写法调整（比如加了 var 前缀）就失效。
    const FRONTEND_PATTERN_SOURCE = WAF_IP_GROUP_NAME_PATTERN.source;

    it('Go 源码里包含前端这条正则', () => {
        expect(svcSrc).toContain('`' + FRONTEND_PATTERN_SOURCE + '`');
    });

    it('接受合法组名', () => {
        for (const name of ['office', 'office_v2', 'office-v2', 'Abc123', 'a', 'A_1-2']) {
            expect(WAF_IP_GROUP_NAME_PATTERN.test(name)).toBe(true);
        }
    });

    it('拒绝会破坏 map key 或匹配语义的组名', () => {
        // 逗号/引号/空格/中文/点号都会破坏 rules.json 的 key 或匹配语义
        for (const name of ['', ' ', 'a b', 'a,b', 'a.b', "a'b", 'a"b', 'a/b', '组名']) {
            expect(WAF_IP_GROUP_NAME_PATTERN.test(name)).toBe(false);
        }
    });

    it('长度上限 64', () => {
        expect(WAF_IP_GROUP_NAME_PATTERN.test('a'.repeat(64))).toBe(true);
        expect(WAF_IP_GROUP_NAME_PATTERN.test('a'.repeat(65))).toBe(false);
    });
});

// ==================== 统计维度契约 ====================
// 前端 statDimensions 里的 prop 必须是后端 WAFStats 真实存在的 JSON 字段。
// 拼错时界面只是渲染一片「暂无数据」，不报任何错 —— 而用户会以为
// 那段日志真的没有，实际是字段名对不上。

describe('统计维度前后端字段名一致', () => {
    const indexSrc = readFileSync('src/views/website/website/waf/index.vue', 'utf8');
    const statsSrc = readFileSync('../agent/app/service/waf_stats.go', 'utf8');

    /** 前端 statDimensions 里声明的 prop */
    // 多行写法（prop 与 titleKey 分两行）也要匹配，否则只能数到单行条目
    const frontendProps = [...indexSrc.matchAll(/prop: '([A-Za-z]+)',\s*\n?\s*titleKey:/g)].map((m) => m[1] ?? '');

    /** 后端 WAFStats 结构体的 json tag */
    const backendFields = new Set([...statsSrc.matchAll(/json:"([A-Za-z]+)"/g)].map((m) => m[1] ?? ''));

    it('前端声明了 12 个维度', () => {
        expect(frontendProps).toHaveLength(12);
    });

    it('每个维度的 prop 都在后端有同名字段', () => {
        for (const p of frontendProps) {
            expect(backendFields.has(p)).toBe(true);
        }
    });

    it('后端 summary 的字段前端都认识（KPI 用得到）', () => {
        // KPI 卡片直接读 stat.summary.xxx，字段名错了会显示 0 而不是报错
        for (const f of ['total', 'denied', 'uniqueIPs', 'avgDurationMs', 'falsePositive']) {
            expect(backendFields.has(f)).toBe(true);
            expect(indexSrc).toContain(`stat.summary?.${f}`);
        }
    });

    it('维度清单里没有重复 prop', () => {
        expect(new Set(frontendProps).size).toBe(frontendProps.length);
    });
});

// ==================== matchType 三处同步 ====================
// matchType 出现在：前端 rule-dialog.vue 的下拉、后端 DTO 的 oneof 白名单、
// Lua rules.lua 的 rule_hit 分支。
//
// 这里是一次真 bug 的回归：batch 3 加了 ip_group，batch 5 加了 geo，
// 但 DTO 的 oneof 一直没更新 —— 界面上选「IP 组」保存会被后端直接拒绝。

describe('matchType 前后端一致', () => {
    const dialogSrc = readFileSync('src/views/website/website/waf/rule-dialog.vue', 'utf8');
    const dtoSrc = readFileSync('../agent/app/dto/request/waf.go', 'utf8');
    const rulesSrc = readFileSync('../agent/utils/waf/lua/rules.lua', 'utf8');

    /** 前端下拉里的 matchTypes */
    const frontendTypes = ((): string[] => {
        const m = dialogSrc.match(/const matchTypes = \[([\s\S]*?)\];/);
        if (!m?.[1]) return [];
        return [...m[1].matchAll(/'([a-z_]+)'/g)].map((x) => x[1] ?? '');
    })();

    /** 后端 DTO 的 oneof 白名单（取 Create 那一条） */
    const backendTypes = ((): string[] => {
        const m = dtoSrc.match(/MatchType\s+string[^\n]*oneof=([a-z_ ]+)/);
        if (!m?.[1]) return [];
        return m[1].trim().split(/\s+/);
    })();

    /** Lua rule_hit 里处理的 match_type 分支 */
    const luaTypes = ((): string[] => {
        const out = new Set<string>();
        for (const m of rulesSrc.matchAll(/mt == "([a-z_]+)"/g)) {
            if (m[1]) out.add(m[1]);
        }
        // ip/cidr 是合在同一个分支里的，上面已分别匹配到
        return [...out];
    })();

    it('前端解析到 11 个类型', () => {
        expect(frontendTypes).toHaveLength(11);
    });

    it('后端白名单解析到 11 个类型', () => {
        expect(backendTypes).toHaveLength(11);
    });

    it('前端与后端完全一致', () => {
        expect([...frontendTypes].sort()).toEqual([...backendTypes].sort());
    });

    it('Lua 对每个类型都有分支', () => {
        for (const t of frontendTypes) {
            expect(luaTypes).toContain(t);
        }
    });

    it('ip_group 与 geo 在两处都必须在（本轮补的真 bug）', () => {
        for (const t of ['ip_group', 'geo']) {
            expect(frontendTypes).toContain(t);
            expect(backendTypes).toContain(t);
            expect(luaTypes).toContain(t);
        }
    });
});

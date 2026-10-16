import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
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

import type { WAFMode } from '@/api/modules/waf';

/**
 * WAF 页面里的纯逻辑函数。
 *
 * 抽出来单独放，是为了能在 vitest 里直接断言 —— SFC 内的 <script setup>
 * 没法被测试直接 import，而这几处逻辑恰恰是最容易出错、又最该被锁住的：
 * curl 拼接的引号转义、排序参数的组装、拦截层名称映射。
 */

// 拦截层取值来自 Lua 侧 access.lua 各处 log_event 的第二个参数
// （rules / subscription / bot / cc / probe / semantic / smuggling / websocket）。
// 这里是它们到 i18n 键的映射；未命中的一律按 unknown 显示，
// 不能直接回显原始字符串 —— 那等于把内部实现细节暴露给用户。
export const WAF_LAYER_LABEL_KEYS: Record<string, string> = {
    rules: 'website.wafLayerRules',
    subscription: 'website.wafLayerSubscription',
    bot: 'website.wafLayerBot',
    cc: 'website.wafLayerCC',
    probe: 'website.wafLayerProbe',
    semantic: 'website.wafLayerSemantic',
    smuggling: 'website.wafLayerSmuggling',
    websocket: 'website.wafLayerWebsocket',
};

export const layerLabelKey = (layer?: string | null): string => {
    if (!layer) return 'website.wafLayerUnknown';
    return WAF_LAYER_LABEL_KEYS[layer] || 'website.wafLayerUnknown';
};

/** 后端支持哪些排序，后端是权威 —— 前端下拉的选项必须与之一致。 */
export type WAFLogSortKey =
    'time_asc' | 'time_desc' | 'ip_asc' | 'ip_desc' | 'type_asc' | 'type_desc' | 'duration_desc';

export const WAF_LOG_SORT_OPTIONS: { value: WAFLogSortKey; labelKey: string }[] = [
    { value: 'time_desc', labelKey: 'website.wafLogSortTimeDesc' },
    { value: 'time_asc', labelKey: 'website.wafLogSortTimeAsc' },
    { value: 'ip_desc', labelKey: 'website.wafLogSortIPDesc' },
    { value: 'ip_asc', labelKey: 'website.wafLogSortIPAsc' },
    { value: 'type_desc', labelKey: 'website.wafLogSortTypeDesc' },
    { value: 'type_asc', labelKey: 'website.wafLogSortTypeAsc' },
    { value: 'duration_desc', labelKey: 'website.wafLogSortDurationDesc' },
];

/**
 * 把前端排序选项翻译成后端请求字段。
 *
 * 后端契约：orderBy 指定排序列，order 指定方向。
 * 两者分开传，避免在后端硬编码一串"order 字符串白名单"，
 * 也避免前端拼 "ip:desc" 这种需要后端再解析一次的格式。
 */
export const buildLogSortParam = (sortKey: WAFLogSortKey | undefined): { orderBy?: string; order?: 'asc' | 'desc' } => {
    switch (sortKey) {
        case 'time_asc':
            return { orderBy: 'created_at', order: 'asc' };
        case 'time_desc':
            return { orderBy: 'created_at', order: 'desc' };
        case 'ip_asc':
            return { orderBy: 'ip', order: 'asc' };
        case 'ip_desc':
            return { orderBy: 'ip', order: 'desc' };
        case 'type_asc':
            return { orderBy: 'attack_type', order: 'asc' };
        case 'type_desc':
            return { orderBy: 'attack_type', order: 'desc' };
        case 'duration_desc':
            return { orderBy: 'duration_ms', order: 'desc' };
        default:
            // 缺省按时间倒序：这是运维查看攻击日志的默认视角。
            return { orderBy: 'created_at', order: 'desc' };
    }
};

/**
 * shell 单引号转义。
 *
 * 载荷里出现单引号是常态（SQLi 的 ' OR '1'='1、SSTI 的 {{ ''.__class__ }}），
 * 不转义的话拼出来的 curl 会被 shell 截断，复制到终端执行得到的是另一个请求，
 * 用户会以为「面板给的复现命令是错的」。
 */
export const shellQuote = (value: string): string => {
    if (value === '') return "''";
    // 安全字符集：不含空格、引号、反斜杠、美元符、反引号 —— 这些才是真正需要转义的。
    if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value;
    return `'${value.split("'").join(`'\\''`)}'`;
};

export interface WAFCurlLog {
    method?: string;
    path?: string;
    query?: string;
    userAgent?: string;
    requestBody?: string;
    websiteName?: string;
}

/**
 * 由攻击日志生成可复现的 curl 命令。
 *
 * 设计取舍：
 * 1. 不带 Cookie —— 日志侧没存请求头，凭空造一个假的头反而误导排查。
 * 2. 请求体只在非空时加 --data，避免 GET 请求出现空的 --data。
 * 3. 路径与 query 拼接后再整体引号，保留攻击载荷的原样形态
 *    （URL 编码过的 query 已是日志里的原值，不重复编码）。
 */
export const buildCurlCommand = (log: WAFCurlLog): string => {
    const parts: string[] = ['curl', '-i', '-X', shellQuote(log.method || 'GET')];

    const path = log.path || '/';
    const query = log.query || '';
    const target = query ? `${path}?${query}` : path;
    // 没有站点名就退化成相对路径，至少 URL 结构是完整的。
    const url = log.websiteName ? `http://${log.websiteName}${target}` : target;
    parts.push(shellQuote(url));

    if (log.userAgent) {
        parts.push('-H', shellQuote(`User-Agent: ${log.userAgent}`));
    }
    if (log.requestBody) {
        parts.push('--data-raw', shellQuote(log.requestBody));
    }
    return parts.join(' ');
};

/** 耗时展示：后端可能给 0 或 undefined，都要显示成"0 毫秒"而不是空白。 */
export const formatDuration = (ms?: number | null): number => {
    const n = Number(ms);
    if (!Number.isFinite(n) || n < 0) return 0;
    return Math.round(n);
};

// ==================== 防护模式与拦截页 ====================

/**
 * 三种防护模式。value 必须与后端 model.WAFOption.Mode 的默认值
 * 以及 Lua access.lua 里判定的字面量完全一致 —— 拼错时 Lua 的判断
 * 静默走默认分支，界面上选了却没效果。
 */
export const WAF_MODES: { value: WAFMode; labelKey: string; descKey: string }[] = [
    { value: 'block', labelKey: 'website.wafModeBlock', descKey: 'website.wafModeBlockDesc' },
    { value: 'observe', labelKey: 'website.wafModeObserve', descKey: 'website.wafModeObserveDesc' },
    { value: 'maintenance', labelKey: 'website.wafModeMaintenance', descKey: 'website.wafModeMaintenanceDesc' },
];

/**
 * 15 类语义检测器。name 必须与 Lua semantic.lua 的 checks 数组键名
 * 以及 _M.attack_types 里的条目一致（含 exposure / sensitive_path
 * 这两个走独立分支的）。名字对不上 = 关不掉，且不报错。
 */
export const WAF_DETECTORS: { name: string; labelKey: string }[] = [
    { name: 'sqli', labelKey: 'website.wafDetectorSqli' },
    { name: 'xss', labelKey: 'website.wafDetectorXss' },
    { name: 'rce', labelKey: 'website.wafDetectorRce' },
    { name: 'lfi', labelKey: 'website.wafDetectorLfi' },
    { name: 'ssrf', labelKey: 'website.wafDetectorSsrf' },
    { name: 'upload', labelKey: 'website.wafDetectorUpload' },
    { name: 'log4shell', labelKey: 'website.wafDetectorLog4shell' },
    { name: 'code_injection', labelKey: 'website.wafDetectorCodeInjection' },
    { name: 'ssti', labelKey: 'website.wafDetectorSsti' },
    { name: 'deserialization', labelKey: 'website.wafDetectorDeserialization' },
    { name: 'xxe', labelKey: 'website.wafDetectorXxe' },
    { name: 'exposure', labelKey: 'website.wafDetectorExposure' },
    { name: 'prototype_pollution', labelKey: 'website.wafDetectorPrototypePollution' },
    { name: 'graphql', labelKey: 'website.wafDetectorGraphql' },
    { name: 'sensitive_path', labelKey: 'website.wafDetectorSensitivePath' },
];

/** 把后端的逗号分隔字符串解析成集合。空/空白/全空项 = 空集合。 */
export const parseDisabledDetectors = (raw?: string | null): Set<string> => {
    const out = new Set<string>();
    if (!raw) return out;
    for (const part of raw.split(',')) {
        const name = part.trim();
        if (name) out.add(name);
    }
    return out;
};

/** 反向：集合 → 逗号分隔字符串。空集合返回空串（后端据此走"全部启用"）。 */
export const formatDisabledDetectors = (names: Iterable<string>): string => {
    const kept = [...names].filter((n) => n.trim()).map((n) => n.trim());
    // 按 WAF_DETECTORS 的固定顺序输出：否则每次保存后列表顺序可能变化，
    // 用户 diff 配置时看不出真正改了什么。
    const order = new Map(WAF_DETECTORS.map((d, i) => [d.name, i]));
    kept.sort((a, b) => (order.get(a) ?? 999) - (order.get(b) ?? 999));
    return kept.join(',');
};

/** 非法颜色名/格式，用于在表单里提前拦住而非等后端。 */
export const isInvalidPageColor = (color: string): boolean => {
    const v = color.trim();
    if (v === '') return false;
    if (/^#[0-9a-fA-F]{6}$/.test(v)) return false;
    return !NAMED_PAGE_COLORS.includes(v.toLowerCase());
};

export const NAMED_PAGE_COLORS = ['black', 'white', 'red', 'orange', 'yellow', 'green', 'blue', 'gray', 'grey'];

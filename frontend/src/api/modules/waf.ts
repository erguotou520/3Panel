import http from '@/api';

export interface WAFRule {
    id?: number;
    name: string;
    scope: 'global' | 'site';
    websiteId?: number;
    priority?: number;
    matchType: string;
    matchValue: string;
    matchOp?: string;
    action: 'allow' | 'deny' | 'log';
    ttl?: number;
    enabled?: boolean;
    remark?: string;
    /** 白名单「加白时仍检测」：放行但继续检测，只记日志不拦截 */
    keepInspecting?: boolean;
    createdAt?: string;
}

export interface WAFLog {
    id: number;
    websiteId: number;
    websiteName: string;
    ruleId: string;
    ruleName: string;
    layer: string;
    attackType: string;
    action: string;
    ip: string;
    area: string;
    method: string;
    path: string;
    query: string;
    userAgent: string;
    detail: string;
    requestBody: string;
    durationMs: number;
    falsePositive: boolean;
    dispositionRemark: string;
    dispositionAt?: string;
    createdAt: string;
}

export interface WAFRuleReorder {
    /** 有序的规则 ID 列表，第一个优先级最高 */
    ids: number[];
}

export const reorderWAFRules = (req: WAFRuleReorder) => {
    return http.post('/waf/rules/reorder', req);
};

export interface WAFRuleSearch {
    scope?: string;
    websiteId?: number;
    action?: string;
    falsePositive?: boolean;
}

export interface WAFLogSearch {
    websiteId?: number;
    attackType?: string;
    ip?: string;
    action?: string;
    startTime?: number;
    endTime?: number;
    page?: number;
    pageSize?: number;
    order?: string;
    /** 排序列，取值见 waf-helpers 的 WAFLogSortKey（后端有白名单校验） */
    orderBy?: string;
    format?: string;
}

export interface WAFStat {
    attackType: { key: string; count: number }[];
    topIP: { key: string; count: number }[];
    trend: { key: string; count: number }[];
}

export interface WAFStatRequest extends WAFLogSearch {
    /** 时间粒度：day（默认）或 hour */
    trendGranularity?: 'day' | 'hour';
}

export const searchWAFRules = (req: WAFRuleSearch) => {
    return http.post<WAFRule[]>('/waf/rules/search', req);
};

export const createWAFRule = (req: WAFRule) => {
    return http.post('/waf/rules', req);
};

export const updateWAFRule = (req: WAFRule) => {
    return http.post('/waf/rules/update', req);
};

export const deleteWAFRule = (id: number) => {
    return http.delete(`/waf/rules/${id}`);
};

export const searchWAFLogs = (req: WAFLogSearch) => {
    return http.post<{ items: WAFLog[]; total: number }>(`/waf/logs/search`, req);
};

export const statWAFLogs = (req: WAFStatRequest) => {
    return http.post<WAFStat>(`/waf/logs/stat`, req);
};

export const exportWAFLogs = (req: WAFLogSearch) => {
    return http.postWithConfig(`/waf/logs/export`, req, { responseType: 'blob' });
};

export const createRuleFromWAFLog = (logId: number, action: string) => {
    return http.post(`/waf/logs/rule`, { logId, action });
};

export const markWAFFalsePositive = (logId: number, ttl = 86400, remark = '') => {
    return http.post(`/waf/logs/false-positive`, { logId, ttl, remark });
};

export interface WAFCCConfig {
    websiteId: number;
    limit: number;
    window: number;
    action: 'deny' | 'challenge' | 'log';
    byUri: boolean;
    enabled: boolean;
}

export const getWAFCCConfig = (websiteId: number) => {
    return http.get<WAFCCConfig>(`/waf/cc`, { websiteId });
};

export const updateWAFCCConfig = (req: WAFCCConfig) => {
    return http.post(`/waf/cc/update`, req);
};

/**
 * 站点级防护模式。取值必须与后端 model + Lua access.lua 的字面量一致：
 * 不一致时 Lua 的判断会静默走默认分支（block），界面上选了却没效果。
 */
export type WAFMode = 'block' | 'observe' | 'maintenance';

/**
 * 保护强度分档。取值必须与后端 model + Lua semantic.lua / bot.lua 一致：
 * 拼错时 Lua 会归一到 balanced，界面上选了却没效果。
 */
export type WAFProtectionLevel = 'off' | 'observe' | 'balanced' | 'high';

export interface WAFBlockPage {
    title: string;
    body: string;
    bgColor: string;
    textColor: string;
}

export interface WAFOption {
    websiteId: number;
    botEnabled: boolean;
    allowGoodBots: boolean;
    blockBadBots: boolean;
    probeEnabled: boolean;
    probeMaxURIs: number;
    probeWindow: number;
    probeMaxRPS: number;
    /** 防护模式：block 防护 / observe 观察 / maintenance 维护。空值按 block 处理 */
    mode?: WAFMode;
    blockPageTitle?: string;
    blockPageBody?: string;
    blockPageBgColor?: string;
    blockPageTextColor?: string;
    /** 被关闭的语义检测器名，逗号分隔。空 = 全部启用 */
    disabledDetectors?: string;
    /** 语义层强度：off / observe / balanced / high */
    semanticLevel?: WAFProtectionLevel;
    /** Bot 层强度：off / observe / balanced / high */
    botLevel?: WAFProtectionLevel;
}

export const getWAFOption = (websiteId: number) => {
    return http.get<WAFOption>(`/waf/option`, { websiteId });
};

export const updateWAFOption = (req: WAFOption) => {
    return http.post(`/waf/option/update`, req);
};

/** 通知渠道。取值必须与后端 constant/alert.go 里的常量一致 —— 大小写错了会被 oneof 校验拒绝。 */
export type WAFWebhookMethod = 'custom' | 'weCom' | 'dingTalk' | 'feiShu';

export interface WAFWebhookSetting {
    enable: boolean;
    method: WAFWebhookMethod;
    url: string;
}

export const getWAFWebhook = () => {
    return http.get<WAFWebhookSetting>(`/waf/webhook`);
};

export const updateWAFWebhook = (req: WAFWebhookSetting) => {
    return http.post(`/waf/webhook/update`, req);
};

export const operateWebsiteWAF = (websiteId: number, operate: 'enable' | 'disable') => {
    return http.post(`/waf/website/op`, { websiteId, operate });
};

// ==================== IP 黑名单订阅 ====================

export interface WAFIPListStatus {
    enabled: boolean;
    autoUpdate: boolean;
    intervalHours: number;
    /** 是否已成功下载过名单 */
    installed: boolean;
    sha256?: string;
    generatedAt?: string;
    countV4?: number;
    countV6?: number;
    size?: number;
    /** 最后一次成功下载所用的镜像 */
    source?: string;
    /** 制品超过 48h 未更新视为过期 */
    stale?: boolean;
    reportEnabled: boolean;
    reportUrl: string;
}

export interface WAFIPListUpdate {
    enabled: boolean;
    autoUpdate: boolean;
    intervalHours: number;
    reportEnabled: boolean;
    reportUrl: string;
}

export const getWAFIPListStatus = () => {
    return http.get<WAFIPListStatus>(`/waf/iplist`);
};

export const updateWAFIPListSetting = (req: WAFIPListUpdate) => {
    return http.post(`/waf/iplist/update`, req);
};

export const syncWAFIPList = () => {
    return http.post<{ changed: boolean; source?: string; error?: string; countV4?: number }>(`/waf/iplist/sync`);
};

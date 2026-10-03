<template>
    <div v-loading="loading">
        <el-card shadow="never">
            <div class="waf-header">
                <span>{{ $t('website.waf') }}</span>
                <el-switch v-model="enabled" @change="onToggle" />
            </div>
            <el-alert v-if="!enabled" :title="$t('website.wafDisabledTip')" type="info" :closable="false" />
        </el-card>

        <template v-if="enabled">
            <el-card shadow="never" class="mt-2">
                <template #header>
                    <div class="card-header">
                        <span>{{ $t('website.wafStat') }}</span>
                        <el-button link type="primary" @click="loadStat">{{ $t('commons.button.refresh') }}</el-button>
                    </div>
                </template>
                <!-- 概览数字先给结论，再给分布：三个 KPI 平铺一行，
                     趋势独占整行（时间维度需要宽度），类型与来源 IP 并排。 -->
                <div class="waf-kpi">
                    <div class="waf-kpi-item">
                        <span class="waf-kpi-value">{{ statTotal }}</span>
                        <span class="waf-kpi-label">{{ $t('website.wafStatTotal') }}</span>
                    </div>
                    <div class="waf-kpi-item">
                        <span class="waf-kpi-value">{{ stat.attackType?.length || 0 }}</span>
                        <span class="waf-kpi-label">{{ $t('website.wafAttackType') }}</span>
                    </div>
                    <div class="waf-kpi-item">
                        <span class="waf-kpi-value">{{ stat.topIP?.length || 0 }}</span>
                        <span class="waf-kpi-label">{{ $t('website.wafTopIP') }}</span>
                    </div>
                </div>

                <div class="waf-stat-trend">
                    <div class="waf-stat-title">{{ $t('website.wafTrend') }}</div>
                    <VCharts
                        v-if="stat.trend?.length"
                        type="line"
                        height="180px"
                        :option="trendOption"
                        class="waf-stat-chart"
                    />
                    <el-empty v-else :image-size="60" :description="$t('website.wafNoData')" />
                </div>

                <el-row :gutter="16" class="mt-3">
                    <el-col :xs="24" :md="12">
                        <div class="waf-stat-title">{{ $t('website.wafAttackType') }}</div>
                        <div v-if="stat.attackType?.length" class="waf-bars">
                            <div v-for="item in stat.attackType" :key="item.key" class="waf-bar-row">
                                <span class="waf-bar-name">{{ item.key || '-' }}</span>
                                <div class="waf-bar-track">
                                    <div class="waf-bar-fill" :style="{ width: barWidth(item.count) }" />
                                </div>
                                <span class="waf-bar-value">{{ item.count }}</span>
                            </div>
                        </div>
                        <el-empty v-else :image-size="60" :description="$t('website.wafNoData')" />
                    </el-col>
                    <el-col :xs="24" :md="12">
                        <div class="waf-stat-title">{{ $t('website.wafTopIP') }}</div>
                        <div v-if="stat.topIP?.length" class="waf-bars">
                            <div v-for="item in stat.topIP" :key="item.key" class="waf-bar-row">
                                <span class="waf-bar-name waf-bar-ip">{{ item.key }}</span>
                                <div class="waf-bar-track">
                                    <div class="waf-bar-fill waf-bar-fill-ip" :style="{ width: barWidth(item.count) }" />
                                </div>
                                <span class="waf-bar-value">{{ item.count }}</span>
                            </div>
                        </div>
                        <el-empty v-else :image-size="60" :description="$t('website.wafNoData')" />
                    </el-col>
                </el-row>
            </el-card>

            <el-card shadow="never" class="mt-2">
                <template #header>
                    <div class="card-header">
                        <span>CC {{ $t('website.wafProtect') }}</span>
                        <div class="flex items-center gap-3">
                            <el-switch v-model="cc.enabled" />
                            <el-button type="primary" plain :disabled="!cc.enabled" @click="saveCC">
                                {{ $t('commons.button.save') }}
                            </el-button>
                        </div>
                    </div>
                </template>
                <!-- 关闭时把阈值等参数置灰但保留取值：直接隐藏会让用户
                     重新开启后要再填一遍，配置也就无法"备而不用"。 -->
                <el-form label-width="120px" class="waf-cc-form">
                    <el-form-item :label="$t('website.wafCCLimit')">
                        <el-input-number v-model="cc.limit" :min="1" :disabled="!cc.enabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafCCWindow')">
                        <el-input-number v-model="cc.window" :min="1" :disabled="!cc.enabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafAction')">
                        <el-select v-model="cc.action" :disabled="!cc.enabled" class="p-w-150">
                            <el-option label="deny" value="deny" />
                            <el-option label="challenge" value="challenge" />
                            <el-option label="log" value="log" />
                        </el-select>
                    </el-form-item>
                    <el-form-item :label="$t('website.wafCCByUri')">
                        <el-switch v-model="cc.byUri" :disabled="!cc.enabled" />
                    </el-form-item>
                </el-form>
                <el-alert :title="$t('website.wafCCTip')" type="info" :closable="false" />
            </el-card>

            <el-card shadow="never" class="mt-2">
                <template #header>
                    <div class="card-header">
                        <span>{{ $t('website.wafBotProbe') }}</span>
                        <el-button type="primary" plain @click="saveOption">{{ $t('commons.button.save') }}</el-button>
                    </div>
                </template>
                <el-form label-width="180px">
                    <el-form-item :label="$t('website.wafBotEnable')">
                        <el-switch v-model="option.botEnabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafBotAllowGood')">
                        <el-switch v-model="option.allowGoodBots" :disabled="!option.botEnabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafBotBlockBad')">
                        <el-switch v-model="option.blockBadBots" :disabled="!option.botEnabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafProbeEnable')">
                        <el-switch v-model="option.probeEnabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafProbeMaxURIs')">
                        <el-input-number v-model="option.probeMaxURIs" :min="1" :disabled="!option.probeEnabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafProbeWindow')">
                        <el-input-number v-model="option.probeWindow" :min="10" :disabled="!option.probeEnabled" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafProbeMaxRPS')">
                        <el-input-number v-model="option.probeMaxRPS" :min="1" :disabled="!option.probeEnabled" />
                    </el-form-item>
                </el-form>
            </el-card>

            <el-card shadow="never" class="mt-2">
                <template #header>
                    <div class="card-header">
                        <span>{{ $t('website.wafRules') }}</span>
                        <el-button type="primary" plain @click="openRuleDialog()">
                            {{ $t('commons.button.create') }}
                        </el-button>
                    </div>
                </template>
                <el-table :data="rules">
                    <el-table-column prop="name" :label="$t('commons.table.name')" min-width="120" />
                    <el-table-column prop="scope" :label="$t('website.wafScope')" width="90" />
                    <el-table-column prop="matchType" :label="$t('website.wafMatchType')" width="100" />
                    <el-table-column
                        prop="matchValue"
                        :label="$t('website.wafMatchValue')"
                        min-width="160"
                        show-overflow-tooltip
                    />
                    <el-table-column prop="matchOp" :label="$t('website.wafMatchOp')" width="90" />
                    <el-table-column prop="action" :label="$t('website.wafAction')" width="90">
                        <template #default="{ row }">
                            <el-tag
                                :type="
                                    row.action === 'allow' ? 'success' : row.action === 'deny' ? 'danger' : 'warning'
                                "
                            >
                                {{ row.action }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column prop="enabled" :label="$t('commons.table.status')" width="80">
                        <template #default="{ row }">
                            <el-tag :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? 'on' : 'off' }}</el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column :label="$t('commons.table.operate')" width="140" fixed="right">
                        <template #default="{ row }">
                            <el-button link type="primary" @click="openRuleDialog(row)">
                                {{ $t('commons.button.edit') }}
                            </el-button>
                            <el-button link type="danger" @click="onDelRule(row)">
                                {{ $t('commons.button.delete') }}
                            </el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </el-card>

            <el-card shadow="never" class="mt-2">
                <template #header>
                    <div class="card-header">
                        <span>{{ $t('website.wafLogs') }}</span>
                        <div>
                            <el-button plain @click="onExport('csv')">CSV</el-button>
                            <el-button plain @click="onExport('json')">JSON</el-button>
                        </div>
                    </div>
                </template>
                <el-form inline class="mb-2">
                    <el-form-item :label="$t('website.wafAttackType')">
                        <el-input v-model="logReq.attackType" clearable class="p-w-150" />
                    </el-form-item>
                    <el-form-item label="IP">
                        <el-input v-model="logReq.ip" clearable class="p-w-150" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafAction')">
                        <el-select v-model="logReq.action" clearable class="p-w-120">
                            <el-option label="deny" value="deny" />
                            <el-option label="challenge" value="challenge" />
                            <el-option label="log" value="log" />
                        </el-select>
                    </el-form-item>
                    <el-form-item>
                        <el-date-picker
                            v-model="logTimeRange"
                            type="datetimerange"
                            range-separator="-"
                            :start-placeholder="$t('commons.search.timeStart')"
                            :end-placeholder="$t('commons.search.timeEnd')"
                        />
                    </el-form-item>
                    <el-form-item>
                        <el-button type="primary" @click="searchLogs">{{ $t('commons.button.search') }}</el-button>
                        <el-button @click="resetLogSearch">{{ $t('commons.button.reset') }}</el-button>
                    </el-form-item>
                </el-form>
                <el-table :data="logs">
                    <el-table-column type="expand" width="44">
                        <template #default="{ row }">
                            <el-descriptions :column="1" border class="m-2">
                                <el-descriptions-item label="Query">{{ row.query || '-' }}</el-descriptions-item>
                                <el-descriptions-item label="User-Agent">{{ row.userAgent || '-' }}</el-descriptions-item>
                                <el-descriptions-item :label="$t('website.wafDetail')">
                                    {{ row.detail || '-' }}
                                </el-descriptions-item>
                                <el-descriptions-item :label="$t('website.wafRequestBody')">
                                    {{ row.requestBody || '-' }}
                                </el-descriptions-item>
                            </el-descriptions>
                        </template>
                    </el-table-column>
                    <el-table-column prop="createdAt" :label="$t('commons.table.date')" width="170" />
                    <el-table-column prop="attackType" :label="$t('website.wafAttackType')" width="110" />
                    <el-table-column prop="action" :label="$t('website.wafAction')" width="80" />
                    <el-table-column prop="ip" label="IP" width="130" />
                    <el-table-column prop="area" label="GeoIP" width="140" show-overflow-tooltip />
                    <el-table-column prop="method" :label="$t('home.method')" width="80" />
                    <el-table-column prop="path" :label="$t('website.wafPath')" min-width="200" show-overflow-tooltip />
                    <el-table-column
                        prop="ruleName"
                        :label="$t('website.wafRuleName')"
                        width="130"
                        show-overflow-tooltip
                    />
                    <el-table-column :label="$t('commons.table.operate')" width="270" fixed="right">
                        <template #default="{ row }">
                            <el-button link type="primary" @click="onLogRule(row, 'allow')">
                                {{ $t('website.wafAddAllow') }}
                            </el-button>
                            <el-tag v-if="row.falsePositive" type="success" size="small">
                                {{ $t('website.wafFalsePositiveMarked') }}
                            </el-tag>
                            <el-button v-else link type="warning" @click="onFalsePositive(row)">
                                {{ $t('website.wafFalsePositive') }}
                            </el-button>
                        </template>
                    </el-table-column>
                </el-table>
                <el-pagination
                    class="mt-2"
                    layout="total, prev, pager, next"
                    :total="logTotal"
                    :page-size="logReq.pageSize"
                    v-model:current-page="logReq.page"
                    @current-change="loadLogs"
                />
            </el-card>
        </template>

        <RuleDialog ref="ruleDialogRef" @reload="loadRules" />
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import VCharts from '@/components/v-charts/index.vue';
import {
    deleteWAFRule,
    createRuleFromWAFLog,
    exportWAFLogs,
    getWAFCCConfig,
    getWAFOption,
    markWAFFalsePositive,
    operateWebsiteWAF,
    searchWAFLogs,
    searchWAFRules,
    statWAFLogs,
    updateWAFOption,
    updateWAFCCConfig,
} from '@/api/modules/waf';
import RuleDialog from './rule-dialog.vue';

const props = defineProps({ websiteId: { type: Number, default: 0 }, wafEnabled: { type: Boolean, default: false } });

const loading = ref(false);
const enabled = ref(props.wafEnabled);
const rules = ref<any[]>([]);
const logs = ref<any[]>([]);
const logTotal = ref(0);
const ruleDialogRef = ref();
const logReq = ref<any>({
    websiteId: props.websiteId,
    attackType: '',
    ip: '',
    action: '',
    page: 1,
    pageSize: 10,
});
const logTimeRange = ref<Date[]>([]);
const stat = ref<any>({ attackType: [], topIP: [], trend: [] });

// 三个分组各有自己的量级，KPI 的「拦截总数」用趋势之和而不是某一组的最大值，
// 否则「攻击类型 3 种」这种计数会被当成事件总数显示。
const statTotal = computed(() => (stat.value.trend || []).reduce((sum: number, item: any) => sum + (item.count || 0), 0));

const statMax = computed(() => {
    const counts = [...(stat.value.attackType || []), ...(stat.value.topIP || [])].map((item: any) => item.count || 0);
    return Math.max(1, ...counts);
});

const barWidth = (count: number) => `${Math.max(3, Math.round(((count || 0) / statMax.value) * 100))}%`;

const trendOption = computed(() => {
    const trend = stat.value.trend || [];
    return {
        grid: { left: 8, right: 16, top: 16, bottom: 8, containLabel: true },
        tooltip: { trigger: 'axis' },
        xAxis: {
            type: 'category',
            data: trend.map((item: any) => item.key),
            boundaryGap: false,
        },
        yAxis: { type: 'value', minInterval: 1 },
        series: [
            {
                type: 'line',
                smooth: true,
                showSymbol: false,
                data: trend.map((item: any) => item.count || 0),
            },
        ],
    };
});
const cc = ref<any>({ websiteId: props.websiteId, limit: 0, window: 60, action: 'deny', byUri: false, enabled: false });
const option = ref<any>({
    websiteId: props.websiteId,
    botEnabled: false,
    allowGoodBots: true,
    blockBadBots: true,
    probeEnabled: false,
    probeMaxURIs: 60,
    probeWindow: 60,
    probeMaxRPS: 120,
});

const loadRules = async () => {
    const res = await searchWAFRules({ websiteId: props.websiteId });
    rules.value = res.data || [];
};
const loadLogs = async () => {
    const res = await searchWAFLogs(logReq.value);
    logs.value = res.data?.items || [];
    logTotal.value = res.data?.total || 0;
};
const searchLogs = () => {
    logReq.value.page = 1;
    logReq.value.startTime = logTimeRange.value?.[0] ? Math.floor(new Date(logTimeRange.value[0]).getTime() / 1000) : 0;
    logReq.value.endTime = logTimeRange.value?.[1] ? Math.floor(new Date(logTimeRange.value[1]).getTime() / 1000) : 0;
    loadLogs();
};
const resetLogSearch = () => {
    logReq.value = { websiteId: props.websiteId, attackType: '', ip: '', action: '', page: 1, pageSize: 10 };
    logTimeRange.value = [];
    loadLogs();
};
const loadStat = async () => {
    const res = await statWAFLogs({ websiteId: props.websiteId });
    stat.value = res.data || { attackType: [], topIP: [], trend: [] };
};
const loadCC = async () => {
    const res = await getWAFCCConfig(props.websiteId);
    if (res.data) {
        cc.value = res.data;
    }
};
const saveCC = async () => {
    await updateWAFCCConfig({ ...cc.value, websiteId: props.websiteId });
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
};
const loadOption = async () => {
    const res = await getWAFOption(props.websiteId);
    if (res.data) {
        option.value = res.data;
    }
};
const saveOption = async () => {
    await updateWAFOption({ ...option.value, websiteId: props.websiteId });
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
};
const onToggle = async (val: any) => {
    loading.value = true;
    try {
        await operateWebsiteWAF(props.websiteId, val ? 'enable' : 'disable');
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        if (val) {
            await loadRules();
            await loadLogs();
            await loadStat();
            await loadCC();
            await loadOption();
        }
    } catch {
        enabled.value = !val;
    } finally {
        loading.value = false;
    }
};
const openRuleDialog = (rule?: any) => {
    ruleDialogRef.value.acceptParams({ websiteId: props.websiteId, rule: rule ? { ...rule } : null });
};
const onDelRule = (row: any) => {
    deleteWAFRule(row.id).then(() => {
        MsgSuccess(i18n.global.t('commons.msg.deleteSuccess'));
        loadRules();
    });
};
const onLogRule = (row: any, action: string) => {
    createRuleFromWAFLog(row.id, action).then(() => {
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        loadRules();
    });
};
const onFalsePositive = (row: any) => {
    markWAFFalsePositive(row.id).then(() => {
        MsgSuccess(i18n.global.t('website.wafFalsePositiveDone'));
        loadLogs();
        loadRules();
    });
};
const onExport = (format: string) => {
    exportWAFLogs({ ...logReq.value, format }).then((res) => {
        const blob = new Blob([res as any]);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `waf_logs.${format}`;
        a.click();
        window.URL.revokeObjectURL(url);
    });
};

onMounted(() => {
    if (props.wafEnabled) {
        loadRules();
        loadLogs();
        loadStat();
        loadCC();
        loadOption();
    }
});
</script>

<style scoped>
.waf-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.mt-2 {
    margin-top: 12px;
}
.mt-3 {
    margin-top: 16px;
}
/* KPI 平铺：先给结论，再给分布 */
.waf-kpi {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}
.waf-kpi-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 14px 16px;
    border: 1px solid var(--el-border-color-lighter);
    border-radius: 6px;
    background-color: var(--el-fill-color-blank);
}
.waf-kpi-value {
    font-size: 24px;
    font-weight: 600;
    line-height: 1.2;
}
.waf-kpi-label {
    font-size: 12px;
    color: var(--el-text-color-secondary);
}
.waf-stat-title {
    margin-bottom: 10px;
    font-size: 14px;
    font-weight: 600;
    color: var(--el-text-color-regular);
}
/* 横向条形：比一列 el-tag 更易比较大小，且长 IP 不会撑破布局 */
.waf-bars {
    display: flex;
    flex-direction: column;
    gap: 8px;
}
.waf-bar-row {
    display: flex;
    align-items: center;
    gap: 10px;
}
.waf-bar-name {
    flex: 0 0 96px;
    overflow: hidden;
    font-size: 13px;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.waf-bar-ip {
    flex-basis: 130px;
    font-family: monospace;
}
.waf-bar-track {
    flex: 1;
    height: 8px;
    overflow: hidden;
    border-radius: 4px;
    background-color: var(--el-fill-color);
}
.waf-bar-fill {
    height: 100%;
    border-radius: 4px;
    background-color: var(--el-color-danger);
}
.waf-bar-fill-ip {
    background-color: var(--el-color-primary);
}
.waf-bar-value {
    flex: 0 0 auto;
    min-width: 32px;
    font-size: 13px;
    text-align: right;
    color: var(--el-text-color-regular);
}
/* CC 表单：两列栅格而非 inline 顺排。inline 会在窄屏折行，
   折行后的标签宽度由 label-width 固定，视觉上就散了。 */
.waf-cc-form :deep(.el-form-item) {
    display: flex;
    align-items: center;
    margin-right: 32px;
}
</style>

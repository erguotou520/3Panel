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
                    </div>
                </template>
                <el-row :gutter="20">
                    <el-col :span="8">
                        <h5>{{ $t('website.wafAttackType') }}</h5>
                        <div v-for="item in stat.attackType" :key="item.key" class="stat-row">
                            <span>{{ item.key || '-' }}</span>
                            <el-tag type="danger" size="small">{{ item.count }}</el-tag>
                        </div>
                        <el-empty v-if="!stat.attackType?.length" :image-size="40" />
                    </el-col>
                    <el-col :span="8">
                        <h5>Top IP</h5>
                        <div v-for="item in stat.topIP" :key="item.key" class="stat-row">
                            <span>{{ item.key }}</span>
                            <el-tag size="small">{{ item.count }}</el-tag>
                        </div>
                        <el-empty v-if="!stat.topIP?.length" :image-size="40" />
                    </el-col>
                    <el-col :span="8">
                        <h5>{{ $t('website.wafTrend') }}</h5>
                        <div v-for="item in stat.trend" :key="item.key" class="stat-row">
                            <span>{{ item.key }}</span>
                            <el-tag type="warning" size="small">{{ item.count }}</el-tag>
                        </div>
                        <el-empty v-if="!stat.trend?.length" :image-size="40" />
                    </el-col>
                </el-row>
            </el-card>

            <el-card shadow="never" class="mt-2">
                <template #header>
                    <div class="card-header">
                        <span>CC {{ $t('website.wafProtect') }}</span>
                        <el-button type="primary" plain @click="saveCC">{{ $t('commons.button.save') }}</el-button>
                    </div>
                </template>
                <el-form label-width="140px" inline>
                    <el-form-item :label="$t('website.wafCCLimit')">
                        <el-input-number v-model="cc.limit" :min="0" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafCCWindow')">
                        <el-input-number v-model="cc.window" :min="1" />
                    </el-form-item>
                    <el-form-item :label="$t('website.wafAction')">
                        <el-select v-model="cc.action" style="width: 140px">
                            <el-option label="deny" value="deny" />
                            <el-option label="challenge" value="challenge" />
                            <el-option label="log" value="log" />
                        </el-select>
                    </el-form-item>
                    <el-form-item :label="$t('website.wafCCByUri')">
                        <el-switch v-model="cc.byUri" />
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
                        <el-button type="primary" plain @click="openRuleDialog()">{{ $t('commons.button.create') }}</el-button>
                    </div>
                </template>
                <el-table :data="rules">
                    <el-table-column prop="name" :label="$t('commons.table.name')" min-width="120" />
                    <el-table-column prop="scope" :label="$t('website.wafScope')" width="90" />
                    <el-table-column prop="matchType" :label="$t('website.wafMatchType')" width="100" />
                    <el-table-column prop="matchValue" :label="$t('website.wafMatchValue')" min-width="160" show-overflow-tooltip />
                    <el-table-column prop="matchOp" :label="$t('website.wafMatchOp')" width="90" />
                    <el-table-column prop="action" :label="$t('website.wafAction')" width="90">
                        <template #default="{ row }">
                            <el-tag :type="row.action === 'allow' ? 'success' : row.action === 'deny' ? 'danger' : 'warning'">
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
                            <el-button link type="primary" @click="openRuleDialog(row)">{{ $t('commons.button.edit') }}</el-button>
                            <el-button link type="danger" @click="onDelRule(row)">{{ $t('commons.button.delete') }}</el-button>
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
                <el-table :data="logs">
                    <el-table-column prop="createdAt" :label="$t('commons.table.date')" width="170" />
                    <el-table-column prop="attackType" :label="$t('website.wafAttackType')" width="110" />
                    <el-table-column prop="action" :label="$t('website.wafAction')" width="80" />
                    <el-table-column prop="ip" label="IP" width="130" />
                    <el-table-column prop="method" :label="$t('home.method')" width="80" />
                    <el-table-column prop="path" :label="$t('website.wafPath')" min-width="200" show-overflow-tooltip />
                    <el-table-column prop="ruleName" :label="$t('website.wafRuleName')" width="130" show-overflow-tooltip />
                    <el-table-column :label="$t('commons.table.operate')" width="160" fixed="right">
                        <template #default="{ row }">
                            <el-button link type="primary" @click="onLogRule(row, 'allow')">{{ $t('website.wafAddAllow') }}</el-button>
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
import { onMounted, ref } from 'vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { deleteWAFRule, createRuleFromWAFLog, exportWAFLogs, getWAFCCConfig, getWAFOption, operateWebsiteWAF, searchWAFLogs, searchWAFRules, statWAFLogs, updateWAFOption, updateWAFCCConfig } from '@/api/modules/waf';
import RuleDialog from './rule-dialog.vue';

const props = defineProps({ websiteId: { type: Number, default: 0 }, wafEnabled: { type: Boolean, default: false } });

const loading = ref(false);
const enabled = ref(props.wafEnabled);
const rules = ref<any[]>([]);
const logs = ref<any[]>([]);
const logTotal = ref(0);
const ruleDialogRef = ref();
const logReq = ref({ websiteId: props.websiteId, page: 1, pageSize: 10 });
const stat = ref<any>({ attackType: [], topIP: [], trend: [] });
const cc = ref<any>({ websiteId: props.websiteId, limit: 0, window: 60, action: 'deny', byUri: false, enabled: false });
const option = ref<any>({ websiteId: props.websiteId, botEnabled: false, allowGoodBots: true, blockBadBots: true, probeEnabled: false, probeMaxURIs: 60, probeWindow: 60, probeMaxRPS: 120 });

const loadRules = async () => {
    const res = await searchWAFRules({ websiteId: props.websiteId });
    rules.value = res.data || [];
};
const loadLogs = async () => {
    const res = await searchWAFLogs(logReq.value);
    logs.value = res.data?.items || [];
    logTotal.value = res.data?.total || 0;
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
</style>

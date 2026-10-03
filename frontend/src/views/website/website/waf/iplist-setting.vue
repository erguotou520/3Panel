<template>
    <div class="waf-iplist p-4">
        <el-card shadow="never" class="mb-4">
            <template #header>
                <div class="flex items-center justify-between">
                    <span>{{ $t('website.wafIPList') }}</span>
                    <el-button size="small" :loading="syncing" @click="onSync">
                        {{ $t('website.wafIPListSyncNow') }}
                    </el-button>
                </div>
            </template>

            <el-form label-width="180px">
                <el-form-item :label="$t('website.wafIPListEnabled')">
                    <el-switch v-model="form.enabled" @change="onSave" />
                    <span class="ml-3 text-gray-400 text-xs">{{ $t('website.wafIPListEnabledHint') }}</span>
                </el-form-item>
                <el-form-item :label="$t('website.wafIPListAutoUpdate')">
                    <el-switch v-model="form.autoUpdate" :disabled="!form.enabled" @change="onSave" />
                    <el-input-number
                        v-model="form.intervalHours"
                        :min="2"
                        :max="168"
                        :disabled="!form.enabled || !form.autoUpdate"
                        class="ml-3"
                        @change="onSave"
                    />
                    <span class="ml-2 text-gray-400 text-xs">{{ $t('website.wafIPListIntervalUnit') }}</span>
                </el-form-item>
            </el-form>
        </el-card>

        <el-card shadow="never" class="mb-4">
            <template #header>
                <span>{{ $t('website.wafIPListStatus') }}</span>
            </template>
            <el-descriptions :column="2" border v-loading="loading">
                <el-descriptions-item :label="$t('website.wafIPListInstalled')">
                    <el-tag :type="status.installed ? 'success' : 'info'">
                        {{ status.installed ? $t('website.wafIPListYes') : $t('website.wafIPListNo') }}
                    </el-tag>
                </el-descriptions-item>
                <el-descriptions-item :label="$t('website.wafIPListEntryCount')">
                    <template v-if="status.installed">
                        {{ (status.countV4 || 0) + (status.countV6 || 0) }}
                        <span class="text-gray-400 text-xs ml-2">
                            (v4 {{ status.countV4 || 0 }} / v6 {{ status.countV6 || 0 }})
                        </span>
                    </template>
                    <span v-else>-</span>
                </el-descriptions-item>
                <el-descriptions-item :label="$t('website.wafIPListGeneratedAt')">
                    <template v-if="status.installed">
                        {{ status.generatedAt }}
                        <el-tag v-if="status.stale" type="warning" size="small" class="ml-2">
                            {{ $t('website.wafIPListStale') }}
                        </el-tag>
                    </template>
                    <span v-else>-</span>
                </el-descriptions-item>
                <el-descriptions-item :label="$t('website.wafIPListSource')">
                    <span v-if="status.installed">{{ status.source || '-' }}</span>
                    <span v-else>-</span>
                </el-descriptions-item>
                <el-descriptions-item :label="$t('website.wafIPListSize')" :span="2">
                    <span v-if="status.installed">
                        {{ formatSize(status.size) }}
                        <span v-if="status.sha256" class="text-gray-400 text-xs ml-2">
                            sha256 {{ status.sha256.slice(0, 16) }}…
                        </span>
                    </span>
                    <span v-else>-</span>
                </el-descriptions-item>
            </el-descriptions>
        </el-card>

        <el-card shadow="never">
            <template #header>
                <span>{{ $t('website.wafReport') }}</span>
            </template>
            <el-alert type="info" :closable="false" class="mb-3">
                <template #title>{{ $t('website.wafReportPrivacy') }}</template>
            </el-alert>
            <!-- 上报地址由面板固定为社区 Worker，不做成可填字段：
                 可改地址等于允许把拦截事件（含来源 IP 与命中参数）投递到任意第三方。 -->
            <el-form label-width="180px">
                <el-form-item :label="$t('website.wafReportEnabled')">
                    <el-switch v-model="form.reportEnabled" @change="onSave" />
                    <span class="ml-3 text-gray-400 text-xs">{{ $t('website.wafReportUrlFixed') }}</span>
                </el-form-item>
            </el-form>
        </el-card>
    </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue';
import { getWAFIPListStatus, updateWAFIPListSetting, syncWAFIPList, type WAFIPListStatus } from '@/api/modules/waf';
import i18n from '@/lang';
import { MsgSuccess, MsgError, MsgWarning } from '@/utils/message';

// 制品体积在几百 KB 量级，KB 足够；避免为此引入额外工具函数。
const formatSize = (n?: number) => (n ? `${(n / 1024).toFixed(1)} KB` : '-');

const loading = ref(false);
const saving = ref(false);
const syncing = ref(false);

const form = reactive({
    enabled: false,
    autoUpdate: true,
    intervalHours: 12,
    reportEnabled: false,
});

const status = reactive<WAFIPListStatus>({
    enabled: false,
    autoUpdate: true,
    intervalHours: 12,
    installed: false,
    reportEnabled: false,
    reportUrl: '',
});

const load = async () => {
    loading.value = true;
    try {
        const data = (await getWAFIPListStatus()) as any;
        Object.assign(status, data);
        Object.assign(form, {
            enabled: !!data.enabled,
            autoUpdate: data.autoUpdate !== false,
            intervalHours: data.intervalHours || 12,
            reportEnabled: !!data.reportEnabled,
        });
    } catch (error) {
        MsgError(i18n.global.t('commons.msg.operationFailed'));
    } finally {
        loading.value = false;
    }
};

const onSave = async () => {
    saving.value = true;
    try {
        await updateWAFIPListSetting(form);
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await load();
    } catch (error) {
        MsgError(i18n.global.t('commons.msg.operationFailed'));
    } finally {
        saving.value = false;
    }
};

const onSync = async () => {
    syncing.value = true;
    try {
        const res = (await syncWAFIPList()) as any;
        const data = res?.data ?? res;
        if (data?.error) {
            // 拉取失败不是致命错误：本地旧数据继续生效。
            MsgWarning(`${i18n.global.t('website.wafIPListSyncFailed')}: ${data.error}`);
        } else if (data?.changed) {
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        } else {
            MsgSuccess(i18n.global.t('website.wafIPListSyncUpToDate'));
        }
        await load();
    } catch (error) {
        MsgError(`${i18n.global.t('website.wafIPListSyncFailed')}: ${error}`);
    } finally {
        syncing.value = false;
    }
};

onMounted(load);
</script>

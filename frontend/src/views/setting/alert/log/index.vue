<template>
    <div>
        <LayoutContent :title="$t('alert.logs')" v-loading="loading">
            <template #toolbar>
                <div class="flex justify-between gap-2 flex-wrap sm:flex-row">
                    <div class="flex flex-wrap gap-3">
                        <el-button v-permission type="primary" plain @click="onClean">
                            {{ $t('alert.cleanLog') }}
                        </el-button>
                    </div>
                </div>
            </template>
            <template #main>
                <ComplexTable :pagination-config="paginationConfig" :data="data" @search="search()">
                    <el-table-column :label="$t('alert.alertMsg')" prop="message" show-overflow-tooltip>
                        <template #default="{ row }">
                            {{ formatMessage(row.alertDetail) }}
                        </template>
                    </el-table-column>

                    <el-table-column
                        :label="$t('alert.alertMethod')"
                        prop="method"
                        width="200px"
                        show-overflow-tooltip
                    >
                        <template #default="{ row }">
                            {{ formatMethod(row) }}
                        </template>
                    </el-table-column>
                    <el-table-column
                        :label="$t('commons.table.status')"
                        fix
                        show-overflow-tooltip
                        prop="status"
                        width="150px"
                    >
                        <template #default="{ row }">
                            <el-tag
                                v-if="statusConfig(row)"
                                :type="statusConfig(row).type"
                                :link="statusConfig(row).link"
                            >
                                <el-tooltip v-if="row.message" :content="row.message" placement="top" trigger="click">
                                    {{ $t(statusConfig(row).text) }}
                                </el-tooltip>
                                <template v-else>
                                    {{ $t(statusConfig(row).text) }}
                                </template>
                            </el-tag>
                        </template>
                    </el-table-column>

                    <el-table-column
                        :label="$t('commons.table.createdAt')"
                        :formatter="dateFormat"
                        prop="createdAt"
                        width="180px"
                    ></el-table-column>

                    <el-table-column :label="$t('alert.sendCount')" prop="count" width="150px">
                        <template #default="{ row }">
                            {{ formatCount(row) }}
                        </template>
                    </el-table-column>
                </ComplexTable>
            </template>
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import { onMounted, reactive, ref } from 'vue';
import { dateFormat } from '@/utils/date';
import { MsgSuccess } from '@/utils/message';
import i18n from '@/lang';
import { Alert } from '@/api/interface/alert';
import { SearchAlertLogs, CleanAlertLogs, PageAlertConfigs } from '@/api/modules/alert';
import { ElMessageBox } from 'element-plus';
import { getAlertConfigDisplayName } from '@/views/setting/alert/setting/drawer/secret-field';

const { t } = i18n.global;
const loading = ref(false);
const data = ref();
const configMap = ref<Map<string, Alert.AlertConfigInfo>>(new Map());

const loadConfigMap = async () => {
    try {
        const res = await PageAlertConfigs({ page: 1, pageSize: 1000 });
        const map = new Map<string, Alert.AlertConfigInfo>();
        for (const c of res.data?.items || []) {
            map.set(String(c.id), c);
        }
        configMap.value = map;
    } catch {}
};
const resourceTypes = [
    'cpu',
    'memory',
    'load',
    'disk',
    'nodeException',
    'licenseException',
    'panelLogin',
    'sshLogin',
    'panelIpLogin',
    'sshIpLogin',
];
const paginationConfig = reactive({
    cacheSizeKey: 'alert-log-page-size',
    currentPage: 1,
    pageSize: Number(localStorage.getItem('alert-log-page-size')) || 20,
    total: 0,
});
const req = reactive({
    page: 1,
    pageSize: 10,
    total: 0,
    count: null,
    message: '',
    CreatedAt: '',
    status: '',
});

const statusMap = {
    PushSuccess: { type: 'success', text: 'alert.pushSuccess' },
    Pushing: { type: 'warning', text: 'alert.pushing' },
    Success: { type: 'success', text: 'alert.success' },
    Error: { type: 'danger', text: 'alert.error' },
    SyncError: { type: 'danger', text: 'alert.syncError', link: true },
    default: { type: 'danger', text: 'alert.pushError', link: true },
};

const statusConfig = (row) => {
    return statusMap[row.status] || statusMap['default'];
};

const formatMessage = (row: Alert.AlertInfo) => {
    const messageTemplates = {
        ssl: () => {
            return row.project === 'all' ? t('alert.allSslTitle') : t('alert.sslTitle', [row.project]);
        },
        siteEndTime: () => {
            return row.project === 'all'
                ? t('alert.allSiteEndTimeTitle')
                : t('alert.siteEndTimeTitle', [row.project]);
        },
        panelPwdEndTime: () => t('alert.panelPwdEndTimeTitle'),
        panelUpdate: () => t('alert.panelUpdateTitle'),
        cpu: () => t('alert.cpuTitle'),
        memory: () => t('alert.memoryTitle'),
        load: () => t('alert.loadTitle'),
        disk: () => {
            return row.project === 'all' ? t('alert.allDiskTitle') : t('alert.diskTitle', [row.project]);
        },
        clams: () => t('alert.clamsTitle', [row.project]),
        app: () => t('alert.cronJobAppTitle', [row.project]),
        website: () => t('alert.cronJobWebsiteTitle', [row.project]),
        database: () => t('alert.cronJobDatabaseTitle', [row.project]),
        directory: () => t('alert.cronJobDirectoryTitle', [row.project]),
        log: () => t('alert.cronJobLogTitle', [row.project]),
        snapshot: () => t('alert.cronJobSnapshotTitle', [row.project]),
        shell: () => t('alert.cronJobShellTitle', [row.project]),
        curl: () => t('alert.cronJobCurlTitle', [row.project]),
        cutWebsiteLog: () => t('alert.cronJobCutWebsiteLogTitle', [row.project]),
        clean: () => t('alert.cronJobCleanTitle', [row.project]),
        ntp: () => t('alert.cronJobNtpTitle', [row.project]),
        nodeException: () => t('alert.nodeException'),
        licenseException: () => t('alert.licenseException'),
        panelLogin: () => t('alert.panelLogin'),
        sshLogin: () => t('alert.sshLogin'),
        panelIpLogin: () => t('alert.panelIpLogin'),
        sshIpLogin: () => t('alert.sshIpLogin'),
    };
    let type = row.type === 'cronJob' ? row.subType : row.type;
    return messageTemplates[type] ? messageTemplates[type]() : '';
};

const formatMethod = (row: Alert.AlertLog) => {
    if (!row.method) return '-';

    const formatMethodPart = (method: string) => {
        const config = configMap.value.get(method);
        if (config) {
            const typeKey = config.type === 'email' ? 'mail' : config.type;
            const typeLabel = i18n.global.t('alert.' + typeKey);
            try {
                const cfg = JSON.parse(config.config || '{}') as Record<string, unknown>;
                const name = getAlertConfigDisplayName(config.type, cfg);
                return name ? `${name}(${typeLabel})` : typeLabel;
            } catch {
                return typeLabel;
            }
        }

        const invalidLabel = /^\d+$/.test(method)
            ? i18n.global.t('alert.methodInvalid', [`#${method}`])
            : i18n.global.t('alert.methodInvalid', [method]);
        switch (method) {
            case 'mail':
            case 'email':
                return t('alert.mail');
            case 'dingTalk':
                return t('alert.dingTalk');
            case 'weCom':
                return t('alert.weCom');
            case 'feiShu':
                return t('alert.feiShu');
            case 'wechat':
                return t('alert.wechat');
            case 'sms':
                return t('alert.sms');
            case 'webhook':
            case 'custom':
                return t('alert.custom');
            case 'bark':
                return t('alert.bark');
            default:
                return invalidLabel;
        }
    };

    return `「${row.method
        .split(',')
        .filter(Boolean)
        .map((item) => formatMethodPart(item.trim()))
        .join('｜')}」`;
};

const formatCount = (row: Alert.AlertInfo) => {
    return resourceTypes.includes(row.type) || row.type === 'cronJob' || row.type === 'clams'
        ? t('alert.daily', [row.count])
        : t('alert.cumulative', [row.count]);
};

const search = async () => {
    loading.value = true;
    if (req.status) {
        req.status = req.status.toLowerCase() === 'enable' ? 'Enable' : 'Disable';
    }
    let params = {
        page: paginationConfig.currentPage,
        pageSize: paginationConfig.pageSize,
        count: req.count,
        status: req.status,
    };
    try {
        const res = await SearchAlertLogs(params);
        data.value = res.data.items || [];
        paginationConfig.total = res.data.total || 0;
    } catch (error) {
    } finally {
        loading.value = false;
    }
};

const onClean = async () => {
    ElMessageBox.confirm(i18n.global.t('commons.msg.clean'), i18n.global.t('alert.cleanAlertLogs'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
        type: 'info',
    }).then(async () => {
        loading.value = true;
        await CleanAlertLogs()
            .then(() => {
                loading.value = false;
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
            })
            .catch(() => {
                loading.value = false;
            });
        await search();
    });
};

onMounted(async () => {
    await loadConfigMap();
    await search();
});
</script>

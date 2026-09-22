<template>
    <div v-loading="loading">
        <LayoutContent :title="$t('alert.list')" v-loading="loading">
            <template #prompt>
                <el-alert type="info" :closable="false" class="!mt-2">
                    <template #title>
                        {{ $t('alert.agentOfflineAlertHelper') }}
                    </template>
                </el-alert>
            </template>
            <template #leftToolBar>
                <el-button v-permission type="primary" @click="openView('create')">
                    {{ $t('alert.addTask') }}
                </el-button>
            </template>
            <template #rightToolBar>
                <div class="dropdowns">
                    <el-select filterable clearable v-model="req.type" @change="search()" class="!w-52 dropdown">
                        <template #prefix>{{ $t('commons.table.type') }}</template>
                        <template v-if="isMaster">
                            <el-option value="panelPwdEndTime" :label="$t('alert.panelPwdEndTime')" />
                            <el-option value="panelLogin" :label="$t('alert.panelLogin')" />
                            <el-option value="nodeException" :label="$t('alert.nodeException')" />
                            <el-option value="panelUpdate" :label="$t('alert.panelUpdate')" />
                        </template>
                        <el-option value="sshLogin" :label="$t('alert.sshLogin')" />
                        <el-option value="ssl" :label="$t('alert.ssl')" />
                        <el-option value="siteEndTime" :label="$t('alert.siteEndTime')" />
                        <el-option value="cpu" :label="$t('alert.cpu')" />
                        <el-option value="memory" :label="$t('alert.memory')" />
                        <el-option value="disk" :label="$t('alert.disk')" />
                        <el-option value="load" :label="$t('alert.load')" />
                        <el-option value="clams" :label="$t('alert.clams')" />
                        <el-option value="shell" :label="$t('alert.cronjob', [$t('cronjob.shell')])" />
                        <el-option value="app" :label="$t('alert.cronjob', [$t('cronjob.app')])" />
                        <el-option value="website" :label="$t('alert.cronjob', [$t('cronjob.website')])" />
                        <el-option value="database" :label="$t('alert.cronjob', [$t('cronjob.database')])" />
                        <el-option value="directory" :label="$t('alert.cronjob', [$t('cronjob.directory')])" />
                        <el-option value="log" :label="$t('alert.cronjob', [$t('cronjob.log')])" />
                        <el-option value="snapshot" :label="$t('alert.cronjob', [$t('cronjob.snapshot')])" />
                        <el-option value="curl" :label="$t('alert.cronjob', [$t('cronjob.curl')])" />
                        <el-option
                            value="cutWebsiteLog"
                            :label="$t('alert.cronjob', [$t('cronjob.cutWebsiteLog')])"
                        />
                        <el-option value="clean" :label="$t('alert.cronjob', [$t('cronjob.clean')])" />
                        <el-option value="ntp" :label="$t('alert.cronjob', [$t('cronjob.ntp')])" />
                    </el-select>
                    <el-select
                        clearable
                        filterable
                        v-model="req.status"
                        @change="search()"
                        @clear="search"
                        class="!w-52 dropdown"
                    >
                        <template #prefix>{{ $t('commons.table.status') }}</template>
                        <el-option :label="$t('commons.button.enable')" value="Enable"></el-option>
                        <el-option :label="$t('commons.button.disable')" value="Disable"></el-option>
                    </el-select>
                </div>
            </template>
            <template #main>
                <ComplexTable
                    :pagination-config="paginationConfig"
                    :data="data"
                    :height-diff="380"
                    @sort-change="changeSort"
                    @search="search()"
                >
                    <el-table-column
                        :label="$t('commons.table.title')"
                        prop="title"
                        min-width="300px"
                        show-overflow-tooltip
                    ></el-table-column>
                    <el-table-column :label="$t('commons.table.status')" prop="status" width="110px">
                        <template #default="{ row }">
                            <el-button
                                v-permission
                                v-if="row.status === 'Enable'"
                                @click="updateAlertStatus('disable', row.id)"
                                link
                                icon="VideoPlay"
                                type="success"
                            >
                                {{ $t('commons.status.enabled') }}
                            </el-button>
                            <el-button
                                v-permission
                                v-else
                                icon="VideoPause"
                                link
                                type="danger"
                                @click="updateAlertStatus('enable', row.id)"
                            >
                                {{ $t('commons.status.disabled') }}
                            </el-button>
                        </template>
                    </el-table-column>
                    <el-table-column
                        :label="$t('alert.alertMethod')"
                        prop="method"
                        width="200px"
                        show-overflow-tooltip
                    >
                        <template #default="{ row }">
                            <span v-if="row.method">{{ formatMethod(row) }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column
                        :label="$t('alert.alertRule')"
                        prop="rule"
                        min-width="300px"
                        show-overflow-tooltip
                    >
                        <template #default="{ row }">
                            {{ formatRule(row) }}
                        </template>
                    </el-table-column>
                    <fu-table-operations
                        :ellipsis="2"
                        width="130px"
                        :buttons="buttons"
                        :label="$t('commons.table.operate')"
                        :fixed="isMobile ? false : 'right'"
                        fix
                    />
                </ComplexTable>
            </template>
        </LayoutContent>
        <AddTask @search="search" ref="addTaskRef" />
    </div>
</template>

<script lang="ts" setup>
import { onMounted, reactive, ref } from 'vue';
import { useGlobalStore } from '@/composables/useGlobalStore';
import { getAlertConfigDisplayName } from '@/views/setting/alert/setting/drawer/secret-field';
import { MsgSuccess } from '@/utils/message';
import i18n from '@/lang';
import { ElMessageBox } from 'element-plus';
import AddTask from '@/views/setting/alert/dash/task/index.vue';
import { Alert } from '@/api/interface/alert';
import { UpdateAlertStatus, SearchAlerts, DeleteAlert, PageAlertConfigs } from '@/api/modules/alert';

const { isMobile, isMaster } = useGlobalStore();

const { t } = i18n.global;
const loading = ref(false);
const addTaskRef = ref();

const req = reactive({
    page: 1,
    pageSize: 10,
    total: 0,
    type: '',
    status: '',
    method: '',
});

const paginationConfig = reactive({
    cacheSizeKey: 'alert-list-page-size',
    currentPage: 1,
    pageSize: Number(localStorage.getItem('alert-list-page-size')) || 20,
    total: 0,
    orderBy: 'created_at',
    order: 'null',
});
const data = ref();

const buttons = [
    {
        label: i18n.global.t('commons.button.edit'),
        permission: true,
        click: function (row: Alert.AlertInfo) {
            openView('edit', row);
        },
    },
    {
        label: i18n.global.t('commons.button.delete'),
        permission: true,
        click: function (row: Alert.AlertInfo) {
            onDelete(row);
        },
    },
];

const openView = async (
    title: string,
    rowData: Partial<Alert.AlertInfo> = {
        type: isMaster.value ? 'panelPwdEndTime' : 'sshLogin',
        cycle: isMaster.value ? 15 : 30,
        count: isMaster.value ? 0 : 3,
        sendCount: 3,
        method: '',
        project: isMaster.value ? '' : 'all',
        status: 'Enable',
        title: '',
    },
) => {
    let params = {
        title,
        rowData: { ...rowData },
    };
    addTaskRef.value.acceptParams(params);
};

const changeSort = ({ prop, order }) => {
    if (order) {
        paginationConfig.orderBy = prop == 'status' ? 'status' : prop;
        paginationConfig.order = order;
    }
    search();
};

const formatRule = (row: Alert.AlertInfo) => {
    const ruleTemplates = {
        ssl: () => t('alert.timeRule', [row.cycle, row.sendCount]),
        siteEndTime: () => t('alert.timeRule', [row.cycle, row.sendCount]),
        panelPwdEndTime: () => t('alert.timeRule', [row.cycle, row.sendCount]),
        panelUpdate: () => t('alert.panelUpdateRule', [row.cycle, row.sendCount]),
        cpu: () => t('alert.avgRule', [row.cycle, t(`alert.${row.type}Name`), row.count, row.sendCount]),
        memory: () => t('alert.avgRule', [row.cycle, t(`alert.${row.type}Name`), row.count, row.sendCount]),
        load: () => t('alert.avgRule', [row.cycle, t(`alert.${row.type}Name`), row.count, row.sendCount]),
        disk: () => {
            return row.project === 'all'
                ? t('alert.allDiskRule', [row.count, row.cycle === 1 ? 'G' : '%', row.sendCount])
                : t('alert.diskRule', [row.project, row.count, row.cycle === 1 ? 'G' : '%', row.sendCount]);
        },
        clams: () => t('alert.clamsRule', [row.sendCount]),
        app: () => t('alert.cronJobAppRule', [row.sendCount]),
        website: () => t('alert.cronJobWebsiteRule', [row.sendCount]),
        database: () => t('alert.cronJobDatabaseRule', [row.sendCount]),
        directory: () => t('alert.cronJobDirectoryRule', [row.sendCount]),
        log: () => t('alert.cronJobLogRule', [row.sendCount]),
        snapshot: () => t('alert.cronJobSnapshotRule', [row.sendCount]),
        shell: () => t('alert.cronJobShellRule', [row.sendCount]),
        curl: () => t('alert.cronJobCurlRule', [row.sendCount]),
        cutWebsiteLog: () => t('alert.cronJobCutWebsiteLogRule', [row.sendCount]),
        clean: () => t('alert.cronJobCleanRule', [row.sendCount]),
        ntp: () => t('alert.cronJobNtpRule', [row.sendCount]),
        nodeException: () => t('alert.nodeExceptionRule', [row.sendCount]),
        licenseException: () => t('alert.licenseExceptionRule', [row.sendCount]),
        panelLogin: () => t('alert.panelLoginRule', [row.sendCount]),
        sshLogin: () => t('alert.sshLoginRule', [row.sendCount]),
    };

    return ruleTemplates[row.type] ? ruleTemplates[row.type]() : '';
};

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

const formatMethod = (row: Alert.AlertInfo) => {
    if (!row.method) return '';

    const resolveMethodLabel = (method: string) => {
        const config = configMap.value.get(method);
        if (config) {
            const typeLabel = i18n.global.t(`alert.${config.type === 'email' ? 'mail' : config.type}`);
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
        const oldLabel = i18n.global.t(`alert.${method}`);
        if (!oldLabel || oldLabel === `alert.${method}` || oldLabel.includes('.')) {
            return invalidLabel;
        }
        return oldLabel;
    };

    return `「${row.method
        .split(',')
        .filter(Boolean)
        .map((item) => resolveMethodLabel(item.trim()))
        .join('｜')}」`;
};

const search = async () => {
    if (req.status) {
        req.status = req.status.toLowerCase() === 'enable' ? 'Enable' : 'Disable';
    }
    loading.value = true;
    let params = {
        page: paginationConfig.currentPage,
        pageSize: paginationConfig.pageSize,
        type: req.type,
        status: req.status,
        method: req.method,
        orderBy: paginationConfig.orderBy,
        order: paginationConfig.order,
    };
    try {
        await loadConfigMap();
        const res = await SearchAlerts(params);
        data.value = res.data.items || [];
        paginationConfig.total = res.data.total || 0;
    } catch (error) {
    } finally {
        loading.value = false;
    }
};

const onDelete = (row: Alert.AlertInfo) => {
    ElMessageBox.confirm(i18n.global.t('alert.deleteMsg'), i18n.global.t('alert.deleteTitle'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
    }).then(async () => {
        await DeleteAlert({ id: row.id });
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await search();
    });
};

const updateAlertStatus = (status: string, id: number) => {
    ElMessageBox.confirm(i18n.global.t('alert.' + status + 'Msg'), i18n.global.t('alert.changeStatus'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
    }).then(async () => {
        let itemStatus = status.toLowerCase() === 'enable' ? 'Enable' : 'Disable';
        await UpdateAlertStatus({ id: id, status: itemStatus });
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await search();
    });
};

onMounted(() => {
    search();
});
</script>

<style lang="scss" scoped>
.dropdowns {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    flex: 1 1 auto;
    justify-content: flex-start;
}

.search-fields {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    flex: 1 1 auto;
    margin-top: 10px;
}

.el-tag {
    cursor: default;
}
</style>

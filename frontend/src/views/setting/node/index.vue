<template>
    <div>
        <LayoutContent v-loading="loading" :title="$t('xpack.node.nodeManagement')">
            <template #leftToolBar>
                <el-button type="primary" @click="onCreate()">
                    {{ $t('xpack.node.addNode') }}
                </el-button>
                <el-button type="primary" plain @click="onCheck()">
                    {{ $t('xpack.node.healthCheck') }}
                </el-button>
            </template>
            <template #rightToolBar>
                <TableSearch @search="search()" v-model:searchName="searchName" />
                <TableRefresh @search="search()" />
            </template>
            <template #main>
                <ComplexTable :data="data" @search="search">
                    <el-table-column
                        show-overflow-tooltip
                        :label="$t('xpack.node.nodeName')"
                        min-width="120"
                        prop="name"
                        fix
                    />
                    <el-table-column
                        show-overflow-tooltip
                        :label="$t('xpack.node.nodeAddr')"
                        min-width="140"
                        prop="addr"
                    />
                    <el-table-column :label="$t('xpack.node.nodeVersion')" min-width="100" prop="version" />
                    <el-table-column :label="$t('xpack.node.nodeStatus')" min-width="90" prop="status">
                        <template #default="{ row }">
                            <el-tag v-if="row.status === 'Online'" type="success">{{ row.status }}</el-tag>
                            <el-tag v-else type="info">{{ row.status }}</el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column
                        show-overflow-tooltip
                        :label="$t('xpack.node.nodeDescription')"
                        min-width="140"
                        prop="description"
                    />
                    <el-table-column :label="$t('commons.table.operate')" min-width="180" fix="right">
                        <template #default="{ row }">
                            <el-button
                                v-if="row.status === 'Online' && row.version !== panelVersion"
                                link
                                type="primary"
                                :loading="upgradingIDs.has(row.id)"
                                @click="onUpgrade(row)"
                            >
                                {{ $t('xpack.node.upgradeNode') }}
                            </el-button>
                            <el-button link type="danger" @click="onDelete(row)">
                                {{ $t('commons.button.delete') }}
                            </el-button>
                        </template>
                    </el-table-column>
                </ComplexTable>
            </template>
        </LayoutContent>

        <el-dialog
            v-model="createVisible"
            :title="$t('xpack.node.addNode')"
            width="560px"
            :close-on-click-modal="false"
        >
            <el-form ref="createFormRef" :model="createForm" :rules="createRules" label-width="100px">
                <el-form-item :label="$t('xpack.node.nodeName')" prop="name">
                    <el-input v-model="createForm.name" :placeholder="$t('xpack.node.nodeNameHelper')" />
                </el-form-item>
                <el-form-item :label="$t('xpack.node.nodeAddr')" prop="addr">
                    <el-input v-model="createForm.addr" :placeholder="$t('xpack.node.nodeAddrHelper')" />
                </el-form-item>
                <el-form-item :label="$t('xpack.node.nodeDescription')" prop="description">
                    <el-input v-model="createForm.description" type="textarea" :rows="2" />
                </el-form-item>
            </el-form>
            <template #footer>
                <el-button @click="createVisible = false">{{ $t('commons.button.cancel') }}</el-button>
                <el-button type="primary" :loading="creating" @click="submitCreate">
                    {{ $t('commons.button.confirm') }}
                </el-button>
            </template>
        </el-dialog>

        <el-dialog
            v-model="joinVisible"
            :title="$t('xpack.node.joinCommand')"
            width="700px"
            :close-on-click-modal="false"
        >
            <el-alert type="success" :title="$t('xpack.node.nodeCreated')" :closable="false" class="mb-3" />
            <div class="join-hint">{{ $t('xpack.node.joinCommandHelper') }}</div>
            <div class="join-cmd">{{ joinCommand }}</div>
            <div class="join-actions">
                <el-button type="primary" @click="copyText(joinCommand)">
                    {{ $t('xpack.node.copyCommand') }}
                </el-button>
                <span v-if="joinExpiredAt" class="join-expire">
                    {{ $t('xpack.node.joinTokenExpire', [joinExpiredAt]) }}
                </span>
            </div>
            <el-collapse>
                <el-collapse-item :title="$t('xpack.node.joinHasAgent')" name="agent">
                    <div class="join-hint">{{ $t('xpack.node.agentCommandHelper') }}</div>
                    <div class="join-cmd">{{ agentCommand }}</div>
                    <el-button plain size="small" class="mt-2" @click="copyText(agentCommand)">
                        {{ $t('xpack.node.copyCommand') }}
                    </el-button>
                </el-collapse-item>
            </el-collapse>
        </el-dialog>
    </div>
</template>

<script lang="ts" setup>
import { onBeforeUnmount, reactive, ref } from 'vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { copyText } from '@/utils/clipboard';
import { dateFormatSimpleWithSecond } from '@/utils/date';
import { Setting } from '@/api/interface/setting';
import {
    checkNodes,
    createNode,
    deleteNode,
    getSettingBaseInfo,
    searchNodes,
    upgradeNode,
} from '@/api/modules/setting';

const loading = ref(false);
const data = ref<Setting.NodeItem[]>([]);
const searchName = ref('');

const createVisible = ref(false);
const creating = ref(false);
const createFormRef = ref();
const createForm = reactive({ name: '', addr: '', description: '' });
const createRules = {
    name: [{ required: true, message: i18n.global.t('xpack.node.nodeNameHelper'), trigger: 'blur' }],
};

const joinVisible = ref(false);
const joinCommand = ref('');
const agentCommand = ref('');
const joinExpiredAt = ref('');

const panelVersion = ref('');
const upgradingIDs = reactive(new Set<number>());
const pollingTimers = new Set<number>();
const onUpgrade = async (row: Setting.NodeItem) => {
    upgradingIDs.add(row.id);
    try {
        const res = await upgradeNode(row.id);
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        pollUpgrade(row.id, res.data.version);
    } catch {
        upgradingIDs.delete(row.id);
    }
};

const pollUpgrade = (id: number, targetVersion: string, attempts = 0) => {
    const timer = window.setTimeout(async () => {
        pollingTimers.delete(timer);
        try {
            const res = await checkNodes();
            data.value = res.data || [];
            const node = data.value.find((item) => item.id === id);
            if (node?.version === targetVersion) {
                upgradingIDs.delete(id);
                return;
            }
        } catch {
            // The agent is expected to be briefly unavailable while restarting.
        }
        if (attempts < 59) pollUpgrade(id, targetVersion, attempts + 1);
        else upgradingIDs.delete(id);
    }, 5000);
    pollingTimers.add(timer);
};

const search = async () => {
    loading.value = true;
    try {
        const res = await searchNodes(searchName.value);
        data.value = res.data || [];
    } finally {
        loading.value = false;
    }
};

const onCheck = async () => {
    loading.value = true;
    try {
        const res = await checkNodes();
        data.value = res.data || [];
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    } catch {
        /* message already shown by interceptor */
    } finally {
        loading.value = false;
    }
};

const onCreate = () => {
    createForm.name = '';
    createForm.addr = '';
    createForm.description = '';
    createVisible.value = true;
};

const submitCreate = async () => {
    await createFormRef.value.validate();
    creating.value = true;
    try {
        const res = await createNode({
            name: createForm.name,
            addr: createForm.addr || undefined,
            description: createForm.description || undefined,
        });
        joinCommand.value = res.data.command;
        agentCommand.value = res.data.agentCommand;
        joinExpiredAt.value = res.data.expiredAt ? dateFormatSimpleWithSecond(res.data.expiredAt) : '';
        createVisible.value = false;
        joinVisible.value = true;
        search();
    } catch {
        /* message already shown by interceptor */
    } finally {
        creating.value = false;
    }
};

const onDelete = async (row: Setting.NodeItem) => {
    try {
        await ElMessageBox.confirm(
            i18n.global.t('xpack.node.deleteNodeConfirm', [row.name]),
            i18n.global.t('commons.button.delete'),
            { type: 'warning' },
        );
    } catch {
        return;
    }
    try {
        await deleteNode(row.id);
        MsgSuccess(i18n.global.t('xpack.node.nodeDeleted'));
        search();
    } catch {
        /* message already shown by interceptor */
    }
};

Promise.all([search(), getSettingBaseInfo().then((res) => (panelVersion.value = res.data.systemVersion))]);
onBeforeUnmount(() => pollingTimers.forEach((timer) => window.clearTimeout(timer)));
</script>

<style scoped>
.join-hint {
    margin-bottom: 10px;
    color: var(--el-text-color-regular);
    line-height: 1.6;
}

.join-cmd {
    padding: 12px;
    background: var(--panel-main-bg-color-10, #f5f5f5);
    border-radius: 4px;
    word-break: break-all;
    font-family: monospace;
    user-select: all;
}

.join-actions {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 12px;
}

.join-expire {
    color: var(--el-text-color-secondary);
    font-size: 12px;
    line-height: 1.4;
}
</style>

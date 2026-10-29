<template>
    <DrawerPro v-model="dialogVisible" :header="$t('terminal.addHost')" @close="handleClose" size="large">
        <el-form ref="hostRef" label-width="100px" label-position="top" :model="form" :rules="rules">
            <el-alert
                v-if="form.isLocal && !connDiag"
                class="common-prompt"
                center
                :title="$t('terminal.connLocalErr')"
                :closable="false"
                type="warning"
            />
            <el-alert
                v-if="form.isLocal && connDiag"
                class="common-prompt"
                center
                :title="connDiag"
                :closable="false"
                type="warning"
            />
            <el-form-item :label="$t('terminal.ip')" prop="addr">
                <el-input @change="isOK = false" clearable v-model.trim="form.addr" />
            </el-form-item>
            <el-form-item :label="$t('commons.login.username')" prop="user">
                <el-input @change="isOK = false" clearable v-model="form.user" />
            </el-form-item>
            <el-form-item :label="$t('terminal.authMode')" prop="authMode">
                <el-radio-group @change="isOK = false" v-model="form.authMode">
                    <el-radio value="password">{{ $t('terminal.passwordMode') }}</el-radio>
                    <el-radio value="key">{{ $t('terminal.keyMode') }}</el-radio>
                </el-radio-group>
            </el-form-item>
            <el-form-item :label="$t('commons.login.password')" v-if="form.authMode === 'password'" prop="password">
                <el-input @change="isOK = false" clearable show-password type="password" v-model="form.password" />
            </el-form-item>
            <el-form-item :label="$t('terminal.key')" v-if="form.authMode === 'key'" prop="privateKey">
                <el-input @change="isOK = false" clearable type="textarea" v-model="form.privateKey" />
            </el-form-item>
            <el-form-item :label="$t('terminal.keyPassword')" v-if="form.authMode === 'key'" prop="passPhrase">
                <el-input @change="isOK = false" type="password" show-password clearable v-model="form.passPhrase" />
            </el-form-item>
            <el-checkbox clearable v-model.number="form.rememberPassword">
                {{ $t('terminal.rememberPassword') }}
            </el-checkbox>
            <el-form-item class="mt-2.5" :label="$t('commons.table.port')" prop="port">
                <el-input @change="isOK = false" clearable v-model.number="form.port" />
            </el-form-item>
            <el-form-item v-if="!form.isLocal" :label="$t('commons.table.group')" prop="groupID">
                <el-select filterable v-model="form.groupID" clearable style="width: 100%">
                    <div v-for="item in groupList" :key="item.id">
                        <el-option
                            v-if="item.name === 'Default'"
                            :label="$t('commons.table.default')"
                            :value="item.id"
                        />
                        <el-option v-else :label="item.name" :value="item.id" />
                    </div>
                </el-select>
            </el-form-item>
            <el-form-item v-if="!form.isLocal" :label="$t('commons.table.title')" prop="name">
                <el-input clearable v-model="form.name" />
            </el-form-item>
            <el-form-item v-if="!form.isLocal" :label="$t('commons.table.description')" prop="description">
                <el-input clearable v-model="form.description" />
            </el-form-item>
        </el-form>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="dialogVisible = false">{{ $t('commons.button.cancel') }}</el-button>
                <el-button @click="submitAddHost(hostRef, 'testConn')">
                    {{ $t('terminal.testConn') }}
                </el-button>
                <el-button type="primary" :disabled="!isOK" @click="submitAddHost(hostRef, 'saveAndConn')">
                    {{ $t('terminal.saveAndConn') }}
                </el-button>
            </span>
        </template>
    </DrawerPro>
</template>

<script setup lang="ts">
import { ElForm } from 'element-plus';
import { Host } from '@/api/interface/host';
import { Rules } from '@/global/form-rules';
import { addHost, editHost, loadLocalConn, testByInfo } from '@/api/modules/terminal';
import i18n from '@/lang';
import { reactive, ref } from 'vue';
import { MsgError, MsgSuccess } from '@/utils/message';
import { decodeBase64 } from '@/utils/base64';
import { getAgentGroupList } from '@/api/modules/group';
import { useGlobalStore } from '@/composables/useGlobalStore';

const { currentNode } = useGlobalStore();
const targetNode = ref('local');

const dialogVisible = ref();
const isOK = ref(false);
// Reason provided by the backend (self-heal diag) for why the local ssh
// connection is not configured; shown above the form when non-empty.
const connDiag = ref('');
type FormInstance = InstanceType<typeof ElForm>;
const hostRef = ref<FormInstance>();

const groupList = ref();
const defaultGroup = ref();

let form = reactive<Host.HostOperate>({
    id: 0,
    name: '',
    groupID: 0,
    addr: '',
    port: 22,
    user: '',
    authMode: 'password',
    password: '',
    privateKey: '',
    passPhrase: '',
    rememberPassword: false,
    description: '',
    isLocal: false,
});

const rules = reactive({
    addr: [Rules.ipV4V6OrDomain],
    port: [Rules.requiredInput, Rules.port],
    user: [Rules.requiredInput],
    authMode: [Rules.requiredSelect],
    password: [Rules.requiredInput],
    privateKey: [Rules.requiredInput],
});

interface DialogProps {
    isLocal: boolean;
    nodeName?: string;
}
const acceptParams = (props: DialogProps) => {
    isOK.value = false;
    form.isLocal = props.isLocal;
    targetNode.value = props.isLocal ? props.nodeName || currentNode.value || 'local' : 'local';
    loadGroups();
    dialogVisible.value = true;
};

const handleClose = () => {
    dialogVisible.value = false;
};

const emit = defineEmits(['on-conn-terminal', 'on-new-local', 'load-host-tree']);

const loadGroups = async () => {
    const res = await getAgentGroupList('host', targetNode.value);
    groupList.value = res.data;
    for (const item of groupList.value) {
        if (item.isDefault) {
            defaultGroup.value = item.id;
            break;
        }
    }
    if (form.isLocal) {
        loadLocal();
    } else {
        setDefault();
    }
};
const loadLocal = async () => {
    connDiag.value = '';
    form.id = 0;
    form.addr = '127.0.0.1';
    form.port = 22;
    form.user = 'root';
    form.authMode = 'password';
    form.password = '';
    form.privateKey = '';
    form.passPhrase = '';
    form.rememberPassword = false;
    const res = await loadLocalConn();
    connDiag.value = res.data.diag || '';
    if (!res.data.addr) {
        return;
    }
    // The backend base64-encodes credential fields in this response.
    form.addr = res.data.addr;
    form.port = res.data.port;
    form.user = res.data.user;
    form.authMode = res.data.authMode;
    if (res.data.password) {
        form.password = decodeBase64(res.data.password);
    }
    if (res.data.privateKey) {
        form.privateKey = decodeBase64(res.data.privateKey);
    }
    if (res.data.passPhrase) {
        form.passPhrase = decodeBase64(res.data.passPhrase);
    }
};

const setDefault = () => {
    form.id = 0;
    form.addr = '';
    form.name = '';
    form.groupID = defaultGroup.value;
    form.port = 22;
    form.user = '';
    form.authMode = 'password';
    form.password = '';
    form.privateKey = '';
    form.passPhrase = '';
    form.rememberPassword = false;
    form.description = '';
};

const submitAddHost = (formEl: FormInstance | undefined, ops: string) => {
    if (!formEl) return;
    formEl.validate(async (valid) => {
        if (!valid) return;
        switch (ops) {
            case 'testConn':
                await testByInfo(form, targetNode.value).then((res) => {
                    if (res.data) {
                        isOK.value = true;
                        MsgSuccess(i18n.global.t('terminal.connTestOk'));
                    } else {
                        isOK.value = false;
                        MsgError(i18n.global.t('terminal.connTestFailed'));
                    }
                });
                break;
            case 'saveAndConn':
                let res;
                if (form.id == 0) {
                    res = await addHost(form, targetNode.value);
                } else {
                    res = await editHost(form);
                }
                dialogVisible.value = false;
                if (form.isLocal) {
                    // The backend cleared the diag on save; mirror it locally.
                    connDiag.value = '';
                    emit('on-new-local', targetNode.value);
                    emit('load-host-tree');
                    return;
                }
                let title = res.data.user + '@' + res.data.addr + ':' + res.data.port;
                if (res.data.name.length !== 0) {
                    title = res.data.name + '-' + title;
                }
                emit('on-conn-terminal', title, res.data.id);
                emit('load-host-tree');
                break;
        }
    });
};

defineExpose({
    acceptParams,
});
</script>

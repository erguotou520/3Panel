<template>
    <el-drawer
        v-model="drawerVisible"
        :title="isEdit ? $t('commons.button.edit') : $t('commons.button.create')"
        size="30%"
    >
        <el-form ref="formRef" label-position="top" :model="form">
            <el-form-item :label="$t('commons.table.name')" prop="name" :rules="rules.required">
                <el-input v-model="form.name" />
            </el-form-item>
            <el-form-item :label="$t('website.wafScope')">
                <el-radio-group v-model="form.scope">
                    <el-radio value="site">site</el-radio>
                    <el-radio value="global">global</el-radio>
                </el-radio-group>
            </el-form-item>
            <el-form-item :label="$t('website.wafMatchType')">
                <el-select v-model="form.matchType">
                    <el-option v-for="t in matchTypes" :key="t" :label="t" :value="t" />
                </el-select>
            </el-form-item>
            <el-form-item :label="$t('website.wafMatchOp')">
                <el-select v-model="form.matchOp">
                    <el-option v-for="t in matchOps" :key="t" :label="t" :value="t" />
                </el-select>
            </el-form-item>
            <el-form-item :label="$t('website.wafMatchValue')" prop="matchValue" :rules="rules.required">
                <el-input v-model="form.matchValue" type="textarea" :rows="2" />
            </el-form-item>
            <el-form-item :label="$t('website.wafAction')">
                <el-radio-group v-model="form.action">
                    <el-radio value="deny">deny</el-radio>
                    <el-radio value="allow">allow</el-radio>
                    <el-radio value="log">log</el-radio>
                </el-radio-group>
            </el-form-item>
            <el-form-item :label="$t('website.wafTTL')">
                <el-input-number v-model="form.ttl" :min="0" />
                <span class="ml-2">{{ $t('website.wafTTLTip') }}</span>
            </el-form-item>
            <el-form-item :label="$t('website.wafPriority')">
                <el-input-number v-model="form.priority" :min="1" :max="9999" />
            </el-form-item>
        </el-form>
        <template #footer>
            <el-button @click="drawerVisible = false">{{ $t('commons.button.cancel') }}</el-button>
            <el-button type="primary" @click="onSubmit">{{ $t('commons.button.confirm') }}</el-button>
        </template>
    </el-drawer>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { createWAFRule, updateWAFRule } from '@/api/modules/waf';

const drawerVisible = ref(false);
const isEdit = ref(false);
const formRef = ref();
const websiteId = ref(0);

const matchTypes = ['ip', 'cidr', 'path', 'ua', 'referer', 'header', 'cookie', 'method', 'expr'];
const matchOps = ['exact', 'contains', 'prefix', 'suffix', 'wildcard', 'regex'];

const form = reactive<any>({
    id: 0,
    name: '',
    scope: 'site',
    websiteId: 0,
    matchType: 'ip',
    matchValue: '',
    matchOp: 'exact',
    action: 'deny',
    ttl: 0,
    priority: 100,
    enabled: true,
});
const rules = reactive({
    required: [{ required: true, message: i18n.global.t('commons.inputRequired'), trigger: 'blur' }],
});

const acceptParams = (params: { websiteId: number; rule: any }) => {
    websiteId.value = params.websiteId;
    isEdit.value = !!params.rule;
    Object.assign(form, {
        id: params.rule?.id || 0,
        name: params.rule?.name || '',
        scope: params.rule?.scope || 'site',
        websiteId: params.rule?.websiteId || params.websiteId,
        matchType: params.rule?.matchType || 'ip',
        matchValue: params.rule?.matchValue || '',
        matchOp: params.rule?.matchOp || 'exact',
        action: params.rule?.action || 'deny',
        ttl: params.rule?.ttl || 0,
        priority: params.rule?.priority || 100,
        enabled: params.rule?.enabled ?? true,
    });
    drawerVisible.value = true;
};
const emit = defineEmits(['reload']);

const onSubmit = () => {
    formRef.value.validate(async (valid: boolean) => {
        if (!valid) return;
        if (form.scope === 'site') {
            form.websiteId = websiteId.value;
        }
        if (isEdit.value) {
            await updateWAFRule(form);
        } else {
            await createWAFRule(form);
        }
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        drawerVisible.value = false;
        emit('reload');
    });
};

defineExpose({ acceptParams });
</script>

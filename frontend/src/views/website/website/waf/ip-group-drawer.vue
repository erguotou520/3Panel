<template>
    <el-drawer
        v-model="visible"
        :title="isEdit ? $t('commons.button.edit') : $t('commons.button.create')"
        size="30%"
        @closed="onClosed"
    >
        <el-form ref="formRef" label-position="top" :model="form" :rules="rules">
            <el-form-item :label="$t('website.wafIPGroupName')" prop="name">
                <el-input v-model="form.name" :placeholder="$t('website.wafIPGroupNamePlaceholder')" />
                <div class="field-tip">{{ $t('website.wafIPGroupNameInvalid') }}</div>
            </el-form-item>
            <el-form-item :label="$t('website.wafIPGroupScope')">
                <el-radio-group v-model="form.scope">
                    <el-radio value="site">{{ $t('website.wafScopeSite') }}</el-radio>
                    <el-radio value="global">{{ $t('website.wafScopeGlobal') }}</el-radio>
                </el-radio-group>
            </el-form-item>
            <el-form-item :label="$t('website.wafIPGroupCIDRs')" prop="cidrs">
                <el-input
                    v-model="form.cidrs"
                    type="textarea"
                    :rows="10"
                    resize="vertical"
                    :placeholder="$t('website.wafIPGroupCIDRsPlaceholder')"
                />
                <div class="field-tip flex justify-between">
                    <span>{{ $t('website.wafIPGroupCIDRsTip') }}</span>
                    <span>已填 {{ countCIDRs(form.cidrs) }} 条</span>
                </div>
            </el-form-item>
            <el-form-item :label="$t('commons.table.status')">
                <el-switch v-model="form.enabled" />
                <span class="field-tip inline ml-2">关闭后该组不会导出到数据面，引用它的规则不会命中</span>
            </el-form-item>
        </el-form>
        <template #footer>
            <el-button @click="visible = false">{{ $t('commons.button.cancel') }}</el-button>
            <el-button type="primary" :loading="saving" @click="onSubmit">
                {{ $t('commons.button.confirm') }}
            </el-button>
        </template>
    </el-drawer>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { createWAFIPGroup, updateWAFIPGroup, WAF_IP_GROUP_NAME_PATTERN } from '@/api/modules/waf';

const emit = defineEmits(['reload']);

const visible = ref(false);
const saving = ref(false);
const isEdit = ref(false);
const formRef = ref();
const websiteId = ref(0);

const form = reactive<any>({
    id: null,
    name: '',
    scope: 'site',
    cidrs: '',
    enabled: true,
    remark: '',
});

// 组名会直接成为 rules.json 里的 map key，必须与后端 validateIPGroupName 完全一致。
const rules = computed(() => ({
    name: [
        { required: true, message: i18n.global.t('commons.rule.requiredInput'), trigger: 'blur' },
        {
            validator: (_r: unknown, value: string, cb: (e?: Error) => void) => {
                if (!value || !WAF_IP_GROUP_NAME_PATTERN.test(value)) {
                    cb(new Error(i18n.global.t('website.wafIPGroupNameInvalid')));
                    return;
                }
                cb();
            },
            trigger: 'blur',
        },
    ],
    cidrs: [{ required: true, message: i18n.global.t('commons.rule.requiredInput'), trigger: 'blur' }],
}));

const countCIDRs = (raw?: string): number => {
    if (!raw) return 0;
    return raw.split(/[\n\r,;\t ]+/).filter((v) => v.trim()).length;
};

const acceptParams = (params: { websiteId: number; group?: any }) => {
    websiteId.value = params.websiteId;
    isEdit.value = !!params.group;
    Object.assign(form, {
        id: params.group?.id ?? null,
        name: params.group?.name || '',
        scope: params.group?.scope || 'site',
        cidrs: params.group?.cidrs || '',
        enabled: params.group?.enabled ?? true,
        remark: params.group?.remark || '',
    });
    visible.value = true;
};

const onClosed = () => {
    formRef.value?.clearValidate();
};

const onSubmit = () => {
    formRef.value.validate(async (valid: boolean) => {
        if (!valid) return;
        saving.value = true;
        try {
            const payload = {
                name: form.name,
                scope: form.scope,
                websiteId: form.scope === 'site' ? websiteId.value : 0,
                enabled: form.enabled,
                remark: form.remark || '',
                cidrs: form.cidrs,
            };
            if (isEdit.value) {
                await updateWAFIPGroup({ ...payload, id: form.id });
            } else {
                await createWAFIPGroup(payload);
            }
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
            visible.value = false;
            emit('reload');
        } finally {
            saving.value = false;
        }
    });
};

defineExpose({ acceptParams });
</script>

<style scoped>
.field-tip {
    margin-top: 4px;
    font-size: 12px;
    line-height: 1.5;
    color: var(--el-text-color-secondary);
}
.field-tip.inline {
    margin-top: 0;
}
</style>

<template>
    <div>
        <el-card class="router_card p-1 sm:p-0">
            <div class="flex w-full flex-col justify-start sm:items-center items-start sm:justify-between sm:flex-row">
                <el-radio-group v-model="activeName" @change="handleChange">
                    <el-radio-button
                        class="router_card_button"
                        :label="button.label"
                        :value="button.label"
                        v-for="(button, index) in buttonArray"
                        size="large"
                        :key="index"
                    >
                        <el-badge :value="button.count" v-if="button.count" is-dot>
                            <span>{{ button.label }}</span>
                        </el-badge>
                    </el-radio-button>
                </el-radio-group>
                <div class="flex flex-col gap-2 sm:flex-row">
                    <slot name="route-button"></slot>
                </div>
            </div>
        </el-card>
        <div v-if="currentNodeVersionMismatch" class="mt-3 version-mismatch-alert">
            <el-alert type="warning" :closable="false" show-icon :title="$t('setting.currentNodeVersionNotSame')" />
            <el-button v-if="isAdmin" type="warning" plain @click="goToNodeManagement">
                {{ $t('xpack.node.upgradeNode') }}
            </el-button>
        </div>
    </div>
</template>

<script lang="ts" setup>
import { routerToNameWithQuery, routerToPathWithQuery } from '@/utils/router';
import { computed, onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';
import { hasPermissionMetaAccess, hasRouteAccess } from '@/utils/rbac';
import { useGlobalStore } from '@/composables/useGlobalStore';
import { getSettingBaseInfo } from '@/api/modules/setting';
import { changeToLocal, listNodes } from '@/utils/node';

defineOptions({ name: 'RouterButton' });

const props = defineProps({
    buttons: {
        type: Array<RouterButton>,
        required: true,
    },
});

const router = useRouter();
const { currentNode, isAdmin } = useGlobalStore();
const buttonArray = computed(() => {
    return props.buttons.filter((button) => {
        if (!hasPermissionMetaAccess(button.permission)) {
            return false;
        }
        if (button.path || button.name) {
            const route = router.resolve(button.path ? { path: button.path } : { name: button.name });
            return route.matched.length === 0 || hasRouteAccess(route);
        }
        return true;
    });
});

const activeName = ref('');
const currentNodeVersionMismatch = ref(false);
const goToNodeManagement = async () => {
    await changeToLocal();
    routerToNameWithQuery('SettingNode', { uncached: 'true' });
};

const handleChange = (label: string) => {
    const btn = buttonArray.value.find((btn) => btn.label === label);
    if (!btn) return;
    if (btn.path) routerToPathWithQuery(btn.path, { uncached: 'true' });
    else if (btn.name) routerToNameWithQuery(btn.name, { uncached: 'true' });
    activeName.value = btn.label;
};

onMounted(() => {
    syncActiveName();
});

watch(
    () => [router.currentRoute.value.path, buttonArray.value.map((button) => button.label).join('|')],
    () => {
        syncActiveName();
    },
);

// 多节点的版本一致性告警对所有部署都生效，不再要求已授权（原实现挂在 isXpackOrEE 上）。
watch([currentNode], checkCurrentNodeVersion, { immediate: true });

async function checkCurrentNodeVersion() {
    const checkedNode = currentNode.value;
    if (checkedNode === 'local') {
        currentNodeVersionMismatch.value = false;
        return;
    }

    try {
        const [settingRes, nodes] = await Promise.all([getSettingBaseInfo(), listNodes()]);
        if (currentNode.value !== checkedNode) {
            return;
        }
        const currentNodeInfo = nodes.find((item) => item.name === checkedNode);
        currentNodeVersionMismatch.value = Boolean(
            currentNodeInfo?.version &&
            settingRes.data.systemVersion &&
            currentNodeInfo.version !== settingRes.data.systemVersion,
        );
    } catch {
        if (currentNode.value === checkedNode) {
            currentNodeVersionMismatch.value = false;
        }
    }
}

function syncActiveName() {
    if (!buttonArray.value.length) {
        activeName.value = '';
        return;
    }
    if (buttonArray.value.length) {
        let isPathExist = false;
        const btn = buttonArray.value.find((btn) => {
            return btn.path && router.currentRoute.value.path.startsWith(btn.path);
        });
        if (btn) {
            isPathExist = true;
            activeName.value = btn.label;
        }
        if (!isPathExist) {
            activeName.value = buttonArray.value[0].label;
        }
    }
}
</script>

<style lang="scss" scoped>
.router_card {
    --el-card-padding: 0;

    :deep(.el-card__body) {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
}

.router_card_button {
    :deep(.el-radio-button__inner) {
        min-width: 100px;
        height: 100%;
        background-color: var(--panel-button-active) !important;
        box-shadow: none !important;
        outline: none !important;
        border: 2px solid transparent !important;
        color: var(--el-text-color-regular) !important;
    }

    :deep(.el-radio-button__original-radio:checked + .el-radio-button__inner) {
        color: var(--panel-button-text-color) !important;
        background-color: var(--panel-button-bg-color) !important;
        border-color: var(--panel-color-primary) !important;
        border-radius: 4px;
    }
}

.version-mismatch-alert {
    display: flex;
    align-items: center;
    gap: 12px;

    .el-alert {
        flex: 1;
    }
}
</style>

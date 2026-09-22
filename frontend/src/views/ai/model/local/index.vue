<template>
    <div>
        <div class="content-container__search">
            <el-card>
                <div>
                    <el-button
                        v-for="button in buttons"
                        :key="button.value"
                        class="tag-button"
                        :class="currentTab === button.value ? '' : 'no-active'"
                        :type="currentTab === button.value ? 'primary' : ''"
                        @click="handleChange(button.value)"
                    >
                        {{ button.label }}
                    </el-button>
                </div>
            </el-card>
        </div>
        <div class="local-model-content">
            <component :is="currentComponent" />
        </div>
    </div>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import OllamaView from '@/views/ai/model/ollama/index.vue';
import TensorRTView from '@/views/ai/model/tensorrt/index.vue';
import { useGlobalStore } from '@/composables/useGlobalStore';

type LocalTab = 'ollama' | 'tensorrt';

const route = useRoute();
const router = useRouter();
const { isFxplay } = useGlobalStore();

const tabLabels: Record<LocalTab, string> = {
    ollama: 'Ollama',
    tensorrt: 'TensorRT LLM',
};

const buttons = computed<Array<{ label: string; value: LocalTab }>>(() => {
    const items: Array<{ label: string; value: LocalTab }> = [{ label: tabLabels.ollama, value: 'ollama' }];
    if (isFxplay.value) {
        items.push({ label: tabLabels.tensorrt, value: 'tensorrt' });
    }
    return items;
});

const currentTab = computed<LocalTab>(() => {
    const tab = route.query.tab;
    if (tab === 'tensorrt' && isFxplay.value) {
        return tab;
    }
    if (tab === 'tensorrt') {
        return 'ollama';
    }
    return 'ollama';
});

const currentComponent = computed(() => {
    switch (currentTab.value) {
        case 'tensorrt':
            return TensorRTView;
        default:
            return OllamaView;
    }
});

const handleChange = async (target: LocalTab) => {
    await router.replace({
        path: '/ai/model/local',
        query: {
            ...route.query,
            tab: target,
        },
    });
};

watch(
    [() => route.query.tab, isFxplay],
    async ([tab, fxplay]) => {
        if (tab !== 'tensorrt' || fxplay) {
            return;
        }
        await router.replace({
            path: '/ai/model/local',
            query: {
                ...route.query,
                tab: 'ollama',
            },
        });
    },
    { immediate: true },
);
</script>

<style lang="scss" scoped>
.content-container__search {
    margin-top: 7px;

    :deep(.el-card) {
        --el-card-padding: 12px;
    }
}

.local-model-content {
    :deep(.content-container__app) {
        margin-top: 7px;
    }

    :deep(.content-container__main) {
        margin-top: 7px;
    }
}
</style>

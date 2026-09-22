<template>
    <div>
        <LayoutContent v-loading="loading" :title="$t('node.multiOverview')" back-name="Dashboard">
            <template #rightToolBar>
                <TableRefresh @search="search()" />
            </template>
            <template #main>
                <el-empty v-if="!loading && items.length === 0" :description="$t('node.nodeManagement')" />
                <el-row :gutter="16">
                    <el-col v-for="item in items" :key="item.name" :xs="24" :sm="12" :md="8" :lg="6">
                        <el-card class="node-card" shadow="hover">
                            <div class="card-header">
                                <span class="node-name">{{ item.name }}</span>
                                <el-tag :type="item.status === 'Online' ? 'success' : 'info'" size="small">
                                    {{ item.status === 'Online' ? $t('node.statusOn') : $t('node.statusOff') }}
                                </el-tag>
                            </div>
                            <div class="node-addr">{{ item.addr || '-' }}</div>
                            <template v-if="item.status === 'Online'">
                                <div class="metric">
                                    <span>CPU</span>
                                    <el-progress
                                        :percentage="Math.min(100, Math.round(item.cpuUsedPercent))"
                                        :stroke-width="8"
                                    />
                                </div>
                                <div class="metric">
                                    <span>Memory</span>
                                    <el-progress
                                        :percentage="Math.min(100, Math.round(item.memoryUsedPercent))"
                                        :stroke-width="8"
                                    />
                                </div>
                                <div class="node-version">{{ item.systemVersion }}</div>
                            </template>
                        </el-card>
                    </el-col>
                </el-row>
            </template>
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import { ref } from 'vue';
import { Setting } from '@/api/interface/setting';
import { listAllSimpleNodes } from '@/api/modules/setting';

const loading = ref(false);
const items = ref<Setting.SimpleNodeItem[]>([]);

const search = async () => {
    loading.value = true;
    try {
        const res = await listAllSimpleNodes();
        items.value = res.data || [];
    } finally {
        loading.value = false;
    }
};

search();
</script>

<style scoped lang="scss">
.node-card {
    margin-bottom: 16px;
    .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        .node-name {
            font-weight: 600;
            font-size: 15px;
        }
    }
    .node-addr {
        color: var(--el-text-color-secondary);
        font-size: 12px;
        margin: 4px 0 12px;
    }
    .metric {
        span {
            display: inline-block;
            width: 60px;
            font-size: 12px;
            color: var(--el-text-color-regular);
        }
        .el-progress {
            width: calc(100% - 64px);
            display: inline-flex;
        }
    }
    .node-version {
        margin-top: 8px;
        font-size: 12px;
        color: var(--el-text-color-secondary);
    }
}
</style>

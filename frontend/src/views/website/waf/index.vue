<template>
    <div>
        <LayoutContent :title="$t('website.waf')" v-loading="loading">
            <!-- 站点列表是 WAF 首页：先看哪些站点开了 WAF，再进入单站配置。
                 之前只有下拉框 + 开关，要逐个站点点进去才能知道开关状态。 -->
            <template #leftToolBar>
                <el-button v-if="view === 'config'" link @click="backToList">
                    {{ $t('website.wafBackToList') }}
                </el-button>
                <el-select
                    v-if="view === 'config' && showSitePicker"
                    v-model="websiteId"
                    filterable
                    class="p-w-300"
                    :placeholder="$t('menu.website')"
                    @change="selectWebsite"
                >
                    <el-option
                        v-for="website in websites"
                        :key="website.id"
                        :label="website.primaryDomain"
                        :value="website.id"
                    />
                </el-select>
            </template>
            <template #rightToolBar>
                <el-switch v-if="view === 'config' && showSitePicker" v-model="wafEnabled" @change="onToggleWAF" />
            </template>
            <template #main>
                <MainDiv :heightDiff="260">
                    <!-- 站点列表视图：域名 / 当前 WAF 状态 / 开关 / 进入配置 -->
                    <el-table v-if="view === 'list'" :data="websites" class="waf-site-table">
                        <el-table-column :label="$t('website.primaryDomain')" prop="primaryDomain" min-width="220" />
                        <el-table-column :label="$t('commons.table.status')" width="140">
                            <template #default="{ row }">
                                <el-tag :type="row.wafEnabled ? 'success' : 'info'">
                                    {{ row.wafEnabled ? $t('website.wafStatusOn') : $t('website.wafStatusOff') }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('website.wafSiteWafColumn')" width="160">
                            <template #default="{ row }">
                                <el-switch
                                    :model-value="!!row.wafEnabled"
                                    :disabled="!openRestyExist"
                                    @change="(val) => toggleSiteWAF(row, val as boolean)"
                                />
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('commons.table.operate')" width="140">
                            <template #default="{ row }">
                                <el-button link type="primary" @click="openConfig(row)">
                                    {{ $t('commons.button.set') }}
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>

                    <!-- 单站配置视图 -->
                    <template v-else>
                        <!-- 所有页签都在 WAF 组件内部（防护/黑白名单/IP 组/统计/日志/名单订阅），
                             这里不再套一层 el-tabs —— 两层页签会让「当前到底在哪一层」变得模糊。 -->
                        <Waf
                            v-if="openRestyExist && selectedWebsite"
                            :key="`${selectedWebsite.id}-${wafEnabled}`"
                            :website-id="selectedWebsite.id"
                            :waf-enabled="wafEnabled"
                            :show-i-p-list="true"
                            @tab-change="onTabChange"
                        />
                        <!-- 未安装 OpenResty 时只剩 IP 名单订阅可用 -->
                        <IPListSetting v-else-if="!loading" />
                    </template>
                </MainDiv>
            </template>
        </LayoutContent>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { listWebsites } from '@/api/modules/website';
import { checkAppInstalled } from '@/api/modules/app';
import { operateWebsiteWAF } from '@/api/modules/waf';
import { Website } from '@/api/interface/website';
import Waf from '@/views/website/website/waf/index.vue';
import IPListSetting from '@/views/website/website/waf/iplist-setting.vue';
import MainDiv from '@/components/main-div/index.vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';

const activeTab = ref('protect');
const openRestyExist = ref(false);
const loading = ref(false);

const websites = ref<Website.WebsiteDTO[]>([]);
const websiteId = ref(0);
const selectedWebsite = computed(() => websites.value.find((item) => item.id === websiteId.value));

// list = 站点开关总览；config = 单站防护配置
const view = ref<'list' | 'config'>('list');

// IP 名单订阅页签下不显示站点选择器与总开关
const showSitePicker = computed(() => openRestyExist.value && activeTab.value !== 'iplist');

const wafEnabled = ref(false);
const syncWafEnabled = () => {
    wafEnabled.value = !!selectedWebsite.value?.wafEnabled;
};

const reloadWebsites = async () => {
    const response = await listWebsites();
    websites.value = (response.data || []).filter((item) => item.type !== 'stream');
};
const selectWebsite = (id: number) => {
    websiteId.value = id;
    syncWafEnabled();
};
const openConfig = (website: Website.WebsiteDTO) => {
    websiteId.value = website.id;
    syncWafEnabled();
    view.value = 'config';
};
const backToList = () => {
    view.value = 'list';
};

// 站点列表里直接切换某个站点的 WAF，不必先进配置页
const toggleSiteWAF = async (website: Website.WebsiteDTO, val: boolean) => {
    try {
        await operateWebsiteWAF(website.id, val ? 'enable' : 'disable');
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    } catch {
        // 失败时保持列表不动，下面统一按服务端状态刷新
    }
    // 无论成功失败都以服务端状态为准刷新开关显示
    await reloadWebsites();
    if (website.id === websiteId.value) syncWafEnabled();
};

const onToggleWAF = async (val: boolean) => {
    if (!selectedWebsite.value) return;
    const id = selectedWebsite.value.id;
    try {
        await operateWebsiteWAF(id, val ? 'enable' : 'disable');
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await reloadWebsites();
        websiteId.value = id;
        syncWafEnabled();
    } catch {
        wafEnabled.value = !val;
    }
};

const onTabChange = (name: string) => {
    activeTab.value = name;
};

onMounted(async () => {
    loading.value = true;
    try {
        const [installed, response] = await Promise.all([
            checkAppInstalled('openresty', '').catch(() => null),
            listWebsites(),
        ]);
        openRestyExist.value = !!installed?.data;
        websites.value = (response.data || []).filter((item) => item.type !== 'stream');
        if (websites.value.length > 0) websiteId.value = websites.value[0].id;
        syncWafEnabled();
    } finally {
        loading.value = false;
    }
});
</script>

<style scoped>
.waf-site-table {
    width: 100%;
}
</style>

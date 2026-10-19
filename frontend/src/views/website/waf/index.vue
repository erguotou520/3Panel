<template>
    <div>
        <LayoutContent :title="$t('website.waf')" v-loading="loading">
            <!-- 站点选择器与总开关只在站点维度页签显示：
                 IP 名单订阅是全局配置，此时选中哪个站点都没有意义。 -->
            <template #leftToolBar>
                <el-select
                    v-if="showSitePicker"
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
                <el-switch v-if="showSitePicker" v-model="wafEnabled" @change="onToggleWAF" />
            </template>
            <template #main>
                <MainDiv :heightDiff="260">
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

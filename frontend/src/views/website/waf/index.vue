<template>
    <div>
        <RouterButton
            :buttons="[
                { label: $t('menu.website'), path: '/websites' },
                { label: 'WAF', path: '/websites/waf' },
            ]"
        />
        <LayoutContent :title="$t('website.waf')" v-loading="loading">
            <template #app>
                <!-- WAF 依附于 OpenResty 运行，未安装时给出安装引导而不是空页面 -->
                <AppStatus
                    app-key="openresty"
                    v-model:mask-show="maskShow"
                    v-model:loading="loading"
                    @is-exist="checkOpenResty"
                />
            </template>
            <template #leftToolBar>
                <el-select
                    v-if="activeTab === 'site' && openRestyExist"
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
            <template #main>
                <!-- IP 黑名单订阅是全局配置，不依赖 OpenResty，未安装时也可用 -->
                <el-tabs v-model="activeTab">
                    <!-- WAF 防护在前：它是这个页面的主功能，IP 名单订阅是附属配置 -->
                    <el-tab-pane v-if="openRestyExist" :label="$t('website.waf')" name="site">
                        <Waf
                            v-if="selectedWebsite"
                            :key="selectedWebsite.id"
                            :website-id="selectedWebsite.id"
                            :waf-enabled="selectedWebsite.wafEnabled"
                        />
                        <el-empty v-else :description="$t('menu.website')" />
                    </el-tab-pane>
                    <el-tab-pane :label="$t('website.wafIPList')" name="iplist">
                        <IPListSetting />
                    </el-tab-pane>
                </el-tabs>
            </template>
        </LayoutContent>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { listWebsites } from '@/api/modules/website';
import { Website } from '@/api/interface/website';
import Waf from '@/views/website/website/waf/index.vue';
import IPListSetting from '@/views/website/website/waf/iplist-setting.vue';
import AppStatus from '@/components/app-status/index.vue';

// 站点页签是站点级配置，IP 名单页签是全局配置 —— 两者混在一个页面，
// 页签切换时要把站点选择器一并收起来，否则会出现"选了站点但当前页用不上"。
// WAF 防护排在前面，因此默认停在它；未安装 OpenResty 时由 checkOpenResty
// 自动回落到 IP 名单页签 —— 站点级 WAF 此时无从谈起。
const activeTab = ref<'site' | 'iplist'>('site');
const openRestyExist = ref(false);
const maskShow = ref(false);
const loading = ref(false);

// AppStatus 在检测到应用存在/缺失时触发，这里只需记录状态。
const checkOpenResty = (exist: boolean) => {
    openRestyExist.value = exist;
    if (!exist && activeTab.value === 'site') {
        activeTab.value = 'iplist';
    }
};
const websites = ref<Website.WebsiteDTO[]>([]);
const websiteId = ref(0);
const selectedWebsite = computed(() => websites.value.find((item) => item.id === websiteId.value));

const selectWebsite = (id: number) => {
    websiteId.value = id;
};

onMounted(async () => {
    loading.value = true;
    try {
        const response = await listWebsites();
        websites.value = response.data.filter((item) => item.type !== 'stream');
        if (websites.value.length > 0) websiteId.value = websites.value[0].id;
    } finally {
        loading.value = false;
    }
});
</script>

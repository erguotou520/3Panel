<template>
    <div>
        <RouterButton
            :buttons="[
                { label: $t('menu.website'), path: '/websites' },
                { label: 'WAF', path: '/websites/waf' },
            ]"
        />
        <LayoutContent :title="$t('website.waf')" v-loading="loading">
            <template #leftToolBar>
                <el-select
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
                <Waf
                    v-if="selectedWebsite"
                    :key="selectedWebsite.id"
                    :website-id="selectedWebsite.id"
                    :waf-enabled="selectedWebsite.wafEnabled"
                />
                <el-empty v-else :description="$t('menu.website')" />
            </template>
        </LayoutContent>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { listWebsites } from '@/api/modules/website';
import { Website } from '@/api/interface/website';
import Waf from '@/views/website/website/waf/index.vue';

const loading = ref(false);
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

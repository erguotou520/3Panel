<template>
    <div>
        <LayoutContent v-loading="loading" :title="$t('setting.about')" :divider="true">
            <template #main>
                <div style="text-align: center; margin-top: 20px">
                    <div style="justify-self: center" class="logo">
                        <img
                            v-if="themeConfig.logo && !logoLoadFailed"
                            style="width: 80px"
                            :src="`/api/v2/images/logo?t=${Date.now()}`"
                            @error="logoLoadFailed = true"
                            alt=""
                        />
                        <PrimaryLogo v-else />
                    </div>
                    <h3 class="description">{{ themeConfig.title || $t('setting.description') }}</h3>
                    <div class="flex justify-center">
                        <SystemUpgrade class="upgrade" />
                    </div>
                    <div class="flex w-full justify-center my-5 flex-wrap md:flex-row gap-4">
                        <el-link @click="toDoc" class="system-link">
                            <el-icon><Document /></el-icon>
                            <span>{{ $t('setting.doc2') }}</span>
                        </el-link>
                        <el-link @click="toRepo" class="system-link">
                            <svg-icon iconName="p-huaban88"></svg-icon>
                            <span>{{ $t('setting.project') }}</span>
                        </el-link>
                        <el-link @click="toIssue" class="system-link">
                            <svg-icon iconName="p-bug"></svg-icon>
                            <span>{{ $t('setting.issue') }}</span>
                        </el-link>
                        <el-link @click="toRepoStar" class="system-link">
                            <svg-icon iconName="p-star"></svg-icon>
                            <span>{{ $t('setting.star') }}</span>
                        </el-link>
                    </div>
                </div>
            </template>
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import { getSystemAvailable } from '@/api/modules/setting';
import { onMounted, ref } from 'vue';
import SystemUpgrade from '@/components/system-upgrade/index.vue';
import { useGlobalStore } from '@/composables/useGlobalStore';
import PrimaryLogo from '@/assets/images/3panel-logo.svg?component';
const { docsUrl, themeConfig } = useGlobalStore();
const loading = ref();
const logoLoadFailed = ref(false);

// The upstream 3panel-dev/3panel links this page shipped with are dead (404);
// this deployment lives at cnb.cool. Keep the repo / issue / star entries but
// point them at the real project so they actually resolve.
const REPO_URL = 'https://cnb.cool/erguotou520/3panel';

const toDoc = () => {
    window.open(docsUrl.value.endsWith('/') ? docsUrl.value : `${docsUrl.value}/`, '_blank', 'noopener,noreferrer');
};
const toRepo = () => {
    window.open(REPO_URL, '_blank', 'noopener,noreferrer');
};
const toIssue = () => {
    window.open(`${REPO_URL}/-/issues`, '_blank', 'noopener,noreferrer');
};
const toRepoStar = () => {
    window.open(`${REPO_URL}/-/stargazers`, '_blank', 'noopener,noreferrer');
};

onMounted(() => {
    getSystemAvailable();
});
</script>

<style lang="scss" scoped>
.system-link {
    margin-left: 15px;

    .svg-icon {
        font-size: 7px;
    }
    span {
        line-height: 20px;
        font-weight: 400;
    }
}
.description {
    color: var(--el-text-color-regular);
}
.logo {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 55px;
    img {
        object-fit: contain;
        width: 95%;
        height: 45px;
    }
}
.upgrade {
    all: initial;
}
</style>

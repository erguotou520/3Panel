<template>
    <div v-if="visibleLinks.length" class="footer-navigation">
        <template v-for="(item, index) in visibleLinks" :key="item.key">
            <el-link type="primary" underline="never" @click="openLink(item.url)">
                <span class="font-normal">{{ $t(item.label) }}</span>
            </el-link>
            <el-divider v-if="index < visibleLinks.length - 1" direction="vertical" />
        </template>
        <el-divider class="footer-navigation__tail" direction="vertical" />
    </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useGlobalStore } from '@/composables/useGlobalStore';
import {
    createDefaultFooterNavigationLinks,
    footerNavigationKeys,
    isSafeExternalUrl,
    mergeFooterNavigationLinks,
} from './model';
import type { FooterNavigationKey } from './model';

const { docsUrl, isFxplay } = useGlobalStore();

const defaults = computed(() => createDefaultFooterNavigationLinks(docsUrl.value));
const links = computed(() => mergeFooterNavigationLinks(null, defaults.value));
const labels: Record<FooterNavigationKey, string> = {
    documentation: 'setting.doc2',
    project: 'setting.project',
};

const visibleLinks = computed(() => {
    return footerNavigationKeys
        .filter((key) => {
            if (isFxplay.value && key !== 'documentation') {
                return false;
            }
            return links.value[key].visible;
        })
        .map((key) => ({
            key,
            label: labels[key],
            url: links.value[key].url,
        }));
});

const openLink = (url: string) => {
    if (!isSafeExternalUrl(url)) {
        return;
    }
    window.open(url, '_blank', 'noopener,noreferrer');
};
</script>

<style scoped lang="scss">
.footer-navigation {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    row-gap: 8px;
}

:deep(.el-link__inner) {
    font-weight: 400;
}

@media (max-width: 767px) {
    .footer-navigation {
        column-gap: 12px;
        justify-content: center;
    }

    .footer-navigation :deep(.el-divider--vertical) {
        display: none;
    }
}
</style>

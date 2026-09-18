<template>
    <div>
        <RouterButton :buttons="buttons" />
        <LayoutContent>
            <RouterViewCache />
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import { computed } from 'vue';
import i18n from '@/lang';
import { useGlobalStore } from '@/composables/useGlobalStore';
// 本仓库是自托管的 GPLv3 分支，没有官方许可证服务：设置里的许可证模块已整体移除
// （RouterButton 入口 + /settings/license 路由 + views/setting/license/ 页面文件）。
// 注意 /enterprise/license-required 必须保留 —— api/index.ts 的 402 拦截器拿它当兜底页。
const { globalStore, isFxplay, isAdmin } = useGlobalStore();

const buttons = computed<RouterButton[]>(() => {
    const items = [
        ...(isAdmin.value
            ? [
                  {
                      label: i18n.global.t('setting.panel'),
                      path: '/settings/panel',
                  },
                  {
                      label: i18n.global.t('setting.safe'),
                      path: '/settings/safe',
                  },
              ]
            : []),
        ...(globalStore.hasPermission('alert_view')
            ? [
                  {
                      label: i18n.global.t('xpack.alert.alertNotice'),
                      path: '/settings/alert',
                      permission: 'alert_view',
                  },
              ]
            : []),
        ...(globalStore.hasPermission('backup_view')
            ? [
                  {
                      label: i18n.global.t('setting.backupAccount', 2),
                      path: '/settings/backupaccount',
                      permission: 'backup_view',
                  },
              ]
            : []),
        ...(isAdmin.value
            ? [
                  {
                      label: i18n.global.t('setting.snapshot', 2),
                      path: '/settings/snapshot',
                  },
                  {
                      label: i18n.global.t('xpack.node.nodeManagement'),
                      path: '/settings/node',
                  },
              ]
            : []),
        ...(isFxplay.value
            ? []
            : [
                  {
                      label: i18n.global.t('setting.about'),
                      path: '/settings/about',
                  },
              ]),
    ];
    return items;
});
</script>

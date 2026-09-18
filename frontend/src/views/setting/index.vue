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
// 「许可证」入口已移除：本仓库是自托管的 GPLv3 分支，没有官方许可证服务，
// 该 tab 只会指向不可用的 /settings/license（企业版路径 /enterprise/license 更是未注册）。
// 路由与页面文件保留，避免 views/ai/model/vllm 的 routerToName('License') 失效。
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

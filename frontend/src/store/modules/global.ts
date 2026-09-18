import { defineStore } from 'pinia';
import type { StoreDefinition } from 'pinia';
import piniaPersistConfig from '@/config/pinia-persist';
import { GlobalState } from '../interface';
import { DeviceType } from '@/enums/app';
import i18n, { setActiveLocale } from '@/lang';
import { isMasterOnlyPermissionCode, setMasterOnlyPermissionCodes, toManageCode } from '@/utils/permission-codes';
import { clearPageStateCache } from '@/utils/page-state-cache';

// 使用手册直接指向上游 1Panel 官方文档：3Panel 是 1Panel 的分支，
// 各页面「使用手册」深链（/user_manual/...）用的都是上游文档的路径结构，
// 自建文档站（3panel.erguotou.me/docs/v2）实测 404，因此这里指回上游。
const CN_DOCS_URL = 'https://1panel.cn/docs/v2';
const INTL_DOCS_URL = 'https://1panel.pro/docs/v2';

const GlobalStore = defineStore('GlobalState', {
    state: (): GlobalState => ({
        language: i18n.global.locale.value,
        device: DeviceType.Desktop,
        themeConfig: {
            panelName: '',
            primary: '#005eeb',
            theme: 'auto',
            footer: true,
            themeColor: '',
            title: '',
            logo: '',
            logoWithText: '',
            favicon: '',
            loginImage: '',
            loginBackground: '',
            loginBgType: '',
            loginBtnLinkColor: '',
        },
        // ui
        isFullScreen: false,
        openMenuTabs: false,
        menuAccordion: false,
        watermark: null,
        watermarkShow: false,
        isLoading: false,
        loadingText: '',
        csrfToken: '',
        // auth
        ignoreCaptcha: true,
        agreeLicense: false,
        isLogin: false,
        entrance: '',
        // context
        hasNewVersion: false,
        lastFilePath: '',
        currentDB: '',
        currentPgDB: '',
        currentRedisDB: '',
        currentMongodbDB: '',
        showEntranceWarn: true,
        defaultNetwork: 'all',
        defaultIO: 'all',
        isOnRestart: false,
        // tags
        isAdmin: false,
        permissions: [],
        masterOnlyPermissions: [],
        nodeRoles: [],
        isEnterprise: false,
        isIntl: false,
        docWithRegion: true,
        isFxplay: false,
        isOffline: false,
        // license
        isProductPro: false,
        productProExpires: 0,
        isMasterProductPro: false,
        isEnterpriseLicensed: false,
        isEnterpriseLicenseLoaded: false,
        // multi-node
        masterAlias: '',
        currentNode: 'local',
        currentNodeAddr: '',
    }),
    getters: {
        isDarkTheme: (state) =>
            state.themeConfig.theme === 'dark' ||
            (state.themeConfig.theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches),
        isDarkGoldTheme: (state) => state.themeConfig.primary === '#F0BE96' && state.isProductPro,
        isNodeAdmin: (state) =>
            state.nodeRoles.some((item) => item.nodeName === state.currentNode && item.roleName === 'Node Admin'),
        isAdminOrNodeAdmin: (state) =>
            state.isAdmin ||
            state.nodeRoles.some((item) => item.nodeName === state.currentNode && item.roleName === 'Node Admin'),
        docsUrl: (state) => {
            if (state.docWithRegion) {
                return state.isIntl ? INTL_DOCS_URL : CN_DOCS_URL;
            }
            const lang = state.language.toLowerCase();
            const isChinese = lang === 'zh';
            return isChinese ? CN_DOCS_URL : INTL_DOCS_URL;
        },
        isMaster: (state) => state.currentNode === 'local',
        isMobile: (state) => state.device === DeviceType.Mobile,

        isXpackOrEE: (state) => {
            return (state.isEnterprise && state.isEnterpriseLicensed) || state.isMasterProductPro;
        },
        isEE: (state) => state.isEnterprise && state.isEnterpriseLicensed,
        isMasterPro: (state) => state.isMasterProductPro,
        // Managing several nodes is a core 3Panel feature rather than a paid
        // add-on, so the node switcher is always available. Enterprise gating
        // stays on the license UI where it belongs.
        isMultiNode: () => true,
    },
    actions: {
        setScreenFull() {
            this.isFullScreen = !this.isFullScreen;
        },
        setLogStatus(login: boolean) {
            this.isLogin = login;
        },
        setAuthInfo(payload: {
            isAdmin: boolean;
            permissions: string[];
            masterOnlyPermissions?: string[];
            nodeRoles?: Array<{ nodeId: number; nodeName: string; roleId: number; roleName: string }>;
        }) {
            this.isAdmin = !!payload.isAdmin;
            this.permissions = payload.permissions || [];
            this.masterOnlyPermissions = payload.masterOnlyPermissions || [];
            this.nodeRoles = payload.nodeRoles || [];
            setMasterOnlyPermissionCodes(this.masterOnlyPermissions);
        },
        clearAuthInfo() {
            clearPageStateCache();
            this.permissions = [];
            this.masterOnlyPermissions = [];
            this.nodeRoles = [];
            this.isAdmin = false;
            setMasterOnlyPermissionCodes([]);
        },
        hasPermission(permission: string) {
            setMasterOnlyPermissionCodes(this.masterOnlyPermissions);
            const normalizedPermission = permission.trim();
            if (!normalizedPermission) {
                return false;
            }
            if (!this.isMaster && isMasterOnlyPermissionCode(normalizedPermission)) {
                return false;
            }
            if (this.isAdmin) {
                return true;
            }
            if (this.permissions.includes(normalizedPermission)) {
                return true;
            }
            const managePermission = toManageCode(normalizedPermission);
            if (!managePermission) {
                return false;
            }
            if (!this.isMaster && isMasterOnlyPermissionCode(managePermission)) {
                return false;
            }
            return this.permissions.includes(managePermission);
        },
        async updateLanguage(language: string) {
            const activeLocale = await setActiveLocale(language);
            this.language = activeLocale;
            return activeLocale;
        },
        toggleDevice(value: DeviceType) {
            this.device = value;
        },
        getMasterAlias() {
            return this.masterAlias || i18n.global.t('xpack.node.master');
        },
    },
    persist: piniaPersistConfig('GlobalState'),
}) as StoreDefinition<'GlobalState', GlobalState, any, any>;

export default GlobalStore;

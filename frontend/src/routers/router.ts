import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router';
import { getXpackRoutes } from '@/extensions/routes';
import { Layout } from '@/routers/constant';

type AppRouteRecord = RouteRecordRaw & { sort?: number };
type RouteModuleMap = Record<string, { default?: AppRouteRecord }>;

let modules = import.meta.glob('./modules/*.ts', { eager: true }) as RouteModuleMap;
const xpackModules = getXpackRoutes(modules);
modules = { ...modules, ...xpackModules };

const homeRouter: RouteRecordRaw = {
    path: '/',
    name: 'Home-Menu',
    component: Layout,
    redirect: '/',
    meta: {
        title: 'menu.home',
        icon: 'p-home',
    },
    children: [
        {
            path: '/',
            name: 'home',
            component: () => import('@/views/home/index.vue'),
        },
        {
            path: '/node-dashboard',
            name: 'NodeDashboard',
            component: () => import('@/views/home/node-dashboard/index.vue'),
            hidden: true,
            meta: {
                title: 'xpack.node.multiOverview',
                activeMenu: '/',
            },
        },
    ],
};

export const routerArray: RouteRecordRaw[] = [];

export const rolesRoutes = [
    ...(
        Object.keys(modules)
            .map((key) => modules[key]['default'])
            .filter(Boolean) as AppRouteRecord[]
    ).sort((r1, r2) => {
        r1.sort ??= Number.MAX_VALUE;
        r2.sort ??= Number.MAX_VALUE;
        return r1.sort - r2.sort;
    }),
];

rolesRoutes.forEach((item) => {
    const menu = item as RouteRecordRaw;
    routerArray.push(menu);
});

export const menuList: RouteRecordRaw[] = [];
// hidden 只表示「不进侧栏菜单」，路由本身仍然可达。
// 之前这段过滤只对 modules/*.ts 的第一个子级生效（homeRouter 是 unshift 进去的，完全没过滤），
// 于是 /node-dashboard 进了概览的子菜单、还让 Home-Menu 从「单子项」变成「子菜单」，
// 递归到没有 meta 的 / 时 $t(undefined, 2) 直接抛 SyntaxError 打断整个侧栏渲染。
const visibleMenuChildren = (children: any[]): RouteRecordRaw[] =>
    (children || []).filter((child: any) => child.hidden == undefined || child.hidden == false);

rolesRoutes.forEach((item) => {
    let menuItem = JSON.parse(JSON.stringify(item));
    if (menuItem.children == undefined) {
        return;
    }
    menuItem.children = visibleMenuChildren(menuItem.children) as RouteRecordRaw[];
    menuList.push(menuItem);
});
const homeMenu = JSON.parse(JSON.stringify(homeRouter));
homeMenu.children = visibleMenuChildren(homeMenu.children) as RouteRecordRaw[];
menuList.unshift(homeMenu);

export const routes: RouteRecordRaw[] = [
    homeRouter,
    {
        path: '/login',
        name: 'login',
        props: true,
        component: () => import('@/views/login/index.vue'),
        meta: {
            key: 'login',
        },
    },
    {
        path: '/enterprise/license-required',
        name: 'EnterpriseLicenseRequired',
        component: () => import('@/views/setting/license-required/index.vue'),
        meta: {
            key: 'enterprise-license-required',
        },
    },
    {
        path: '/s/:code',
        name: 'file-share',
        component: () => import('@/views/share/index.vue'),
        meta: {},
    },
    {
        path: '/:code?',
        name: 'entrance',
        component: () => import('@/views/login/index.vue'),
        props: true,
    },
    ...routerArray,
    {
        path: '/:pathMatch(.*)',
        redirect: { name: '404' },
    },
];
const router = createRouter({
    history: createWebHistory('/'),
    routes: routes as RouteRecordRaw[],
    strict: false,
    scrollBehavior: () => ({ left: 0, top: 0 }),
});

export default router;

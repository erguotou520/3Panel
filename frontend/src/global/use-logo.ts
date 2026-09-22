import { useGlobalStore } from '@/composables/useGlobalStore';

export const useLogo = async () => {
    const { themeConfig } = useGlobalStore();

    const link = (document.querySelector("link[rel*='icon']") || document.createElement('link')) as HTMLLinkElement;
    link.type = 'image/x-icon';
    link.rel = 'shortcut icon';
    link.href = themeConfig.value.favicon ? `/api/v2/images/favicon?t=${Date.now()}` : '/public/favicon.png';
    document.getElementsByTagName('head')[0].appendChild(link);
};

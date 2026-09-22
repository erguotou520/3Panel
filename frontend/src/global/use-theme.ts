import { useGlobalStore } from '@/composables/useGlobalStore';

let themeListenerInitialized = false;

export const useTheme = () => {
    const { themeConfig } = useGlobalStore();

    const switchTheme = () => {
        const rawTheme = themeConfig.value.theme;
        let itemTheme = rawTheme;
        if (itemTheme === 'auto') {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            itemTheme = prefersDark ? 'dark' : 'light';
        }
        document.documentElement.className = itemTheme === 'dark' ? 'dark' : 'light';
    };

    const ensureSystemThemeListener = () => {
        if (themeListenerInitialized || typeof window === 'undefined') {
            return;
        }

        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        const onSystemThemeChange = () => {
            if (themeConfig.value.theme === 'auto') {
                switchTheme();
            }
        };

        mediaQuery.addEventListener('change', onSystemThemeChange);
        themeListenerInitialized = true;
    };

    ensureSystemThemeListener();

    return {
        switchTheme,
    };
};

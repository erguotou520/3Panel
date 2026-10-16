import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';

// 前端测试配置。WAF 模块的改动集中在「参数组装」与「格式化」这类纯函数上，
// 组件挂载测试只用于验证结构性改动（字段是否渲染、参数是否传下去）。
export default defineConfig({
    plugins: [vue()],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url)),
        },
    },
    test: {
        environment: 'happy-dom',
        include: ['src/**/__tests__/**/*.spec.ts'],
        globals: true,
    },
});

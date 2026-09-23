import { jumpToPath } from './router';
import router from '@/routers';

export const jumpToInstall = (type: string, key: string) => {
    switch (type) {
        case 'php':
        case 'node':
        case 'java':
        case 'go':
        case 'python':
        case 'dotnet':
            jumpToPath(router, '/websites/runtimes/' + type);
            return true;
    }
    switch (key) {
        case 'openclaw':
            jumpToPath(router, '/ai/agents/agent');
            return true;
        case 'copaw':
            router.push({
                path: '/ai/agents/agent',
                query: {
                    uncached: 'true',
                    open: 'create',
                    agentType: 'copaw',
                },
            });
            return true;
        case 'hermes-agent':
            router.push({
                path: '/ai/agents/agent',
                query: {
                    uncached: 'true',
                    open: 'create',
                    agentType: 'hermes-agent',
                },
            });
            return true;
        case 'vllm':
            return false;
    }
    return false;
};

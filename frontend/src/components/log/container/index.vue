<template>
    <div v-if="showControl" class="log-toolbar">
        <el-select @change="searchLogs" class="fetchClass" v-model="logSearch.mode">
            <template #prefix>{{ $t('container.fetch') }}</template>
            <el-option v-for="item in timeOptions" :key="item.label" :value="item.value" :label="item.label" />
        </el-select>
        <el-select @change="searchLogs" class="tailClass" v-model.number="logSearch.tail">
            <template #prefix>{{ $t('container.lines') }}</template>
            <el-option :value="0" :label="$t('commons.table.all')" />
            <el-option :value="100" :label="100" />
            <el-option :value="200" :label="200" />
            <el-option :value="500" :label="500" />
            <el-option :value="1000" :label="1000" />
        </el-select>
        <div class="margin-button float-left">
            <el-checkbox border @change="searchLogs" v-model="logSearch.isWatch">
                {{ $t('commons.button.watch') }}
            </el-checkbox>
        </div>
        <div class="margin-button float-left">
            <el-checkbox border @change="searchLogs" v-model="logSearch.isShowTimestamp">
                {{ $t('commons.table.date') }}
            </el-checkbox>
        </div>
        <el-button class="margin-button" @click="openDownloadDialog" icon="Download">
            {{ $t('commons.button.download') }}
        </el-button>
        <el-button v-permission="'container_manage'" class="margin-button" @click="onClean" icon="Delete">
            {{ $t('commons.button.clean') }}
        </el-button>
    </div>
    <div class="log-container" :style="styleVars">
        <WTerm
            v-if="termMounted"
            :key="termKey"
            class="log-viewer"
            :auto-resize="true"
            :cursor-blink="false"
            @ready="onTermReady"
            @data="onLogInput"
        />
    </div>
    <DialogPro
        v-model="downloadDialogVisible"
        :title="$t('commons.button.download')"
        size="small"
        :close-on-click-modal="true"
    >
        <el-form label-position="top">
            <el-form-item :label="$t('container.fetch')">
                <el-select v-model="downloadForm.mode" class="w-full">
                    <el-option v-for="item in timeOptions" :key="item.label" :value="item.value" :label="item.label" />
                </el-select>
            </el-form-item>
            <el-form-item :label="$t('container.lines')">
                <el-select
                    v-model="downloadForm.tail"
                    class="w-full"
                    filterable
                    allow-create
                    default-first-option
                    :reserve-keyword="false"
                >
                    <el-option :value="0" :label="$t('commons.table.all')" />
                    <el-option :value="100" :label="100" />
                    <el-option :value="200" :label="200" />
                    <el-option :value="500" :label="500" />
                    <el-option :value="1000" :label="1000" />
                </el-select>
                <div class="download-tail-helper">{{ $t('container.downloadLinesHelper') }}</div>
            </el-form-item>
        </el-form>
        <template #footer>
            <el-button @click="downloadDialogVisible = false">{{ $t('commons.button.cancel') }}</el-button>
            <el-button type="primary" @click="onDownload">{{ $t('commons.button.confirm') }}</el-button>
        </template>
    </DialogPro>
</template>

<script lang="ts" setup>
import { cleanComposeLog, cleanContainerLog, DownloadFile } from '@/api/modules/container';
import { Terminal as WTerm } from '@wterm/vue';
import type { WTerm as WTermInstance } from '@wterm/vue';
import '@wterm/vue/css';
import { WTERM_RESET, toWtermNewlines } from '@/utils/wterm';
import i18n from '@/lang';
import { dateFormatForName } from '@/utils/date';
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue';
import { ElMessageBox } from 'element-plus';
import { MsgError, MsgSuccess } from '@/utils/message';
import { useGlobalStore } from '@/composables/useGlobalStore';
import { checkStreamAuth } from '@/utils/stream-auth';
const { currentNode: globalCurrentNode } = useGlobalStore();

const em = defineEmits(['update:loading']);

const props = defineProps({
    container: {
        type: String,
        default: '',
    },
    compose: {
        type: String,
        default: '',
    },
    resource: {
        type: String,
        default: '',
    },
    highlightDiff: {
        type: Number,
        default: 320,
    },
    node: {
        type: String,
        default: '',
    },
    showControl: {
        type: Boolean,
        default: true,
    },
    defaultFollow: {
        type: Boolean,
        default: false,
    },
    defaultIsShowTimestamp: {
        type: Boolean,
        default: false,
    },
});

const styleVars = computed(() => ({
    '--custom-height': `${props.highlightDiff || 320}px`,
}));

let eventSource: EventSource | null = null;
let term: WTermInstance | null = null;
const termMounted = ref(false);
const termKey = ref(0);
const followBottom = ref(true);

const logSearch = reactive({
    isWatch: props.defaultFollow ? true : true,
    isShowTimestamp: props.defaultIsShowTimestamp,
    container: '',
    mode: 'all',
    tail: props.defaultFollow ? 0 : 100,
    compose: '',
    resource: '',
});
const downloadDialogVisible = ref(false);
const downloadForm = reactive<{ mode: string; tail: number | string }>({
    mode: 'all',
    tail: 0,
});

const timeOptions = ref([
    { label: i18n.global.t('commons.table.all'), value: 'all' },
    {
        label: i18n.global.t('container.lastDay'),
        value: '24h',
    },
    {
        label: i18n.global.t('container.last4Hour'),
        value: '4h',
    },
    {
        label: i18n.global.t('container.lastHour'),
        value: '1h',
    },
    {
        label: i18n.global.t('container.last10Min'),
        value: '10m',
    },
]);

const stopListening = () => {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
};

const clearTerminal = () => {
    term?.write(WTERM_RESET);
    followBottom.value = true;
};

const scrollLogToBottom = () => {
    const element = term?.element;
    if (element) element.scrollTop = element.scrollHeight;
};

const writeLogLine = (data: string) => {
    if (!term) return;
    // wterm keeps `\n` only; the log stream is line based, so normalise the endings.
    term.write(`${toWtermNewlines(data)}\r\n`);
    if (followBottom.value) {
        scrollLogToBottom();
    }
};

const onLogScroll = () => {
    const element = term?.element;
    if (!element) return;
    followBottom.value = element.scrollTop + element.clientHeight >= element.scrollHeight - 2;
};

const bindScrollEvents = () => {
    const element = term?.element;
    if (!element) return;
    element.removeEventListener('scroll', onLogScroll);
    element.addEventListener('scroll', onLogScroll, { passive: true });
};

// The viewer is read only. wterm echoes locally when nothing listens to `data`, so the
// handler has to exist and swallow the input.
const onLogInput = () => {};

const showEventSourceAuthError = (message: string) => {
    MsgError(message);
    writeLogLine(message);
};

// wterm loads its WASM core asynchronously, so mounting and the log stream are split:
// `searchLogs()` only starts once the terminal is ready, otherwise early lines are lost.
const mountTerminal = () => {
    termKey.value += 1;
    termMounted.value = true;
};

const onTermReady = (instance: WTermInstance) => {
    term = instance;
    bindScrollEvents();
    searchLogs();
};

const handleClose = async () => {
    stopListening();
};

const searchLogs = async () => {
    if (Number(logSearch.tail) < 0) {
        MsgError(i18n.global.t('container.linesHelper'));
        return;
    }
    stopListening();
    clearTerminal();

    let currentNode = globalCurrentNode.value;
    if (props.node && props.node !== '') {
        currentNode = props.node;
    }

    let url = `/api/v2/containers/search/log?container=${logSearch.container}&since=${logSearch.mode}&tail=${logSearch.tail}&follow=${logSearch.isWatch}&timestamp=${logSearch.isShowTimestamp}&operateNode=${currentNode}`;
    if (logSearch.compose !== '') {
        url = `/api/v2/containers/search/log?compose=${logSearch.compose}&since=${logSearch.mode}&tail=${logSearch.tail}&follow=${logSearch.isWatch}&timestamp=${logSearch.isShowTimestamp}&operateNode=${currentNode}`;
    }

    const authError = await checkStreamAuth(url, currentNode);
    if (authError) {
        showEventSourceAuthError(authError);
        return;
    }
    eventSource = new EventSource(url);
    eventSource.onmessage = (event: MessageEvent) => {
        writeLogLine(event.data);
    };
    eventSource.onerror = (event: MessageEvent) => {
        stopListening();
        if (event.data && event.data != '') {
            MsgError(event.data);
        }
    };
};

const openDownloadDialog = () => {
    downloadForm.mode = logSearch.mode;
    downloadForm.tail = logSearch.tail;
    downloadDialogVisible.value = true;
};

const onDownload = async () => {
    const customTail = Number(downloadForm.tail);
    if (Number.isNaN(customTail) || customTail < 0) {
        MsgError(i18n.global.t('container.linesHelper'));
        return;
    }
    const container = logSearch.compose === '' ? logSearch.container : logSearch.compose;
    let resource = container;
    if (props.resource) {
        resource = props.resource;
    }
    const containerType = logSearch.compose === '' ? 'container' : 'compose';
    const params = {
        container: container,
        since: downloadForm.mode,
        tail: customTail,
        timestamp: logSearch.isShowTimestamp,
        containerType: containerType,
    };
    const addItem = {};
    addItem['name'] = resource + '-' + dateFormatForName(new Date()) + '.log';
    DownloadFile(params).then((res) => {
        const downloadUrl = window.URL.createObjectURL(new Blob([res]));
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = downloadUrl;
        a.download = addItem['name'];
        const event = new MouseEvent('click');
        a.dispatchEvent(event);
    });
    downloadDialogVisible.value = false;
};

const onClean = async () => {
    ElMessageBox.confirm(i18n.global.t('container.cleanLogHelper'), i18n.global.t('container.cleanLog'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
        type: 'info',
    }).then(async () => {
        let currentNode = globalCurrentNode.value;
        if (props.node && props.node !== '') {
            currentNode = props.node;
        }
        if (logSearch.compose !== '') {
            em('update:loading', true);
            await cleanComposeLog(logSearch.resource, logSearch.compose, currentNode)
                .then(() => {
                    em('update:loading', false);
                    searchLogs();
                    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                })
                .finally(() => {
                    em('update:loading', false);
                });
            return;
        }
        await cleanContainerLog(logSearch.container, currentNode);
        searchLogs();
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    });
};

onMounted(() => {
    logSearch.container = props.container;
    logSearch.compose = props.compose;
    logSearch.resource = props.resource;

    logSearch.tail = 100;
    logSearch.mode = 'all';
    logSearch.isWatch = true;

    nextTick(() => {
        mountTerminal();
    });
});

onUnmounted(() => {
    handleClose();
    const element = term?.element;
    if (element) element.removeEventListener('scroll', onLogScroll);
    term = null;
    termMounted.value = false;
});
</script>

<style scoped lang="scss">
.margin-button {
    margin-left: 0;
}
.fullScreen {
    border: none;
}
.tailClass {
    width: 160px;
}
.fetchClass {
    width: 220px;
}

.log-toolbar {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
}

.log-toolbar :deep(.el-button),
.log-toolbar :deep(.el-checkbox) {
    white-space: nowrap;
    flex-shrink: 0;
}

.download-tail-helper {
    margin-top: 6px;
    font-size: 12px;
    color: var(--el-text-color-secondary);
}

.log-container {
    height: calc(100vh - var(--custom-height, 320px));
    overflow: hidden;
    position: relative;
    background-color: #111827;
    border: 1px solid #374151;
    border-radius: 6px;
    box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.03);
    margin-top: 10px;
}

// `.log-viewer` is merged onto wterm's root element, so it styles the terminal itself;
// the palette is provided through wterm's CSS custom properties.
.log-viewer {
    width: 100%;
    height: 100%;
    padding: 6px 8px;
    border-radius: 0;
    box-shadow: none;
    font-weight: 500;
    --term-font-size: 14px;
    --term-font-family: 'JetBrains Mono', Monaco, Menlo, Consolas, 'Courier New', monospace;
    --term-line-height: 1.2;
    --term-bg: #111827;
    --term-fg: #e5e7eb;
    --term-cursor: #e5e7eb;
    --term-color-0: #111827;
    --term-color-1: #f87171;
    --term-color-2: #34d399;
    --term-color-3: #fbbf24;
    --term-color-4: #60a5fa;
    --term-color-5: #c084fc;
    --term-color-6: #22d3ee;
    --term-color-7: #e5e7eb;
    --term-color-8: #6b7280;
    --term-color-9: #f87171;
    --term-color-10: #34d399;
    --term-color-11: #fbbf24;
    --term-color-12: #60a5fa;
    --term-color-13: #c084fc;
    --term-color-14: #22d3ee;
    --term-color-15: #f9fafb;
}
</style>

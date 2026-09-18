<template>
    <div class="terminal-shell">
        <WTerm
            v-if="termMounted"
            :key="termKey"
            ref="termRef"
            class="terminal-container"
            :class="{ 'cursor-blink': cursorBlinkEnabled }"
            :style="termStyleVars"
            :auto-resize="true"
            :cursor-blink="false"
            @ready="onTermReady"
            @data="onTermData"
            @resize="onTermResized"
            @error="onTermError"
        />
        <transition name="ai-mask-fade">
            <div v-if="aiNotice.loading" class="ai-notice-mask"></div>
        </transition>
        <transition name="ai-notice-fade">
            <div
                v-if="aiNotice.visible"
                class="ai-notice"
                :class="[`ai-notice--${aiNotice.level}`, { 'ai-notice--loading': aiNotice.loading }]"
            >
                {{ aiNotice.message }}
            </div>
        </transition>
    </div>
</template>

<script lang="ts" setup>
import { ref, shallowRef, onActivated, onBeforeUnmount, nextTick, computed } from 'vue';
import { Terminal as WTerm } from '@wterm/vue';
import type { WTerm as WTermInstance } from '@wterm/vue';
import '@wterm/vue/css';
import { WTERM_RESET, wtermStyleVars } from '@/utils/wterm';
import { decodeBase64, encodeBase64 } from '@/utils/base64';
import { TerminalStore } from '@/store';
import { MsgError } from '@/utils/message';
import { checkStreamAuth } from '@/utils/stream-auth';
import { useGlobalStore } from '@/composables/useGlobalStore';
import i18n from '@/lang';
const { currentNode } = useGlobalStore();

// session: agent side session id known (fresh or reattached)
// expired: the agent no longer has the session; a reconnect must open a new one
const emit = defineEmits(['session', 'expired']);

// Close codes of the agent's session protocol (agent/utils/terminal/session.go).
const CLOSE_SESSION_NOT_FOUND = 4404;
const CLOSE_ATTACHED_ELSEWHERE = 4409;
const CLOSE_REVALIDATE = 4410;

const termRef = ref<null | { instance: WTermInstance | null }>(null);
const termMounted = ref(false);
const termKey = ref(0);
const termReady = ref(false);
const webSocketReady = ref(false);
const term = shallowRef<WTermInstance | null>(null);
// connection requested by acceptParams(), started once the terminal reports `ready`
let pendingConnect = false;
let pendingEndpoint = '';
let pendingArgs = '';
let pendingWrite = '';
const terminalSocket = ref<WebSocket>();
const heartbeatTimer = ref<NodeJS.Timer>();
let initWebSocketToken = 0;
const latency = ref(0);
// Reconnect state. Only terminals that received a session hello reconnect;
// the agent keeps a dirty-disconnected session alive for a short grace period.
const sessionId = ref('');
let wsEndpoint = '';
let wsArgs = '';
let closing = false;
let reconnecting = false;
let reconnectNoticeShown = false;
let revalidating = false;
let reconnectStartedAt = 0;
let reconnectDelay = 1000;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
// Must match graceTimeout in agent/utils/terminal/session.go: past it the agent has dropped the shell.
const reconnectWindow = 30 * 60 * 1000;
const initCmd = ref('');
const hideInitCmdEcho = ref(false);
const initCmdEchoBuffer = ref('');
const waitForPrompt = ref('');
const waitForPromptBuffer = ref('');
const aiNotice = ref({
    visible: false,
    loading: false,
    level: 'info',
    message: '',
});
let aiNoticeTimer: ReturnType<typeof setTimeout> | null = null;
let lastResizeColumns = 0;
let lastResizeRows = 0;

const terminalStore = TerminalStore();
const lineHeight = computed(() => terminalStore.lineHeight);
const fontSize = computed(() => terminalStore.fontSize);
const fontFamily = computed(() => terminalStore.fontFamily);
const backgroundColor = computed(() => terminalStore.backgroundColor);
const foregroundColor = computed(() => terminalStore.foregroundColor);
const letterSpacing = computed(() => terminalStore.letterSpacing);
// wterm takes its appearance from CSS custom properties on the `.wterm` root element,
// so font/colour settings are applied reactively instead of mutating terminal options.
const cursorBlinkEnabled = computed(() => String(terminalStore.cursorBlink).toLowerCase() === 'enable');
const termStyleVars = computed(() =>
    wtermStyleVars({
        fontSize: fontSize.value,
        lineHeight: lineHeight.value,
        letterSpacing: letterSpacing.value,
        fontFamily: fontFamily.value,
        backgroundColor: backgroundColor.value,
        foregroundColor: foregroundColor.value,
    }),
);

interface WsProps {
    endpoint: string;
    args: string;
    error: string;
    initCmd: string;
    waitForPrompt?: string;
    sessionId?: string;
}

const acceptParams = (props: WsProps) => {
    nextTick(() => {
        if (props.error.length !== 0) {
            initError(props.error);
        } else {
            initCmd.value = props.initCmd || '';
            waitForPrompt.value = props.waitForPrompt || '';
            waitForPromptBuffer.value = '';
            sessionId.value = props.sessionId || '';
            init(props.endpoint, props.args);
        }
    });
};

const init = (endpoint: string, args: string) => {
    mountTerminal(true, endpoint, args);
};

const initError = (errorInfo: string) => {
    mountTerminal(false, '', '', errorInfo);
};

// wterm initialises asynchronously (it loads a WASM core), so the socket is only opened
// once the component reports `ready`; the terminal is re-created for every new session.
const mountTerminal = (online: boolean, endpoint: string, args: string, errorInfo: string = '') => {
    pendingConnect = online;
    pendingEndpoint = endpoint;
    pendingArgs = args;
    pendingWrite = errorInfo;
    lastResizeColumns = 0;
    lastResizeRows = 0;
    termKey.value += 1;
    termMounted.value = true;
};

const onTermReady = (instance: WTermInstance) => {
    term.value = instance;
    termReady.value = true;
    if (pendingWrite) {
        instance.write(pendingWrite);
        pendingWrite = '';
    }
    if (pendingConnect) {
        pendingConnect = false;
        initWebSocket(pendingEndpoint, pendingArgs);
    }
};

const onTermError = (err: unknown) => {
    termReady.value = false;
    console.error('[wterm] init failed', err);
    MsgError(err instanceof Error ? err.message : 'terminal init failed');
};

function onClose(isKeepShow: boolean = false) {
    initWebSocketToken++;
    closing = true;
    stopReconnect();
    lastResizeColumns = 0;
    lastResizeRows = 0;
    clearAINotice();
    webSocketReady.value = false;
    try {
        // 1000 tells the agent this is deliberate: close the shell now, no grace period
        terminalSocket.value?.close(1000);
    } catch {}
    if (heartbeatTimer.value) {
        clearInterval(Number(heartbeatTimer.value));
        heartbeatTimer.value = undefined;
    }
    terminalSocket.value = undefined;
    pendingConnect = false;
    pendingWrite = '';
    if (!isKeepShow) {
        // unmounting the component destroys the underlying WTerm instance
        termReady.value = false;
        termMounted.value = false;
        term.value = null;
    }
}

// terminal 相关代码 start

// wterm keeps the grid fitted to its container by itself (`autoResize`), so the only job
// left here is telling the agent about the new dimensions.
const pushTerminalSize = (force: boolean = false) => {
    const instance = term.value;
    if (!instance || !isWsOpen()) return;
    const { cols, rows } = instance;
    if (cols <= 0 || rows <= 0) return;
    if (!force && cols === lastResizeColumns && rows === lastResizeRows) {
        return;
    }
    lastResizeColumns = cols;
    lastResizeRows = rows;
    terminalSocket.value!.send(
        JSON.stringify({
            type: 'resize',
            cols: cols,
            rows: rows,
        }),
    );
};

const onTermResized = () => pushTerminalSize();
const changeTerminalSize = () => pushTerminalSize();

// terminal 相关代码 end

// websocket 相关代码 start

const initWebSocket = async (endpoint_: string, args: string = '') => {
    const token = ++initWebSocketToken;
    closing = false;
    wsEndpoint = endpoint_;
    wsArgs = args;
    const href = window.location.href;
    const protocol = href.split('//')[0] === 'http:' ? 'ws' : 'wss';
    const host = href.split('//')[1].split('/')[0];
    const endpoint = endpoint_.replace(/^\/+/, '');
    let node = args.indexOf('id=') !== -1 ? 'local' : currentNode.value;
    let conn = `${protocol}://${host}/${endpoint}?cols=${term.value.cols}&rows=${term.value.rows}&${args}&operateNode=${node}`;
    if (args.indexOf('operateNode=') !== -1) {
        conn = `${protocol}://${host}/${endpoint}?cols=${term.value.cols}&rows=${term.value.rows}&${args}`;
    }
    if (sessionId.value) {
        conn += `&session=${encodeURIComponent(sessionId.value)}`;
    }
    if (revalidating) {
        conn += '&terminalRevalidate=1';
    }
    const authError = await checkStreamAuth(conn);
    if (token !== initWebSocketToken || !termReady.value) {
        return;
    }
    if (authError) {
        reconnecting = false;
        revalidating = false;
        sessionId.value = '';
        showWebSocketAuthError(authError);
        emit('expired');
        return;
    }
    if (heartbeatTimer.value) {
        clearInterval(Number(heartbeatTimer.value));
    }
    terminalSocket.value = new WebSocket(conn);
    terminalSocket.value.onopen = runRealTerminal;
    terminalSocket.value.onmessage = onWSReceive;
    terminalSocket.value.onclose = closeRealTerminal;
    terminalSocket.value.onerror = errorRealTerminal;
    heartbeatTimer.value = setInterval(() => {
        if (isWsOpen()) {
            terminalSocket.value!.send(
                JSON.stringify({
                    type: 'heartbeat',
                    timestamp: `${new Date().getTime()}`,
                }),
            );
        }
    }, 1000 * 10);
};

const showWebSocketAuthError = (message: string) => {
    clearAINotice();
    MsgError(message);
    term.value?.write(`\x1b[31m${message}\x1b[m\r\n`);
};

const runRealTerminal = () => {
    webSocketReady.value = true;
    pushTerminalSize(true);
    term.value?.focus();
    // a reattached shell already ran its init command
    if (initCmd.value !== '' && !sessionId.value) {
        hideInitCmdEcho.value = true;
        initCmdEchoBuffer.value = '';
        sendMsg(initCmd.value);
    }
};

const stripInitCmdEchoLine = (message: string) => {
    if (!hideInitCmdEcho.value) {
        return message;
    }
    initCmdEchoBuffer.value += message;
    const lineBreakIndex = initCmdEchoBuffer.value.search(/\r?\n/);
    if (lineBreakIndex === -1) {
        return '';
    }

    const lineBreakLength = initCmdEchoBuffer.value[lineBreakIndex] === '\r' ? 2 : 1;
    const remaining = initCmdEchoBuffer.value.slice(lineBreakIndex + lineBreakLength);
    hideInitCmdEcho.value = false;
    initCmdEchoBuffer.value = '';
    initCmd.value = '';
    return remaining;
};

const flushPromptBuffer = (message: string) => {
    if (!waitForPrompt.value) {
        return message;
    }
    waitForPromptBuffer.value += message;
    const promptIndex = waitForPromptBuffer.value.indexOf(waitForPrompt.value);
    if (promptIndex === -1) {
        return '';
    }

    const visible = waitForPromptBuffer.value.slice(promptIndex);
    waitForPrompt.value = '';
    waitForPromptBuffer.value = '';
    return visible;
};

const onWSReceive = (message: MessageEvent) => {
    const wsMsg = JSON.parse(message.data);
    switch (wsMsg.type) {
        case 'cmd': {
            if (wsMsg.data) {
                let receiveMsg = decodeBase64(wsMsg.data);
                if (hideInitCmdEcho.value) {
                    receiveMsg = stripInitCmdEchoLine(receiveMsg);
                }
                if (receiveMsg && waitForPrompt.value) {
                    receiveMsg = flushPromptBuffer(receiveMsg);
                }
                if (!receiveMsg) {
                    break;
                }
                term.value?.write(receiveMsg);
            }
            break;
        }
        case 'heartbeat': {
            latency.value = new Date().getTime() - wsMsg.timestamp;
            break;
        }
        case 'session': {
            const wasReconnect = reconnecting;
            const wasRevalidate = revalidating;
            reconnecting = false;
            revalidating = false;
            reconnectDelay = 1000;
            sessionId.value = wsMsg.id || '';
            if (wasReconnect && !wasRevalidate) {
                // replay is a tail of recent output, start from a clean screen
                term.value?.write(WTERM_RESET);
            }
            emit('session', sessionId.value);
            break;
        }
        case 'ai_notice': {
            const message = wsMsg.message?.trim();
            if (!message) {
                break;
            }
            showAINotice(wsMsg.level || 'info', message);
            break;
        }
    }
};

const errorRealTerminal = (ex: any) => {
    clearAINotice();
    if (reconnecting) return;
    let message = ex.message;
    if (!message) message = 'disconnected';
    term.value?.write(`\x1b[31m${message}\x1b[m\r\n`);
};

const closeRealTerminal = (ev: CloseEvent) => {
    clearAINotice();
    webSocketReady.value = false;
    if (heartbeatTimer.value) {
        clearInterval(Number(heartbeatTimer.value));
        heartbeatTimer.value = undefined;
    }
    terminalSocket.value = undefined;
    if (closing || !sessionId.value) {
        term.value?.write('The connection has been disconnected.');
        term.value?.write(ev.reason);
        return;
    }
    switch (ev.code) {
        case 1000: // the shell exited or the agent closed it
        case CLOSE_SESSION_NOT_FOUND:
            sessionId.value = '';
            reconnecting = false;
            writeNotice(
                '31',
                ev.code === 1000 ? 'The connection has been disconnected.' : i18n.global.t('terminal.sessionExpired'),
            );
            emit('expired');
            return;
        case CLOSE_ATTACHED_ELSEWHERE:
            reconnecting = false;
            writeNotice('31', i18n.global.t('terminal.sessionKicked'));
            return;
        case CLOSE_REVALIDATE:
            revalidating = true;
            scheduleReconnect(true);
            return;
        default:
            scheduleReconnect();
    }
};

const writeNotice = (color: string, message: string) => {
    term.value?.write(`\r\n\x1b[${color}m${message}\x1b[m\r\n`);
};

// scheduleReconnect retries with backoff for as long as the agent keeps a detached session.
const scheduleReconnect = (forRevalidation = false) => {
    const now = Date.now();
    if (!reconnecting) {
        reconnecting = true;
        reconnectStartedAt = now;
        reconnectDelay = 1000;
        reconnectNoticeShown = false;
    } else if (now - reconnectStartedAt > reconnectWindow) {
        reconnecting = false;
        sessionId.value = '';
        writeNotice('31', i18n.global.t('terminal.sessionExpired'));
        emit('expired');
        return;
    }
    if (!forRevalidation && !reconnectNoticeShown) {
        writeNotice('33', i18n.global.t('terminal.sessionReconnecting'));
        reconnectNoticeShown = true;
    }
    reconnectTimer = setTimeout(
        () => {
            reconnectTimer = null;
            if (closing || !sessionId.value) return;
            initWebSocket(wsEndpoint, wsArgs);
        },
        forRevalidation ? 0 : reconnectDelay,
    );
    if (!forRevalidation) {
        reconnectDelay = Math.min(reconnectDelay * 2, 8000);
    }
};

const stopReconnect = () => {
    reconnecting = false;
    revalidating = false;
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }
};

const isWsOpen = () => {
    const readyState = terminalSocket.value && terminalSocket.value.readyState;
    return readyState === 1;
};

function isEnterInputData(data: string): boolean {
    return data === '\r' || data === '\n' || data === '\r\n';
}

// wterm exposes the cell grid instead of an xterm-style buffer, and it has no soft-wrap
// flag, so only the physical row under the cursor can be read: a wrapped command reports
// just its last row.
function getCurrentTerminalLine(): string {
    const bridge = term.value?.bridge;
    if (!bridge) return '';
    const cursor = bridge.getCursor();
    if (!cursor) return '';
    const cols = bridge.getCols();
    let content = '';
    for (let col = 0; col < cols; col++) {
        const cell = bridge.getCell(cursor.row, col);
        if (!cell || cell.width === 0) continue;
        content += cell.chars ?? String.fromCodePoint(cell.char || 32);
    }
    return content.trimEnd();
}

function sendMsg(data: string, line: string = '') {
    if (isWsOpen()) {
        terminalSocket.value!.send(
            JSON.stringify({
                type: 'cmd',
                data: encodeBase64(data),
                line,
            }),
        );
    }
}

function onTermData(data: string) {
    if (!data) return;
    if (aiNotice.value.loading) return;
    sendMsg(data, isEnterInputData(data) ? getCurrentTerminalLine() : '');
}

function clearAINotice() {
    if (aiNoticeTimer) {
        clearTimeout(aiNoticeTimer);
        aiNoticeTimer = null;
    }
    aiNotice.value = {
        ...aiNotice.value,
        visible: false,
        loading: false,
    };
}

function showAINotice(level: string, message: string) {
    if (aiNoticeTimer) {
        clearTimeout(aiNoticeTimer);
        aiNoticeTimer = null;
    }
    const resolvedLevel = ['success', 'error', 'info'].includes(level) ? level : 'info';
    aiNotice.value = {
        visible: true,
        loading: resolvedLevel === 'info',
        level: resolvedLevel,
        message,
    };
    if (resolvedLevel === 'info') {
        return;
    }
    aiNoticeTimer = setTimeout(() => {
        aiNotice.value = {
            ...aiNotice.value,
            visible: false,
            loading: false,
        };
        aiNoticeTimer = null;
    }, 2600);
}

// websocket 相关代码 end

defineExpose({
    acceptParams,
    onClose,
    isWsOpen,
    sendMsg,
    getLatency: () => latency.value,
    // kept for callers that re-fit after the element was moved back into a visible
    // container; wterm re-fits itself via its own ResizeObserver, so this only re-syncs
    // the dimensions with the agent
    refit: () => changeTerminalSize(),
});

onBeforeUnmount(() => {
    onClose();
});

onActivated(() => {
    nextTick(changeTerminalSize);
});
</script>

<style lang="scss" scoped>
// `.terminal-container` is merged onto wterm's own root element, so these rules target
// `.wterm` itself (scoped styles keep working because the root carries the scope id).
.terminal-container {
    width: 100%;
    height: 100%;
    padding: 5px;
    border-radius: 0;
    box-shadow: none;
    letter-spacing: var(--panel-term-letter-spacing, 0px);
    scrollbar-width: thin;
    scrollbar-color: rgba(255, 255, 255, 0.3) rgba(255, 255, 255, 0.1);
}

.terminal-container::-webkit-scrollbar {
    width: 10px;
    height: 10px;
    background: rgba(255, 255, 255, 0.1);
}

.terminal-container::-webkit-scrollbar-thumb {
    border-radius: 6px;
    border: 2px solid transparent;
    background-clip: content-box;
    background-color: rgba(255, 255, 255, 0.3);
}

.terminal-container::-webkit-scrollbar-thumb:hover {
    background-color: rgba(255, 255, 255, 0.45);
}

.terminal-container::-webkit-scrollbar-corner {
    background: transparent;
}

// wterm renders block elements and wide glyphs inside fixed `1ch`/`2ch` boxes, so the
// configured letter spacing has to be added back to those boxes.
:deep(.term-block) {
    width: calc(1ch + var(--panel-term-letter-spacing, 0px));
}

:deep(.term-wide) {
    width: calc(2ch + 2 * var(--panel-term-letter-spacing, 0px));
}

.terminal-shell {
    position: relative;
    width: 100%;
    height: 100%;
}

.ai-notice-mask {
    position: absolute;
    inset: 0;
    z-index: 10;
    background: rgba(8, 10, 14, 0.12);
    backdrop-filter: blur(1.5px);
    pointer-events: auto;
    cursor: progress;
}

.ai-notice {
    position: absolute;
    left: 50%;
    top: 24px;
    transform: translateX(-50%);
    z-index: 12;
    width: fit-content;
    min-width: 240px;
    max-width: min(72%, 560px);
    padding: 9px 14px;
    border-radius: 999px;
    border: 1px solid rgba(255, 255, 255, 0.16);
    background: rgba(16, 18, 24, 0.78);
    color: #f3f4f6;
    font-size: 12px;
    line-height: 1.4;
    text-align: center;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.2);
    backdrop-filter: blur(8px);
    pointer-events: none;
    white-space: pre-wrap;
}

.ai-notice--loading {
    top: 50%;
    width: min(72%, 560px);
    padding: 12px 16px;
    border-radius: 12px;
    font-size: 13px;
    line-height: 1.5;
    transform: translate(-50%, -50%);
    background: rgba(16, 18, 24, 0.92);
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.3);
    backdrop-filter: blur(10px);
}

.ai-notice--success {
    border-color: rgba(34, 197, 94, 0.45);
    background: rgba(10, 28, 18, 0.78);
}

.ai-notice--error {
    border-color: rgba(248, 113, 113, 0.45);
    background: rgba(40, 16, 16, 0.8);
}

.ai-notice-fade-enter-active,
.ai-notice-fade-leave-active {
    transition:
        opacity 180ms ease,
        transform 180ms ease;
}

.ai-mask-fade-enter-active,
.ai-mask-fade-leave-active {
    transition: opacity 180ms ease;
}

.ai-notice-fade-enter-from,
.ai-notice-fade-leave-to {
    opacity: 0;
    transform: translateX(-50%) translateY(-6px);
}

.ai-notice--loading.ai-notice-fade-enter-from,
.ai-notice--loading.ai-notice-fade-leave-to {
    transform: translate(-50%, calc(-50% + 8px));
}

.ai-mask-fade-enter-from,
.ai-mask-fade-leave-to {
    opacity: 0;
}
</style>

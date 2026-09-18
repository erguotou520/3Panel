<template>
    <div v-loading="loading">
        <LayoutContent :title="$t('container.setting')" :divider="true">
            <template #main>
                <el-form :model="form" label-position="left" label-width="150px">
                    <el-row>
                        <el-col :span="1"><br /></el-col>
                        <el-col :xs="24" :sm="20" :md="15" :lg="12" :xl="12">
                            <el-form-item :label="$t('terminal.lineHeight')">
                                <el-input-number
                                    class="formInput"
                                    :min="1"
                                    :max="2.0"
                                    :precision="1"
                                    :step="0.1"
                                    v-model="form.lineHeight"
                                    @change="changeItem()"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('terminal.letterSpacing')">
                                <el-input-number
                                    class="formInput"
                                    :min="0"
                                    :max="3.5"
                                    :precision="1"
                                    :step="0.5"
                                    v-model="form.letterSpacing"
                                    @change="changeItem()"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('terminal.fontSize')">
                                <el-input-number
                                    class="formInput"
                                    :step="1"
                                    :min="12"
                                    :max="20"
                                    v-model="form.fontSize"
                                    @change="changeItem()"
                                />
                            </el-form-item>
                            <el-form-item :label="$t('terminal.fontFamily')">
                                <el-select
                                    class="formInput"
                                    clearable
                                    v-model="selectedFontFamilies"
                                    multiple
                                    filterable
                                    allow-create
                                    default-first-option
                                    :reserve-keyword="false"
                                >
                                    <el-option
                                        v-for="item in fontFamilyOptions"
                                        :key="item.value"
                                        :label="item.label"
                                        :value="item.value"
                                    />
                                </el-select>
                                <span class="input-help">{{ $t('terminal.fontFamilySupportHelper') }}</span>
                            </el-form-item>
                            <el-form-item :label="$t('terminal.backgroundColor')">
                                <el-color-picker v-model="form.backgroundColor" @change="changeItem()" />
                            </el-form-item>
                            <el-form-item :label="$t('terminal.foregroundColor')">
                                <el-color-picker v-model="form.foregroundColor" @change="changeItem()" />
                            </el-form-item>

                            <el-form-item>
                                <WTerm
                                    v-if="termMounted"
                                    :key="termKey"
                                    ref="termRef"
                                    class="terminal"
                                    :class="{ 'cursor-blink': form.cursorBlink === 'Enable' }"
                                    :style="termStyleVars"
                                    :auto-resize="true"
                                    :cursor-blink="false"
                                    @ready="onTermReady"
                                />
                            </el-form-item>

                            <el-form-item :label="$t('terminal.cursorBlink')">
                                <el-switch
                                    v-model="form.cursorBlink"
                                    active-value="Enable"
                                    inactive-value="Disable"
                                    @change="changeItem()"
                                />
                            </el-form-item>
                            <el-form-item>
                                <el-button @click="onSetDefault()" plain>
                                    {{ $t('commons.button.setDefault') }}
                                </el-button>
                                <el-button @click="search(true)" plain>{{ $t('commons.button.reset') }}</el-button>
                                <el-button @click="onSave" type="primary">{{ $t('commons.button.save') }}</el-button>
                            </el-form-item>

                            <el-divider border-style="dashed" />

                            <el-form-item :label="$t('terminal.defaultConn')">
                                <el-switch v-model="form.showDefaultConn" @change="changeShow" />
                            </el-form-item>
                            <el-form-item :label="$t('xpack.node.connInfo')">
                                <el-input disabled v-model="form.defaultConn">
                                    <template #append>
                                        <el-button @click="dialogRef.acceptParams(false)" icon="Setting">
                                            {{ $t('commons.button.set') }}
                                        </el-button>
                                    </template>
                                </el-input>
                            </el-form-item>

                            <el-divider border-style="dashed" />

                            <el-form-item :label="$t('terminal.showTerminalButton')">
                                <el-switch v-model="form.showTerminalButton" @change="changeTerminalButton" />
                                <span class="input-help">{{ $t('terminal.showTerminalButtonHelper') }}</span>
                            </el-form-item>
                        </el-col>
                    </el-row>
                </el-form>
            </template>
        </LayoutContent>
        <OperateDialog @search="loadConnShow" ref="dialogRef" />

        <OpDialog ref="opRef" @search="search" @cancel="loadConnShow" @submit="submitChangeShow">
            <template #content>
                <el-form class="mt-4 mb-1" ref="deleteForm" v-if="!form.showDefaultConn" label-position="left">
                    <el-form-item>
                        <el-checkbox v-model="resetConn" :label="$t('terminal.withReset')" />
                    </el-form-item>
                </el-form>
            </template>
        </OpDialog>
    </div>
</template>

<script lang="ts" setup>
import { ref, reactive, computed, watch } from 'vue';
import { getTerminalInfo, UpdateTerminalInfo } from '@/api/modules/setting';
import { Terminal as WTerm } from '@wterm/vue';
import type { WTerm as WTermInstance } from '@wterm/vue';
import '@wterm/vue/css';
import { wtermStyleVars } from '@/utils/wterm';
import OperateDialog from '@/views/terminal/setting/default-conn/index.vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { TerminalDockSessionStore, TerminalStore } from '@/store';
import { loadLocalConn, updateLocalConn } from '@/api/modules/terminal';
import { ElMessageBox } from 'element-plus';

const loading = ref(false);
const terminalStore = TerminalStore();
const dockSessions = TerminalDockSessionStore();
const dialogRef = ref();

const termRef = ref<null | { instance: WTermInstance | null }>(null);
const term = ref<WTermInstance | null>(null);
const termMounted = ref(false);
const termKey = ref(0);
const DEFAULT_FONT_FAMILY = "Monaco, Menlo, Consolas, 'Courier New', monospace";
const selectedFontFamilies = ref<string[]>([]);
const fontFamilyOptions = [
    { label: 'Monaco', value: 'Monaco' },
    { label: 'Menlo', value: 'Menlo' },
    { label: 'Consolas', value: 'Consolas' },
    { label: 'JetBrains Mono', value: "'JetBrains Mono'" },
    { label: 'Fira Code', value: "'Fira Code'" },
    { label: 'Cascadia Code', value: "'Cascadia Code'" },
    { label: 'Source Code Pro', value: "'Source Code Pro'" },
    { label: 'Ubuntu Mono', value: "'Ubuntu Mono'" },
    { label: 'DejaVu Sans Mono', value: "'DejaVu Sans Mono'" },
    { label: 'Courier New', value: "'Courier New'" },
    { label: 'monospace', value: 'monospace' },
];

const form = reactive({
    showTerminalButton: true,
    lineHeight: 1.2,
    letterSpacing: 1.2,
    fontSize: 12,
    fontFamily: DEFAULT_FONT_FAMILY,
    backgroundColor: '#000000',
    foregroundColor: '#f5f5f5',
    cursorBlink: 'Enable',
    showDefaultConn: false,
    defaultConn: '',
});
const resetConn = ref(false);
const opRef = ref();

const splitFontFamily = (value: string): string[] => {
    return value
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item.length > 0);
};

const syncFontFamilyFromSelected = () => {
    const values = selectedFontFamilies.value.map((item) => item.trim()).filter((item) => item.length > 0);
    form.fontFamily = values.join(', ');
};

const ensureFontFamily = () => {
    if (selectedFontFamilies.value.length > 0) return;
    selectedFontFamilies.value = splitFontFamily(DEFAULT_FONT_FAMILY);
    form.fontFamily = DEFAULT_FONT_FAMILY;
    if (term.value) {
        changeItem();
    }
};

watch(
    selectedFontFamilies,
    () => {
        syncFontFamilyFromSelected();
        if (!term.value) return;
        changeItem();
    },
    { deep: true },
);

const acceptParams = () => {
    search(true);
    loadConnShow();
    iniTerm();
};

// The preview mirrors the panel terminal settings through wterm's CSS variables, so it
// only needs to be created once; every change re-renders `termStyleVars` below.
const termStyleVars = computed(() =>
    wtermStyleVars({
        fontSize: form.fontSize,
        lineHeight: form.lineHeight,
        letterSpacing: form.letterSpacing,
        fontFamily: form.fontFamily || DEFAULT_FONT_FAMILY,
        backgroundColor: form.backgroundColor,
        foregroundColor: form.foregroundColor,
    }),
);

const search = async (withReset?: boolean) => {
    loading.value = true;
    await getTerminalInfo()
        .then((res) => {
            loading.value = false;
            form.showTerminalButton = res.data.showTerminalButton !== 'Disable';
            form.lineHeight = Number(res.data.lineHeight);
            form.letterSpacing = Number(res.data.letterSpacing);
            form.fontSize = Number(res.data.fontSize);
            form.fontFamily = res.data.fontFamily || DEFAULT_FONT_FAMILY;
            selectedFontFamilies.value = splitFontFamily(form.fontFamily);
            form.backgroundColor = res.data.backgroundColor || '#000000';
            form.foregroundColor = res.data.foregroundColor || '#f5f5f5';
            form.cursorBlink = res.data.cursorBlink;
            terminalStore.fontFamily = res.data.fontFamily || '';

            if (withReset) {
                changeItem();
            }
        })
        .catch(() => {
            loading.value = false;
        });
};

const changeTerminalButton = async () => {
    const showTerminalButton = form.showTerminalButton;
    loading.value = true;
    try {
        if (!showTerminalButton && dockSessions.entries.length > 0) {
            await ElMessageBox.confirm(
                i18n.global.t('terminal.disableShortcutConfirm'),
                i18n.global.t('terminal.showTerminalButton'),
                {
                    confirmButtonText: i18n.global.t('commons.button.confirm'),
                    cancelButtonText: i18n.global.t('commons.button.cancel'),
                    type: 'warning',
                },
            );
        }
        await UpdateTerminalInfo({
            showTerminalButton: showTerminalButton ? 'Enable' : 'Disable',
        });
        terminalStore.showTerminalButton = showTerminalButton;
        if (!showTerminalButton) dockSessions.closeAll();
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    } catch {
        form.showTerminalButton = !showTerminalButton;
    } finally {
        loading.value = false;
    }
};

const loadConnShow = async () => {
    await loadLocalConn().then((res) => {
        form.showDefaultConn = res.data.localSSHConnShow === 'Enable';
        if (res.data.addr && res.data.port && res.data.user) {
            form.defaultConn = res.data.user + '@' + res.data.addr + ':' + res.data.port;
        } else {
            form.defaultConn = '-';
        }
        resetConn.value = false;
    });
};

const changeShow = async () => {
    let op = form.showDefaultConn ? i18n.global.t('xpack.waf.allow') : i18n.global.t('xpack.waf.deny');
    opRef.value.acceptParams({
        title: i18n.global.t('terminal.defaultConn'),
        names: [],
        msg: i18n.global.t('terminal.defaultConnHelper', [op]),
        api: null,
        params: {},
    });
};
const submitChangeShow = async () => {
    loading.value = true;
    await updateLocalConn({
        withReset: resetConn.value,
        defaultConn: form.showDefaultConn ? 'Enable' : 'Disable',
    })
        .then(() => {
            loading.value = false;
            loadConnShow();
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        })
        .finally(() => {
            loading.value = false;
        });
};

const iniTerm = () => {
    if (termMounted.value) return;
    termKey.value += 1;
    termMounted.value = true;
};

const onTermReady = (instance: WTermInstance) => {
    term.value = instance;
    instance.write('the first line\r\nthe second line');
};

// The preview follows the form reactively through `termStyleVars`; the handler is kept
// because every field in the form is wired to it.
const changeItem = () => {};

const onSetDefault = () => {
    form.lineHeight = 1.2;
    form.letterSpacing = 0;
    form.fontSize = 12;
    form.fontFamily = DEFAULT_FONT_FAMILY;
    selectedFontFamilies.value = splitFontFamily(DEFAULT_FONT_FAMILY);
    form.backgroundColor = '#000000';
    form.foregroundColor = '#f5f5f5';
    form.cursorBlink = 'Enable';

    changeItem();
};

const onSave = () => {
    ensureFontFamily();
    ElMessageBox.confirm(i18n.global.t('terminal.saveHelper'), i18n.global.t('container.setting'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
        type: 'info',
    }).then(async () => {
        loading.value = true;
        try {
            let param = {
                lineHeight: form.lineHeight + '',
                letterSpacing: form.letterSpacing + '',
                fontSize: form.fontSize + '',
                fontFamily: form.fontFamily,
                backgroundColor: form.backgroundColor,
                foregroundColor: form.foregroundColor,
                cursorBlink: form.cursorBlink,
            };
            await UpdateTerminalInfo(param);
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
            terminalStore.$patch({
                lineHeight: form.lineHeight,
                letterSpacing: form.letterSpacing,
                fontSize: form.fontSize,
                fontFamily: form.fontFamily,
                backgroundColor: form.backgroundColor,
                foregroundColor: form.foregroundColor,
                cursorBlink: form.cursorBlink,
            });
        } finally {
            loading.value = false;
        }
    });
};

defineExpose({
    acceptParams,
});
</script>

<style lang="css" scoped>
.formInput {
    width: 100%;
}
.terminal {
    width: 100%;
    height: 100px;
    padding: 5px;
    border-radius: 0;
    box-shadow: none;
    letter-spacing: var(--panel-term-letter-spacing, 0px);
}

/* wterm renders block elements and wide glyphs inside fixed `1ch`/`2ch` boxes, so the
   configured letter spacing has to be added back to those boxes. */
:deep(.term-block) {
    width: calc(1ch + var(--panel-term-letter-spacing, 0px));
}

:deep(.term-wide) {
    width: calc(2ch + 2 * var(--panel-term-letter-spacing, 0px));
}
</style>

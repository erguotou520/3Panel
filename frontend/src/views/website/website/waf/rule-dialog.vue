<template>
    <el-drawer
        v-model="drawerVisible"
        :title="isEdit ? $t('commons.button.edit') : $t('commons.button.create')"
        size="30%"
    >
        <el-form ref="formRef" label-position="top" :model="form">
            <el-form-item :label="$t('commons.table.name')" prop="name" :rules="rules.required">
                <el-input v-model="form.name" />
            </el-form-item>
            <el-form-item :label="$t('website.wafScope')">
                <el-radio-group v-model="form.scope">
                    <el-radio value="site">site</el-radio>
                    <el-radio value="global">global</el-radio>
                </el-radio-group>
            </el-form-item>
            <el-form-item :label="$t('website.wafMatchType')">
                <el-select v-model="form.matchType">
                    <el-option v-for="t in matchTypes" :key="t" :label="t" :value="t" />
                </el-select>
            </el-form-item>
            <el-form-item :label="$t('website.wafMatchOp')">
                <el-select v-model="form.matchOp">
                    <el-option v-for="t in matchOps" :key="t" :label="t" :value="t" />
                </el-select>
            </el-form-item>
            <el-form-item :label="$t('website.wafMatchValue')" prop="matchValue" :rules="rules.required">
                <!-- ip_group 用下拉而不是输入框：组名会直接成为
                     rules.json 里的 map key，填错一个字符就是
                     「组不存在」且 Lua 侧静默放行 —— 界面上完全看不出异常。
                     禁用手输从根上消除这类错误。 -->
                <!-- geo：多选地区码，提交时拼成逗号分隔（与后端 collectGeoCodes 的解析一致） -->
                <el-select
                    v-if="form.matchType === 'geo'"
                    :model-value="geoSelected"
                    multiple
                    filterable
                    class="p-w-300"
                    @update:model-value="onGeoChange"
                >
                    <el-option v-for="c in geoCountries" :key="c.code" :label="geoLabel(c)" :value="c.code" />
                </el-select>
                <el-select v-else-if="form.matchType === 'ip_group'" v-model="form.matchValue" class="p-w-300">
                    <el-option v-for="g in availableIPGroups" :key="g.name" :label="g.name" :value="g.name">
                        <span>{{ g.name }}</span>
                        <span class="ml-2 text-xs text-gray-400">
                            {{ $t(g.scope === 'site' ? 'website.wafScopeSite' : 'website.wafScopeGlobal') }}
                            · {{ countCIDRs(g.cidrs) }}
                        </span>
                    </el-option>
                </el-select>
                <el-input v-else v-model="form.matchValue" type="textarea" :rows="2" />
                <div v-if="form.matchType === 'ip_group'" class="text-xs text-gray-400 mt-1">
                    {{ $t('website.wafIPGroupHint') }}
                </div>
                <div v-if="form.matchType === 'geo'" class="text-xs text-gray-400 mt-1">
                    {{ $t('website.wafGeoHint') }}
                </div>
            </el-form-item>
            <el-form-item :label="$t('website.wafAction')">
                <el-radio-group v-model="form.action">
                    <el-radio value="deny">deny</el-radio>
                    <el-radio value="allow">allow</el-radio>
                    <el-radio value="log">log</el-radio>
                </el-radio-group>
            </el-form-item>

            <!-- 「加白时仍检测」只在白名单下有意义：黑名单本来就是拦。
                     开启后加白不等于让这段攻击彻底不可见 —— 仍会检测、只记日志。 -->
            <el-form-item v-if="form.action === 'allow'" :label="$t('website.wafKeepInspect')">
                <el-switch v-model="form.keepInspecting" />
                <div class="text-xs text-gray-400 ml-2">{{ $t('website.wafKeepInspectTip') }}</div>
            </el-form-item>
            <el-form-item :label="$t('website.wafTTL')">
                <el-input-number v-model="form.ttl" :min="0" />
                <span class="ml-2">{{ $t('website.wafTTLTip') }}</span>
            </el-form-item>
            <el-form-item :label="$t('website.wafPriority')">
                <el-input-number v-model="form.priority" :min="1" :max="9999" />
            </el-form-item>
        </el-form>
        <template #footer>
            <el-button @click="drawerVisible = false">{{ $t('commons.button.cancel') }}</el-button>
            <el-button type="primary" @click="onSubmit">{{ $t('commons.button.confirm') }}</el-button>
        </template>
    </el-drawer>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { createWAFRule, updateWAFRule, WAF_GEO_COUNTRIES } from '@/api/modules/waf';

const drawerVisible = ref(false);
const isEdit = ref(false);
const formRef = ref();
const websiteId = ref(0);

const matchTypes = ['ip', 'cidr', 'ip_group', 'geo', 'path', 'ua', 'referer', 'header', 'cookie', 'method', 'expr'];
// 负向操作符（not_*）与正向一一对应，由 Lua 侧 rules.lua 的
// match_ops 批量生成。这里手写列表必须与 DTO 的 oneof 白名单同步 ——
// 少一个，界面上就选不到；多一个，保存会被后端校验拒绝。
const matchOps = [
    'exact',
    'contains',
    'prefix',
    'suffix',
    'wildcard',
    'regex',
    'not_exact',
    'not_contains',
    'not_prefix',
    'not_suffix',
    'not_wildcard',
    'not_regex',
];

const form = reactive<any>({
    id: 0,
    name: '',
    scope: 'site',
    websiteId: 0,
    matchType: 'ip',
    matchValue: '',
    matchOp: 'exact',
    action: 'deny',
    ttl: 0,
    priority: 100,
    enabled: true,
    keepInspecting: false,
});
const rules = reactive({
    required: [{ required: true, message: i18n.global.t('commons.rule.requiredInput'), trigger: 'blur' }],
});

// 当前站点可见的 IP 组。传进来而不是抽屉自己拉 ——
// 打开抽屉时父组件已经加载过，避免每次开抽屉都多一次请求。
const ipGroups = ref<any[]>([]);

/** 只列出启用的组：禁用组即使存在，数据面也不会导出它 */
const availableIPGroups = computed(() => ipGroups.value.filter((g: any) => g.enabled));

/** 统计组里的条目数，用于在下拉里一眼看出组的规模 */
const countCIDRs = (raw?: string): number => {
    if (!raw) return 0;
    return raw.split(/[\n\r,;\t ]+/).filter((v) => v.trim()).length;
};

// 地理规则：matchValue 存的是逗号分隔的地区码，但 UI 用多选。
// 两边格式不同，需要一个中转的数组表示，否则每次勾选都要手动切分拼接。
const geoCountries = WAF_GEO_COUNTRIES;
const geoSelected = computed<string[]>(() =>
    (form.matchValue || '')
        .split(',')
        .map((v) => v.trim().toUpperCase())
        .filter(Boolean),
);

const onGeoChange = (codes: string[]) => {
    // 统一大写并按字典序输出：顺序固定后，用户 diff 配置时能看出真正改了什么
    form.matchValue = [...new Set(codes.map((c) => c.toUpperCase()))].sort().join(',');
};

/** 地区显示名：中文用 zh，其他语言回落到英文名 */
const geoLabel = (c: { code: string; zh: string; en: string }) => {
    const locale = (i18n.global.locale as any)?.value || 'zh';
    const name = String(locale).startsWith('zh') ? c.zh : c.en;
    return `${name} (${c.code})`;
};

const acceptParams = (params: { websiteId: number; rule: any; ipGroups?: any[] }) => {
    websiteId.value = params.websiteId;
    ipGroups.value = params.ipGroups || [];
    isEdit.value = !!params.rule;
    Object.assign(form, {
        id: params.rule?.id || 0,
        name: params.rule?.name || '',
        scope: params.rule?.scope || 'site',
        websiteId: params.rule?.websiteId || params.websiteId,
        matchType: params.rule?.matchType || 'ip',
        matchValue: params.rule?.matchValue || '',
        matchOp: params.rule?.matchOp || 'exact',
        action: params.rule?.action || 'deny',
        ttl: params.rule?.ttl || 0,
        priority: params.rule?.priority || 100,
        enabled: params.rule?.enabled ?? true,
        keepInspecting: params.rule?.keepInspecting ?? false,
    });
    drawerVisible.value = true;
};
const emit = defineEmits(['reload']);

const onSubmit = () => {
    formRef.value.validate(async (valid: boolean) => {
        if (!valid) return;
        if (form.scope === 'site') {
            form.websiteId = websiteId.value;
        }
        // 该开关只对白名单有意义，切换到黑名单时显式清掉，
        // 否则数据库里会留下"deny + keepInspecting"这种无意义的组合。
        if (form.action !== 'allow') {
            form.keepInspecting = false;
        }
        if (isEdit.value) {
            await updateWAFRule(form);
        } else {
            await createWAFRule(form);
        }
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        drawerVisible.value = false;
        emit('reload');
    });
};

defineExpose({ acceptParams });
</script>

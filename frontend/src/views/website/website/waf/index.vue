<template>
    <div v-loading="loading" class="waf-page">
        <!-- 总开关在容器页标题栏右侧（与站点选择器同一行），
             本页只承载启用后的配置与数据。 -->
        <el-empty v-if="!wafEnabled" :description="$t('website.wafDisabledTip')" :image-size="80" />

        <el-tabs v-else v-model="activeTab" class="waf-tabs" @tab-change="onTabChange">
            <!-- ============ 1. 防护配置 ============ -->
            <el-tab-pane name="protect" :label="$t('website.wafProtect')">
                <el-card shadow="never" class="waf-card">
                    <template #header>
                        <div class="card-header">
                            <div class="card-title">
                                <span>{{ $t('website.wafModeTitle') }}</span>
                                <span class="card-sub">{{ $t('website.wafProtectSub') }}</span>
                            </div>
                            <el-button type="primary" :disabled="!optionDirty" @click="saveOption">
                                {{ $t('commons.button.save') }}
                            </el-button>
                        </div>
                    </template>

                    <el-form label-width="150px" label-position="left">
                        <el-form-item :label="$t('website.wafMode')">
                            <div class="field-row">
                                <el-radio-group v-model="option.mode" class="waf-mode-group">
                                    <el-radio-button v-for="m in modeOptions" :key="m.value" :value="m.value">
                                        {{ $t(m.labelKey) }}
                                    </el-radio-button>
                                </el-radio-group>
                                <span class="field-tip">{{ $t(currentModeDescKey) }}</span>
                            </div>
                        </el-form-item>

                        <el-divider class="waf-divider" />

                        <el-form-item :label="$t('website.wafBlockPageTitle')">
                            <el-input
                                v-model="option.blockPageTitle"
                                :placeholder="$t('website.wafBlockPageTitlePlaceholder')"
                                maxlength="200"
                                show-word-limit
                            />
                        </el-form-item>
                        <el-form-item :label="$t('website.wafBlockPageBody')">
                            <el-input
                                v-model="option.blockPageBody"
                                type="textarea"
                                :rows="3"
                                :placeholder="$t('website.wafBlockPageBodyPlaceholder')"
                                maxlength="2000"
                                show-word-limit
                            />
                        </el-form-item>
                        <!-- 色板与色值分开摆：塞进 el-input 的 append 槽时，
                             两个输入框在 flex 行里会被压到只剩一百多像素，
                             颜色值根本看不全。 -->
                        <el-form-item :label="$t('website.wafBlockPageBgColor')">
                            <div class="field-row">
                                <el-color-picker v-model="option.blockPageBgColor" :validate="isValidPageColorValue" />
                                <el-input
                                    v-model="option.blockPageBgColor"
                                    class="p-w-200"
                                    :placeholder="$t('website.wafBlockPageColorPlaceholder')"
                                />
                            </div>
                        </el-form-item>
                        <el-form-item :label="$t('website.wafBlockPageTextColor')">
                            <div class="field-row">
                                <el-color-picker
                                    v-model="option.blockPageTextColor"
                                    :validate="isValidPageColorValue"
                                />
                                <el-input
                                    v-model="option.blockPageTextColor"
                                    class="p-w-200"
                                    :placeholder="$t('website.wafBlockPageColorPlaceholder')"
                                />
                            </div>
                        </el-form-item>
                        <el-form-item v-if="pageColorInvalid">
                            <el-alert :title="$t('website.wafBlockPageColorTip')" type="warning" :closable="false" />
                        </el-form-item>

                        <el-divider class="waf-divider" />

                        <el-row :gutter="24">
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafSemanticLevel')">
                                    <div class="field-row">
                                        <el-select v-model="option.semanticLevel" class="p-w-150">
                                            <el-option
                                                v-for="lv in levelOptions"
                                                :key="lv.value"
                                                :label="$t(lv.labelKey)"
                                                :value="lv.value"
                                            />
                                        </el-select>
                                        <span class="field-tip">{{ $t(levelDescKey(option.semanticLevel)) }}</span>
                                    </div>
                                </el-form-item>
                            </el-col>
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafBotLevel')">
                                    <div class="field-row">
                                        <el-select v-model="option.botLevel" class="p-w-150">
                                            <el-option
                                                v-for="lv in levelOptions"
                                                :key="lv.value"
                                                :label="$t(lv.labelKey)"
                                                :value="lv.value"
                                            />
                                        </el-select>
                                        <span class="field-tip">{{ $t(levelDescKey(option.botLevel)) }}</span>
                                    </div>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-divider class="waf-divider" />

                        <el-form-item :label="$t('website.wafDetectors')">
                            <div class="waf-detector-grid">
                                <el-checkbox
                                    v-for="d in detectorOptions"
                                    :key="d.name"
                                    :value="d.name"
                                    :label="$t(d.labelKey)"
                                    @change="onDetectorToggle(d.name, $event)"
                                />
                                <span class="field-tip block">{{ $t('website.wafDetectorsTip') }}</span>
                            </div>
                        </el-form-item>

                        <el-divider class="waf-divider" />

                        <div class="section-title">{{ $t('website.wafBotProbe') }}</div>
                        <el-row :gutter="24">
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafBotEnable')" label-width="170px">
                                    <div class="field-row">
                                        <el-switch v-model="option.botEnabled" />
                                        <span class="field-tip">{{ $t('website.wafBotEnableTip') }}</span>
                                    </div>
                                </el-form-item>
                                <el-form-item :label="$t('website.wafBotAllowGood')" label-width="170px">
                                    <el-switch v-model="option.allowGoodBots" :disabled="!option.botEnabled" />
                                </el-form-item>
                                <el-form-item :label="$t('website.wafBotBlockBad')" label-width="170px">
                                    <el-switch v-model="option.blockBadBots" :disabled="!option.botEnabled" />
                                </el-form-item>
                            </el-col>
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafProbeEnable')" label-width="170px">
                                    <div class="field-row">
                                        <el-switch v-model="option.probeEnabled" />
                                        <span class="field-tip">{{ $t('website.wafProbeEnableTip') }}</span>
                                    </div>
                                </el-form-item>
                                <el-form-item :label="$t('website.wafProbeThreshold')" label-width="170px">
                                    <div class="field-row">
                                        <el-input-number
                                            v-model="option.probeMaxURIs"
                                            :min="1"
                                            :disabled="!option.probeEnabled"
                                            controls-position="right"
                                            class="p-w-120"
                                        />
                                        <span class="field-unit">{{ $t('website.wafProbeURIs') }}</span>
                                        <el-input-number
                                            v-model="option.probeWindow"
                                            :min="10"
                                            :disabled="!option.probeEnabled"
                                            controls-position="right"
                                            class="p-w-120 ml-3"
                                        />
                                        <span class="field-unit">{{ $t('website.wafProbeWindowUnit') }}</span>
                                    </div>
                                </el-form-item>
                                <el-form-item :label="$t('website.wafProbeMaxRPS')" label-width="170px">
                                    <el-input-number
                                        v-model="option.probeMaxRPS"
                                        :min="1"
                                        :disabled="!option.probeEnabled"
                                        controls-position="right"
                                    />
                                </el-form-item>
                            </el-col>
                        </el-row>
                    </el-form>
                </el-card>

                <el-card shadow="never" class="waf-card">
                    <template #header>
                        <div class="card-header">
                            <div class="card-title">
                                <span>CC {{ $t('website.wafProtect') }}</span>
                                <span class="card-sub">{{ $t('website.wafCCSub') }}</span>
                            </div>
                            <el-button type="primary" :disabled="!ccDirty" @click="saveCC">
                                {{ $t('commons.button.save') }}
                            </el-button>
                        </div>
                    </template>
                    <el-form label-width="150px" label-position="left">
                        <el-form-item :label="$t('commons.table.status')">
                            <div class="field-row">
                                <el-switch v-model="cc.enabled" />
                                <span class="field-tip">{{ $t('website.wafCCEnableTip') }}</span>
                            </div>
                        </el-form-item>
                        <el-row :gutter="24">
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafCCLimit')">
                                    <div class="field-row">
                                        <el-input-number
                                            v-model="cc.limit"
                                            :min="1"
                                            :disabled="!cc.enabled"
                                            controls-position="right"
                                            class="p-w-150"
                                        />
                                        <span class="field-unit">{{ $t('website.wafCCLimitUnit') }}</span>
                                    </div>
                                </el-form-item>
                            </el-col>
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafCCWindow')">
                                    <div class="field-row">
                                        <el-input-number
                                            v-model="cc.window"
                                            :min="1"
                                            :disabled="!cc.enabled"
                                            controls-position="right"
                                            class="p-w-150"
                                        />
                                        <span class="field-unit">{{ $t('website.wafCCWindowUnit') }}</span>
                                    </div>
                                </el-form-item>
                            </el-col>
                        </el-row>
                        <el-row :gutter="24">
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafAction')">
                                    <el-select v-model="cc.action" :disabled="!cc.enabled" class="p-w-150">
                                        <el-option label="deny" value="deny" />
                                        <el-option label="challenge" value="challenge" />
                                        <el-option label="log" value="log" />
                                    </el-select>
                                </el-form-item>
                            </el-col>
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafCCByUri')">
                                    <div class="field-row">
                                        <el-switch v-model="cc.byUri" :disabled="!cc.enabled" />
                                        <span class="field-tip">{{ $t('website.wafCCByUriTip') }}</span>
                                    </div>
                                </el-form-item>
                            </el-col>
                        </el-row>
                        <el-alert :title="$t('website.wafCCTip')" type="info" :closable="false" show-icon />
                    </el-form>
                </el-card>

                <el-card shadow="never" class="waf-card">
                    <template #header>
                        <div class="card-header">
                            <div class="card-title">
                                <span>{{ $t('website.wafNotify') }}</span>
                                <span class="card-sub">{{ $t('website.wafNotifySub') }}</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <el-button :loading="notifyTesting" @click="testNotify">
                                    {{ $t('website.wafNotifyTest') }}
                                </el-button>
                                <el-button type="primary" :disabled="!notifyDirty" @click="saveNotify">
                                    {{ $t('commons.button.save') }}
                                </el-button>
                            </div>
                        </div>
                    </template>
                    <el-form label-width="150px" label-position="left">
                        <el-form-item :label="$t('commons.table.status')">
                            <div class="field-row">
                                <el-switch v-model="notify.enable" />
                                <span class="field-tip">{{ $t('website.wafNotifyEnableTip') }}</span>
                            </div>
                        </el-form-item>
                        <el-form-item :label="$t('website.wafNotifyMethod')">
                            <el-select v-model="notify.method" :disabled="!notify.enable" class="p-w-200">
                                <el-option
                                    v-for="opt in notifyMethods"
                                    :key="opt.value"
                                    :label="$t(opt.labelKey)"
                                    :value="opt.value"
                                />
                            </el-select>
                        </el-form-item>
                        <el-form-item :label="$t('website.wafNotifyURL')">
                            <el-input
                                v-model="notify.url"
                                :disabled="!notify.enable"
                                :placeholder="$t('website.wafNotifyURLPlaceholder')"
                            />
                            <div class="field-tip block">{{ $t('website.wafNotifyTip') }}</div>
                        </el-form-item>
                        <el-form-item v-if="notifyAuthOptions.length" :label="$t('website.wafNotifyAuth')">
                            <div class="field-row">
                                <el-radio-group v-model="notify.authType" :disabled="!notify.enable">
                                    <el-radio
                                        v-for="opt in notifyAuthOptions"
                                        :key="opt.value"
                                        :value="opt.value"
                                        class="mr-4"
                                    >
                                        {{ $t(opt.labelKey) }}
                                    </el-radio>
                                </el-radio-group>
                            </div>
                            <div class="field-tip block">{{ $t('website.wafNotifyAuthTip') }}</div>
                        </el-form-item>
                        <el-form-item v-if="notify.authType === 'keyword'" :label="$t('website.wafNotifyKeyword')">
                            <el-input
                                v-model="notify.keyword"
                                :disabled="!notify.enable"
                                class="p-w-300"
                                :placeholder="$t('website.wafNotifyKeywordPlaceholder')"
                            />
                            <div class="field-tip block">{{ $t('website.wafNotifyKeywordTip') }}</div>
                        </el-form-item>
                        <el-form-item v-if="notify.authType === 'sign'" :label="$t('website.wafNotifySecret')">
                            <el-input
                                v-model="notify.secret"
                                type="password"
                                show-password
                                :disabled="!notify.enable"
                                class="p-w-300"
                                :placeholder="
                                    notify.secretSet
                                        ? $t('website.wafNotifySecretKeepPlaceholder')
                                        : $t('website.wafNotifySecretPlaceholder')
                                "
                            />
                            <div class="field-tip block">{{ $t('website.wafNotifySecretTip') }}</div>
                        </el-form-item>
                    </el-form>
                </el-card>
            </el-tab-pane>

            <!-- ============ 2. 黑白名单 ============ -->
            <el-tab-pane name="rules" :label="$t('website.wafRules')">
                <el-card shadow="never" class="waf-card">
                    <template #header>
                        <div class="card-header">
                            <div class="card-title">
                                <span>{{ $t('website.wafRules') }}</span>
                                <span class="card-sub">{{ $t('website.wafRulesSub') }}</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <template v-if="ruleSortMode">
                                    <el-select v-model="ruleScope" class="p-w-120" @change="loadRules">
                                        <el-option :label="$t('website.wafScopeSite')" value="site" />
                                        <el-option :label="$t('website.wafScopeGlobal')" value="global" />
                                    </el-select>
                                    <el-button type="primary" plain @click="onSaveRuleOrder">
                                        {{ $t('commons.button.save') }}
                                    </el-button>
                                    <el-button @click="onResetRuleOrder">
                                        {{ $t('website.wafSortReset') }}
                                    </el-button>
                                </template>
                                <el-button type="primary" plain @click="openRuleDialog()">
                                    {{ $t('commons.button.create') }}
                                </el-button>
                                <el-tooltip :content="$t('website.wafSortTip')" placement="top">
                                    <el-switch
                                        v-model="ruleSortMode"
                                        :active-text="$t('website.wafSortMode')"
                                        inline-prompt
                                    />
                                </el-tooltip>
                            </div>
                        </div>
                    </template>

                    <el-alert
                        v-if="hasGeoRules && !geoStatus.available"
                        :title="$t('website.wafGeoUnavailable')"
                        :description="$t('website.wafGeoUnavailableTip', { path: geoStatus.path })"
                        type="warning"
                        :closable="false"
                        show-icon
                        class="mb-2"
                    />

                    <el-table ref="ruleTableRef" :data="displayRules" :row-key="'id'" class="waf-table">
                        <template #empty>
                            <el-empty :image-size="70" :description="$t('website.wafNoRules')" />
                        </template>
                        <el-table-column v-if="ruleSortMode" width="44" class-name="rule-drag-col">
                            <template #default>
                                <span class="rule-drag-handle" title="drag">⋮⋮</span>
                            </template>
                        </el-table-column>
                        <el-table-column prop="priority" :label="$t('website.wafPriority')" width="80" />
                        <el-table-column prop="name" :label="$t('commons.table.name')" min-width="120" />
                        <el-table-column :label="$t('website.wafScope')" width="90">
                            <template #default="{ row }">
                                <el-tag size="small" type="info">
                                    {{ $t(row.scope === 'site' ? 'website.wafScopeSite' : 'website.wafScopeGlobal') }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column prop="matchType" :label="$t('website.wafMatchType')" width="110">
                            <template #default="{ row }">
                                <span class="mono">{{ row.matchType }}</span>
                            </template>
                        </el-table-column>
                        <el-table-column
                            prop="matchValue"
                            :label="$t('website.wafMatchValue')"
                            min-width="160"
                            show-overflow-tooltip
                        />
                        <el-table-column prop="matchOp" :label="$t('website.wafMatchOp')" width="110" />
                        <el-table-column :label="$t('website.wafAction')" width="90">
                            <template #default="{ row }">
                                <el-tag
                                    :type="
                                        row.action === 'allow'
                                            ? 'success'
                                            : row.action === 'deny'
                                              ? 'danger'
                                              : 'warning'
                                    "
                                >
                                    {{ row.action }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('commons.table.status')" width="80">
                            <template #default="{ row }">
                                <el-tag :type="row.enabled ? 'success' : 'info'" effect="plain">
                                    {{ row.enabled ? $t('website.wafStatusOn') : $t('website.wafStatusOff') }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column
                            v-if="!ruleSortMode"
                            :label="$t('commons.table.operate')"
                            width="130"
                            fixed="right"
                        >
                            <template #default="{ row }">
                                <el-button link type="primary" @click="openRuleDialog(row)">
                                    {{ $t('commons.button.edit') }}
                                </el-button>
                                <el-button link type="danger" @click="onDelRule(row)">
                                    {{ $t('commons.button.delete') }}
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                </el-card>
            </el-tab-pane>

            <!-- ============ 3. IP 组 ============ -->
            <el-tab-pane name="ipgroup" :label="$t('website.wafIPGroupTitle')">
                <el-card shadow="never" class="waf-card">
                    <template #header>
                        <div class="card-header">
                            <div class="card-title">
                                <span>{{ $t('website.wafIPGroupTitle') }}</span>
                                <span class="card-sub">{{ $t('website.wafIPGroupSub') }}</span>
                            </div>
                            <el-button type="primary" plain @click="onNewIPGroup">
                                {{ $t('commons.button.create') }}
                            </el-button>
                        </div>
                    </template>
                    <el-table :data="ipGroups" class="waf-table">
                        <template #empty>
                            <el-empty :image-size="70" :description="$t('website.wafIPGroupEmpty')" />
                        </template>
                        <el-table-column prop="name" :label="$t('website.wafIPGroupName')" min-width="140">
                            <template #default="{ row }">
                                <span class="mono">{{ row.name }}</span>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('website.wafIPGroupScope')" width="100">
                            <template #default="{ row }">
                                <el-tag size="small" type="info">
                                    {{ $t(row.scope === 'site' ? 'website.wafScopeSite' : 'website.wafScopeGlobal') }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('website.wafIPGroupCount')" width="100">
                            <template #default="{ row }">{{ countCIDRs(row.cidrs) }}</template>
                        </el-table-column>
                        <el-table-column :label="$t('commons.table.status')" width="90">
                            <template #default="{ row }">
                                <el-tag :type="row.enabled ? 'success' : 'info'" effect="plain">
                                    {{ row.enabled ? $t('website.wafStatusOn') : $t('website.wafStatusOff') }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column
                            prop="remark"
                            :label="$t('commons.table.description')"
                            min-width="140"
                            show-overflow-tooltip
                        />
                        <el-table-column :label="$t('commons.table.operate')" width="130" fixed="right">
                            <template #default="{ row }">
                                <el-button link type="primary" @click="onEditIPGroup(row)">
                                    {{ $t('commons.button.edit') }}
                                </el-button>
                                <el-button link type="danger" @click="onDelIPGroup(row)">
                                    {{ $t('commons.button.delete') }}
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                </el-card>
            </el-tab-pane>

            <!-- ============ 4. 统计 ============ -->
            <el-tab-pane name="stat" :label="$t('website.wafStat')">
                <div class="stat-toolbar">
                    <el-radio-group v-model="trendGranularity" size="small" @change="loadStat">
                        <el-radio-button value="day">{{ $t('website.wafTrendByDay') }}</el-radio-button>
                        <el-radio-button value="hour">{{ $t('website.wafTrendByHour') }}</el-radio-button>
                    </el-radio-group>
                    <el-button link type="primary" @click="loadStat">
                        {{ $t('commons.button.refresh') }}
                    </el-button>
                </div>

                <!-- 每个指标一张卡：先给结论（5 个 KPI），再给趋势，最后是各维度分布。 -->
                <el-row :gutter="12" class="stat-kpi-row">
                    <el-col v-for="k in kpiItems" :key="k.key" :xs="12" :sm="8" :md="4">
                        <el-card shadow="never" class="stat-kpi-card">
                            <div class="stat-kpi-value" :class="k.class">{{ k.value }}</div>
                            <div class="stat-kpi-label">{{ $t(k.labelKey) }}</div>
                        </el-card>
                    </el-col>
                </el-row>

                <el-card shadow="never" class="waf-card">
                    <template #header>
                        <div class="card-title">
                            <span>{{ $t('website.wafTrend') }}</span>
                            <span class="card-sub">{{ $t('website.wafTrendSub') }}</span>
                        </div>
                    </template>
                    <VCharts
                        v-if="stat.trend?.length"
                        type="line"
                        height="220px"
                        :option="trendOption"
                        class="waf-stat-chart"
                    />
                    <el-empty v-else :image-size="60" :description="$t('website.wafNoData')" />
                </el-card>

                <el-row :gutter="12">
                    <el-col v-for="d in statDimensions" :key="d.prop" :xs="24" :sm="12" :lg="8">
                        <el-card shadow="never" class="stat-dim-card">
                            <template #header>
                                <div class="card-title">
                                    <span>{{ $t(d.titleKey) }}</span>
                                    <span v-if="d.hintKey" class="card-sub">{{ $t(d.hintKey) }}</span>
                                </div>
                            </template>
                            <div v-if="statItems(d.prop).length" class="waf-bars">
                                <div v-for="item in statItems(d.prop)" :key="item.key" class="waf-bar-row">
                                    <span class="waf-bar-name" :title="item.key">
                                        {{ d.labelFn ? d.labelFn(item.key) : item.key || '-' }}
                                    </span>
                                    <div class="waf-bar-track">
                                        <div
                                            class="waf-bar-fill"
                                            :style="{ width: barWidth(item.count, statItems(d.prop)) }"
                                        />
                                    </div>
                                    <span class="waf-bar-value">{{ item.count }}</span>
                                </div>
                            </div>
                            <el-empty v-else :image-size="50" :description="$t('website.wafNoData')" />
                        </el-card>
                    </el-col>
                </el-row>
            </el-tab-pane>

            <!-- ============ 5. 攻击日志 ============ -->
            <el-tab-pane name="logs" :label="$t('website.wafLogs')">
                <el-card shadow="never" class="waf-card">
                    <template #header>
                        <div class="card-header">
                            <div class="card-title">
                                <span>{{ $t('website.wafLogs') }}</span>
                                <span class="card-sub">{{ $t('website.wafLogsSub') }}</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <el-button plain @click="onExport('csv')">CSV</el-button>
                                <el-button plain @click="onExport('json')">JSON</el-button>
                            </div>
                        </div>
                    </template>
                    <el-form class="waf-filter">
                        <el-form-item :label="$t('website.wafLogSort')">
                            <el-select v-model="logSort" class="p-w-200">
                                <el-option
                                    v-for="opt in sortOptions"
                                    :key="opt.value"
                                    :label="$t(opt.labelKey)"
                                    :value="opt.value"
                                />
                            </el-select>
                        </el-form-item>
                        <el-form-item :label="$t('website.wafAttackType')">
                            <el-input v-model="logReq.attackType" clearable class="p-w-150" />
                        </el-form-item>
                        <el-form-item label="IP">
                            <el-input v-model="logReq.ip" clearable class="p-w-150" />
                        </el-form-item>
                        <el-form-item :label="$t('website.wafAction')">
                            <el-select v-model="logReq.action" clearable class="p-w-120">
                                <el-option label="deny" value="deny" />
                                <el-option label="challenge" value="challenge" />
                                <el-option label="log" value="log" />
                            </el-select>
                        </el-form-item>
                        <el-form-item class="waf-filter-range">
                            <el-date-picker
                                v-model="logTimeRange"
                                type="datetimerange"
                                range-separator="-"
                                :start-placeholder="$t('commons.search.timeStart')"
                                :end-placeholder="$t('commons.search.timeEnd')"
                            />
                        </el-form-item>
                        <div class="waf-filter-actions">
                            <el-button type="primary" @click="searchLogs">{{ $t('commons.button.search') }}</el-button>
                            <el-button @click="resetLogSearch">{{ $t('commons.button.reset') }}</el-button>
                        </div>
                    </el-form>
                    <el-table :data="logs" class="waf-table">
                        <template #empty>
                            <el-empty :image-size="70" :description="$t('website.wafNoData')" />
                        </template>
                        <el-table-column type="expand" width="44">
                            <template #default="{ row }">
                                <el-descriptions :column="1" border class="m-2">
                                    <el-descriptions-item :label="$t('website.wafLayer')">
                                        <el-tag size="small" type="info">
                                            {{ $t(layerLabelKey(row.layer)) }}
                                        </el-tag>
                                    </el-descriptions-item>
                                    <el-descriptions-item :label="$t('website.wafDuration')">
                                        {{ $t('website.wafDurationMs', { n: formatDuration(row.durationMs) }) }}
                                    </el-descriptions-item>
                                    <el-descriptions-item label="Query">{{ row.query || '-' }}</el-descriptions-item>
                                    <el-descriptions-item label="User-Agent">
                                        {{ row.userAgent || '-' }}
                                    </el-descriptions-item>
                                    <el-descriptions-item :label="$t('website.wafDetail')">
                                        {{ row.detail || '-' }}
                                    </el-descriptions-item>
                                    <el-descriptions-item :label="$t('website.wafRequestBody')">
                                        {{ row.requestBody || '-' }}
                                    </el-descriptions-item>
                                    <el-descriptions-item :label="$t('website.wafCopyCurl')">
                                        <el-button link type="primary" @click="onCopyCurl(row)">
                                            {{ $t('website.wafCopyCurl') }}
                                        </el-button>
                                    </el-descriptions-item>
                                </el-descriptions>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('commons.table.date')" width="170">
                            <template #default="{ row }">{{ formatTime(row.createdAt) }}</template>
                        </el-table-column>
                        <el-table-column :label="$t('website.wafAttackType')" width="120">
                            <template #default="{ row }">
                                <el-tag size="small" type="danger" effect="plain">{{ row.attackType }}</el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('website.wafAction')" width="90">
                            <template #default="{ row }">
                                <el-tag
                                    size="small"
                                    :type="row.action === 'deny' ? 'danger' : row.action === 'log' ? 'info' : 'warning'"
                                >
                                    {{ row.action }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('website.wafLayer')" width="110">
                            <template #default="{ row }">
                                <el-tag size="small" type="info" effect="plain">
                                    {{ $t(layerLabelKey(row.layer)) }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column prop="ip" label="IP" width="130" class-name="mono" />
                        <el-table-column prop="area" label="GeoIP" width="140" show-overflow-tooltip />
                        <el-table-column prop="method" :label="$t('website.wafMethod')" width="80" />
                        <el-table-column
                            prop="path"
                            :label="$t('website.wafPath')"
                            min-width="200"
                            show-overflow-tooltip
                        />
                        <el-table-column :label="$t('website.wafDuration')" width="100">
                            <template #default="{ row }">
                                {{ $t('website.wafDurationMs', { n: formatDuration(row.durationMs) }) }}
                            </template>
                        </el-table-column>
                        <el-table-column
                            prop="ruleName"
                            :label="$t('website.wafRuleName')"
                            width="130"
                            show-overflow-tooltip
                        >
                            <template #default="{ row }">
                                <span v-if="row.ruleName">{{ row.ruleName }}</span>
                                <span v-else class="text-gray-400 text-xs">{{ $t('website.wafNoRule') }}</span>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('commons.table.operate')" width="190" fixed="right">
                            <template #default="{ row }">
                                <el-button link type="primary" @click="onLogRule(row, 'allow')">
                                    {{ $t('website.wafAddAllow') }}
                                </el-button>
                                <el-tag v-if="row.falsePositive" type="success" size="small">
                                    {{ $t('website.wafFalsePositiveMarked') }}
                                </el-tag>
                                <el-button v-else link type="warning" @click="onFalsePositive(row)">
                                    {{ $t('website.wafFalsePositiveShort') }}
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                    <el-pagination
                        class="mt-3 justify-end"
                        layout="total, prev, pager, next"
                        :total="logTotal"
                        :page-size="logReq.pageSize"
                        v-model:current-page="logReq.page"
                        @current-change="loadLogs"
                    />
                </el-card>
            </el-tab-pane>

            <!-- ============ 6. IP 名单订阅（仅独立页面） ============ -->
            <el-tab-pane v-if="showIPList" name="iplist" :label="$t('website.wafIPList')">
                <IPListSetting />
            </el-tab-pane>
        </el-tabs>

        <RuleDialog ref="ruleDialogRef" @reload="loadRules" />
        <IPGroupDrawer ref="ipGroupDrawerRef" @reload="loadIPGroups" />
    </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import Sortable from 'sortablejs';
import { ElMessageBox } from 'element-plus';
import i18n from '@/lang';
import { dateFormatSimpleWithSecond } from '@/utils/date';
import { MsgSuccess, MsgWarning } from '@/utils/message';
import VCharts from '@/components/v-charts/index.vue';
import {
    deleteWAFRule,
    createRuleFromWAFLog,
    exportWAFLogs,
    getWAFCCConfig,
    getWAFOption,
    getWAFWebhook,
    markWAFFalsePositive,
    searchWAFLogs,
    searchWAFRules,
    statWAFLogs,
    updateWAFOption,
    updateWAFCCConfig,
    updateWAFWebhook,
    testWAFWebhook,
    reorderWAFRules,
    listWAFIPGroups,
    getWAFGEOStatus,
    deleteWAFIPGroup,
    type WAFWebhookMethod,
    type WAFWebhookAuthType,
} from '@/api/modules/waf';
import {
    buildCurlCommand,
    buildLogSortParam,
    formatDuration,
    formatDisabledDetectors,
    isInvalidPageColor,
    layerLabelKey,
    parseDisabledDetectors,
    WAF_DETECTORS,
    WAF_LOG_SORT_OPTIONS,
    WAF_MODES,
    WAF_LEVELS,
    NAMED_PAGE_COLORS,
    normalizeLevel,
    type WAFLogSortKey,
} from '@/api/modules/waf-helpers';
import RuleDialog from './rule-dialog.vue';
import IPGroupDrawer from './ip-group-drawer.vue';
import IPListSetting from './iplist-setting.vue';

const props = defineProps({
    websiteId: { type: Number, default: 0 },
    wafEnabled: { type: Boolean, default: false },
    // 独立页面（/websites/waf）把 IP 名单订阅并进来，只在这一层出 tabs；
    // 站点详情页里的 WAF 标签不显示它，避免两层 tabs 套娃。
    showIPList: { type: Boolean, default: false },
});

// 外层页面据此收起站点选择器与总开关：IP 名单订阅是全局配置，
// 当前页签下站点维度没有意义。
const emit = defineEmits(['tab-change']);

const loading = ref(false);
const activeTab = ref<'protect' | 'rules' | 'ipgroup' | 'stat' | 'logs' | 'iplist'>('protect');

const rules = ref<any[]>([]);
const logs = ref<any[]>([]);
const logTotal = ref(0);
const ruleDialogRef = ref();
const ipGroupDrawerRef = ref();

const logReq = ref<any>({
    websiteId: props.websiteId,
    attackType: '',
    ip: '',
    action: '',
    page: 1,
    pageSize: 10,
});
const logTimeRange = ref<Date[]>([]);
const stat = ref<any>({ attackType: [], topIP: [], trend: [] });
const trendGranularity = ref<'day' | 'hour'>('day');

// ============ 防护模式与检测器开关 ============
const modeOptions = WAF_MODES;
const detectorOptions = WAF_DETECTORS;
const levelOptions = WAF_LEVELS;

const levelDescKey = (lv?: string) => {
    const item = WAF_LEVELS.find((x) => x.value === normalizeLevel(lv));
    return item?.descKey ?? 'website.wafLevelBalancedDesc';
};

const disabledDetectors = ref<Set<string>>(new Set());

const currentModeDescKey = computed(() => {
    const m = WAF_MODES.find((x) => x.value === option.value.mode);
    return m?.descKey ?? 'website.wafModeBlockDesc';
});

const pageColorInvalid = computed(
    () =>
        isInvalidPageColor(option.value.blockPageBgColor || '') ||
        isInvalidPageColor(option.value.blockPageTextColor || ''),
);

const isValidPageColorValue = (color: string) =>
    /^#[0-9a-fA-F]{6}$/.test(color) || NAMED_PAGE_COLORS.includes(color.toLowerCase());

const onDetectorToggle = (name: string, checked: boolean | (string | number)[]) => {
    const on = checked === true;
    if (on) {
        disabledDetectors.value.delete(name);
    } else {
        disabledDetectors.value.add(name);
    }
    option.value.disabledDetectors = formatDisabledDetectors(disabledDetectors.value);
};

// 后端时间戳是 RFC3339 带时区（2026-10-19T16:16:17+08:00），
// 直接渲染会在 170px 列里折成两行，也看不出本地时间。
const formatTime = (v?: string) => (v ? dateFormatSimpleWithSecond(v) : '-');

const logSort = ref<WAFLogSortKey>('time_desc');
const sortOptions = WAF_LOG_SORT_OPTIONS;

const notifyMethods: { value: WAFWebhookMethod; labelKey: string }[] = [
    { value: 'weCom', labelKey: 'website.wafNotifyMethodWeCom' },
    { value: 'dingTalk', labelKey: 'website.wafNotifyMethodDingTalk' },
    { value: 'feiShu', labelKey: 'website.wafNotifyMethodFeiShu' },
    { value: 'custom', labelKey: 'website.wafNotifyMethodCustom' },
];
const notify = ref<{
    enable: boolean;
    method: WAFWebhookMethod;
    url: string;
    authType: WAFWebhookAuthType;
    keyword: string;
    secret: string;
    secretSet: boolean;
}>({
    enable: false,
    method: 'custom',
    url: '',
    authType: 'none',
    keyword: '',
    secret: '',
    secretSet: false,
});

// 认证方式按渠道过滤：加签只有钉钉支持；自定义关键词企微/钉钉支持；
// 飞书机器人用的是另一套校验（签名在 header），自定义 webhook 由对端自行处理。
const notifyAuthOptions = computed<{ value: WAFWebhookAuthType; labelKey: string }[]>(() => {
    const all: { value: WAFWebhookAuthType; labelKey: string; methods: WAFWebhookMethod[] }[] = [
        { value: 'none', labelKey: 'website.wafNotifyAuthNone', methods: ['weCom', 'dingTalk', 'feiShu', 'custom'] },
        { value: 'keyword', labelKey: 'website.wafNotifyAuthKeyword', methods: ['weCom', 'dingTalk'] },
        { value: 'sign', labelKey: 'website.wafNotifyAuthSign', methods: ['dingTalk'] },
    ];
    return all.filter((o) => o.methods.includes(notify.value.method));
});

// 渠道切换后当前认证方式可能不存在于新渠道的选项里（比如钉钉加签 → 企微），
// 必须在选项变化时回退，否则 radio 群里没有选中项、保存还会被后端 oneof/校验拒绝。
watch(
    () => [notify.value.method, notify.value.authType],
    () => {
        if (notifyAuthOptions.value.length && !notifyAuthOptions.value.some((o) => o.value === notify.value.authType)) {
            notify.value.authType = notifyAuthOptions.value[0].value;
        }
    },
);

// ============ 统计维度 ============
const statDimensions: {
    prop: string;
    titleKey: string;
    hintKey?: string;
    labelFn?: (k: string) => string;
}[] = [
    { prop: 'attackType', titleKey: 'website.wafAttackType' },
    { prop: 'topIP', titleKey: 'website.wafTopIP' },
    {
        prop: 'layer',
        titleKey: 'website.wafStatLayer',
        hintKey: 'website.wafStatLayerHint',
        labelFn: (k: string) => i18n.global.t(layerLabelKey(k)),
    },
    {
        prop: 'action',
        titleKey: 'website.wafStatAction',
        labelFn: (k: string) => {
            const keys: Record<string, string> = {
                deny: 'website.wafStatActionDeny',
                allow: 'website.wafStatActionAllow',
                log: 'website.wafStatActionLog',
                challenge: 'website.wafStatActionChallenge',
            };
            return i18n.global.t(keys[k] || 'website.wafStatActionUnknown');
        },
    },
    { prop: 'area', titleKey: 'website.wafStatArea' },
    { prop: 'topPath', titleKey: 'website.wafStatPath' },
    { prop: 'topUA', titleKey: 'website.wafStatUA' },
    { prop: 'method', titleKey: 'website.wafStatMethod' },
    { prop: 'topRule', titleKey: 'website.wafStatRule' },
    { prop: 'website', titleKey: 'website.wafStatWebsite', hintKey: 'website.wafStatWebsiteHint' },
    { prop: 'duration', titleKey: 'website.wafStatDuration' },
    { prop: 'falsePositive', titleKey: 'website.wafStatFalsePositiveType' },
];

const statItems = (prop: string) => stat.value[prop] || [];

const barWidth = (count: number, items: any[]) => {
    const max = Math.max(1, ...items.map((i: any) => i.count || 0));
    return `${Math.max(3, Math.round(((count || 0) / max) * 100))}%`;
};

// 每个 KPI 一张卡；命中数与误报需要一眼可见，用色区分而不是靠位置。
const kpiItems = computed(() => [
    { key: 'total', labelKey: 'website.wafStatTotal', value: stat.value.summary?.total ?? 0, class: '' },
    { key: 'denied', labelKey: 'website.wafStatDenied', value: stat.value.summary?.denied ?? 0, class: 'danger' },
    {
        key: 'uniqueIPs',
        labelKey: 'website.wafStatUniqueIPs',
        value: stat.value.summary?.uniqueIPs ?? 0,
        class: '',
    },
    {
        key: 'avg',
        labelKey: 'website.wafStatAvgDuration',
        value: formatDuration(stat.value.summary?.avgDurationMs),
        class: '',
    },
    {
        key: 'fp',
        labelKey: 'website.wafStatFalsePositive',
        value: stat.value.summary?.falsePositive ?? 0,
        class: stat.value.summary?.falsePositive > 0 ? 'warn' : '',
    },
]);

const trendOption = computed(() => {
    const trend = stat.value.trend || [];
    return {
        xData: trend.map((item: any) => item.key),
        yData: [{ name: i18n.global.t('website.wafTrend'), data: trend.map((item: any) => item.count || 0) }],
        formatStr: i18n.global.t('website.wafTrendUnit'),
        legend: { show: false },
        grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
    };
});

const cc = ref<any>({
    websiteId: props.websiteId,
    limit: 0,
    window: 60,
    action: 'deny',
    byUri: false,
    enabled: false,
});
const option = ref<any>({
    websiteId: props.websiteId,
    botEnabled: false,
    allowGoodBots: true,
    blockBadBots: true,
    probeEnabled: false,
    probeMaxURIs: 60,
    probeWindow: 60,
    probeMaxRPS: 120,
});

const ipGroups = ref<any[]>([]);

const countCIDRs = (raw?: string): number => {
    if (!raw) return 0;
    return raw.split(/[\n\r,;\t ]+/).filter((v) => v.trim()).length;
};

// ============ 保存按钮的脏检查 ============
//
// 三张卡对应三个后端接口（option / cc / webhook），各自持有一份提交快照：
// 内容与快照一致时保存按钮禁用。用显式 payload 而不是直接序列化 ref，
// 是因为 ref 里还混着 id/createdAt 之类不参与提交的字段，
// 它们变化会让「没有任何改动」也亮起来。
const snapshot = (v: unknown) => JSON.stringify(v);

const optionPayload = computed(() => ({
    websiteId: props.websiteId,
    botEnabled: option.value.botEnabled,
    allowGoodBots: option.value.allowGoodBots,
    blockBadBots: option.value.blockBadBots,
    probeEnabled: option.value.probeEnabled,
    probeMaxURIs: option.value.probeMaxURIs,
    probeWindow: option.value.probeWindow,
    probeMaxRPS: option.value.probeMaxRPS,
    mode: option.value.mode,
    blockPageTitle: option.value.blockPageTitle || '',
    blockPageBody: option.value.blockPageBody || '',
    blockPageBgColor: option.value.blockPageBgColor || '',
    blockPageTextColor: option.value.blockPageTextColor || '',
    semanticLevel: normalizeLevel(option.value.semanticLevel),
    botLevel: normalizeLevel(option.value.botLevel),
    disabledDetectors: formatDisabledDetectors(disabledDetectors.value),
}));
const optionSnap = ref('');
const optionDirty = computed(() => snapshot(optionPayload.value) !== optionSnap.value);
const markOptionClean = async () => {
    await nextTick();
    optionSnap.value = snapshot(optionPayload.value);
};

const ccPayload = computed(() => ({
    websiteId: props.websiteId,
    enabled: cc.value.enabled,
    limit: cc.value.limit,
    window: cc.value.window,
    action: cc.value.action,
    byUri: cc.value.byUri,
}));
const ccSnap = ref('');
const ccDirty = computed(() => snapshot(ccPayload.value) !== ccSnap.value);
const markCCClean = async () => {
    await nextTick();
    ccSnap.value = snapshot(ccPayload.value);
};

const notifyPayload = computed(() => ({
    enable: notify.value.enable,
    method: notify.value.method,
    url: notify.value.url.trim(),
    authType: notify.value.authType,
    keyword: notify.value.keyword.trim(),
    // 空串 = 沿用已保存的密钥，后端不会把原文带回来
    secret: notify.value.secret.trim(),
}));
const notifySnap = ref('');
const notifyDirty = computed(() => snapshot(notifyPayload.value) !== notifySnap.value);
const markNotifyClean = async () => {
    await nextTick();
    notifySnap.value = snapshot(notifyPayload.value);
};

const onNewIPGroup = () => {
    ipGroupDrawerRef.value.acceptParams({ websiteId: props.websiteId });
};

const onEditIPGroup = (row: any) => {
    ipGroupDrawerRef.value.acceptParams({ websiteId: props.websiteId, group: row });
};

const onDelIPGroup = async (row: any) => {
    await ElMessageBox.confirm(
        i18n.global.t('website.wafIPGroupDeleteConfirm', { name: row.name }),
        i18n.global.t('commons.button.delete'),
        { type: 'warning' },
    );
    await deleteWAFIPGroup(row.id);
    MsgSuccess(i18n.global.t('commons.msg.deleteSuccess'));
    loadIPGroups();
};

const loadIPGroups = async () => {
    const res = await listWAFIPGroups(props.websiteId);
    ipGroups.value = res.data || [];
};

const geoStatus = ref<{ available: boolean; path: string }>({ available: true, path: '' });

const loadGeoStatus = async () => {
    try {
        const res = await getWAFGEOStatus();
        geoStatus.value = res.data || { available: true, path: '' };
    } catch (e) {
        geoStatus.value = { available: true, path: '' };
    }
};

const hasGeoRules = computed(() => rules.value.some((r: any) => r.matchType === 'geo'));

const loadRules = async () => {
    const res = await searchWAFRules({ websiteId: props.websiteId });
    rules.value = res.data || [];
};

const loadLogs = async () => {
    const { orderBy, order } = buildLogSortParam(logSort.value);
    const res = await searchWAFLogs({ ...logReq.value, orderBy, order });
    logs.value = res.data?.items || [];
    logTotal.value = res.data?.total || 0;
};

const searchLogs = () => {
    logReq.value.page = 1;
    logReq.value.startTime = logTimeRange.value?.[0] ? Math.floor(new Date(logTimeRange.value[0]).getTime() / 1000) : 0;
    logReq.value.endTime = logTimeRange.value?.[1] ? Math.floor(new Date(logTimeRange.value[1]).getTime() / 1000) : 0;
    loadLogs();
};

const resetLogSearch = () => {
    logReq.value = { websiteId: props.websiteId, attackType: '', ip: '', action: '', page: 1, pageSize: 10 };
    logTimeRange.value = [];
    loadLogs();
};

const loadStat = async () => {
    const res = await statWAFLogs({ websiteId: props.websiteId, trendGranularity: trendGranularity.value });
    stat.value = res.data || { attackType: [], topIP: [], trend: [] };
};

const loadCC = async () => {
    const res = await getWAFCCConfig(props.websiteId);
    if (res.data) {
        cc.value = res.data;
    }
    await markCCClean();
};

const saveCC = async () => {
    await updateWAFCCConfig(ccPayload.value);
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    await markCCClean();
};

const loadOption = async () => {
    const res = await getWAFOption(props.websiteId);
    if (res.data) {
        option.value = res.data;
        if (!option.value.mode) {
            option.value.mode = 'block';
        }
        option.value.semanticLevel = normalizeLevel(option.value.semanticLevel);
        option.value.botLevel = normalizeLevel(option.value.botLevel);
        disabledDetectors.value = parseDisabledDetectors(option.value.disabledDetectors);
    }
    await markOptionClean();
};

const saveOption = async () => {
    if (pageColorInvalid.value) {
        MsgWarning(i18n.global.t('website.wafBlockPageColorTip'));
        return;
    }
    await updateWAFOption(optionPayload.value);
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    await markOptionClean();
};

const loadNotify = async () => {
    const res = await getWAFWebhook();
    if (res.data) {
        notify.value = { ...notify.value, ...res.data };
    }
    await markNotifyClean();
};

const notifyTesting = ref(false);
// 用当前表单值测试，不要求先保存：配置对不对应该在点「保存」之前就能确认。
const testNotify = async () => {
    if (!notify.value.url.trim()) {
        MsgWarning(i18n.global.t('website.wafNotifyURLRequired'));
        return;
    }
    notifyTesting.value = true;
    try {
        await testWAFWebhook(notifyPayload.value as any);
        MsgSuccess(i18n.global.t('website.wafNotifyTestOk'));
    } catch (e) {
        // 请求拦截器已把后端带回的上游原因弹出来，这里不重复提示
    } finally {
        notifyTesting.value = false;
    }
};

const saveNotify = async () => {
    if (notify.value.enable && !notify.value.url.trim()) {
        MsgWarning(i18n.global.t('website.wafNotifyURLRequired'));
        return;
    }
    if (notify.value.enable && notify.value.authType === 'keyword' && !notify.value.keyword.trim()) {
        MsgWarning(i18n.global.t('website.wafNotifyKeywordRequired'));
        return;
    }
    await updateWAFWebhook(notifyPayload.value as any);
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    // 密钥保存后后端不回传原文，重新拉一次让占位文案从「粘贴密钥」变成「留空不修改」，
    // 同时清掉输入框，避免密钥原文常驻在前端内存里。
    notify.value.secret = '';
    await loadNotify();
};

const onCopyCurl = async (row: any) => {
    const cmd = buildCurlCommand({
        method: row.method,
        path: row.path,
        query: row.query,
        userAgent: row.userAgent,
        requestBody: row.requestBody,
        websiteName: row.websiteName,
    });
    try {
        await navigator.clipboard.writeText(cmd);
        MsgSuccess(i18n.global.t('website.wafCurlCopied'));
    } catch (e) {
        ElMessageBox.alert(cmd, i18n.global.t('website.wafCopyCurl'), {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            type: 'warning',
            customClass: 'waf-curl-fallback',
        }).catch(() => undefined);
    }
};

// ============ 名单拖动排序 ============
const ruleSortMode = ref(false);
const ruleTableRef = ref();
const displayRules = computed(() =>
    ruleSortMode.value ? rules.value.filter((r: any) => r.scope === ruleScope.value) : rules.value,
);
let ruleSortable: Sortable | null = null;

const destroyRuleSortable = () => {
    if (ruleSortable) {
        ruleSortable.destroy();
        ruleSortable = null;
    }
};

const setupRuleSortable = async () => {
    await nextTick();
    destroyRuleSortable();
    const el = ruleTableRef.value?.$el?.querySelector('.el-table__body-wrapper tbody');
    if (!el) return;
    ruleSortable = Sortable.create(el, {
        animation: 150,
        ghostClass: 'rule-drag-ghost',
        handle: '.rule-drag-handle',
        onEnd: (evt: any) => {
            const list = [...displayRules.value];
            const [moved] = list.splice(evt.oldIndex, 1);
            list.splice(evt.newIndex, 0, moved);
            list.forEach((r: any, i: number) => {
                r.priority = (i + 1) * 10;
            });
            rules.value = rules.value.map((r: any) => list.find((x: any) => x.id === r.id) || r);
        },
    });
};

const ruleScope = ref<'site' | 'global'>('site');

const onSaveRuleOrder = async () => {
    const ids = rules.value
        .filter((r: any) => r.scope === ruleScope.value)
        .map((r: any) => r.id)
        .filter((id: number) => id);
    if (!ids.length) {
        MsgWarning(i18n.global.t('website.wafNoData'));
        return;
    }
    await reorderWAFRules({ ids });
    MsgSuccess(i18n.global.t('website.wafSortSaved'));
    loadRules();
};

const onResetRuleOrder = () => {
    loadRules();
};

watch(ruleSortMode, async (on) => {
    if (on) {
        setupRuleSortable();
    } else {
        destroyRuleSortable();
        loadRules();
    }
});

onUnmounted(destroyRuleSortable);

const openRuleDialog = (rule?: any) => {
    ruleDialogRef.value.acceptParams({
        websiteId: props.websiteId,
        rule: rule ? { ...rule } : null,
        ipGroups: ipGroups.value,
    });
};

const onDelRule = (row: any) => {
    deleteWAFRule(row.id).then(() => {
        MsgSuccess(i18n.global.t('commons.msg.deleteSuccess'));
        loadRules();
    });
};

const onLogRule = (row: any, action: string) => {
    createRuleFromWAFLog(row.id, action).then(() => {
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        loadRules();
    });
};

const onFalsePositive = (row: any) => {
    markWAFFalsePositive(row.id).then(() => {
        MsgSuccess(i18n.global.t('website.wafFalsePositiveDone'));
        loadLogs();
        loadRules();
    });
};

const onExport = (format: string) => {
    const { orderBy, order } = buildLogSortParam(logSort.value);
    exportWAFLogs({ ...logReq.value, orderBy, order, format }).then((res) => {
        const blob = new Blob([res as any]);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `waf_logs.${format}`;
        a.click();
        window.URL.revokeObjectURL(url);
    });
};

// 每个页签按需加载：首屏只拉防护配置，规则/日志/统计各自在切入时再查。
// 日志由 cron 每分钟入库，每次切回都要重查，否则计数会停留在旧值。
const tabLoaded = ref<Record<string, boolean>>({});
const onTabChange = (name: string | number) => {
    const tab = String(name);
    emit('tab-change', tab);
    if (tab === 'protect') return;
    if (tab === 'rules') {
        loadRules();
        loadGeoStatus();
        loadIPGroups();
    } else if (tab === 'ipgroup') {
        loadIPGroups();
    } else if (tab === 'stat') {
        loadStat();
    } else if (tab === 'logs') {
        loadLogs();
    }
    tabLoaded.value[tab] = true;
};

watch(logSort, () => {
    logReq.value.page = 1;
    loadLogs();
});

let protectLoading = false;
const loadProtect = async () => {
    if (protectLoading) return;
    protectLoading = true;
    try {
        await Promise.all([loadOption(), loadCC(), loadNotify()]);
    } finally {
        protectLoading = false;
    }
};

watch(
    () => props.wafEnabled,
    (val) => {
        if (val) {
            activeTab.value = 'protect';
            tabLoaded.value = {};
            loadProtect();
        }
    },
);

onMounted(() => {
    if (props.wafEnabled) {
        loadProtect();
    }
});
</script>

<style scoped>
.waf-page {
    padding-bottom: 8px;
}

/* 页签：与 Element 默认样式区分一点，避免和上级页签混在一起看不出来 */
.waf-tabs :deep(.el-tabs__header) {
    margin-bottom: 12px;
}

.waf-card {
    margin-bottom: 12px;
    border: 1px solid var(--el-border-color-lighter);
}

.waf-card:last-child {
    margin-bottom: 0;
}

.card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
}

.card-title {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 14px;
    font-weight: 600;
    color: var(--el-text-color-primary);
}

.card-sub {
    font-size: 12px;
    font-weight: 400;
    color: var(--el-text-color-secondary);
}

.section-title {
    margin: 4px 0 10px;
    font-size: 13px;
    font-weight: 600;
    color: var(--el-text-color-regular);
}

/* 控件与其后的说明文字必须留出间距。
   之前用 mt-1 只给了 4px 且仍在同一行，读起来是「按钮+紧贴的一串灰字」。 */
.field-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    width: 100%;
}

.field-tip {
    flex: 1 1 auto;
    min-width: 180px;
    font-size: 12px;
    line-height: 1.6;
    color: var(--el-text-color-secondary);
}

.field-tip.block {
    display: block;
    margin-top: 4px;
    min-width: 100%;
}

.field-unit {
    font-size: 12px;
    color: var(--el-text-color-secondary);
}

.field-unit + .el-input-number {
    margin-left: 12px;
}

.waf-divider {
    margin: 6px 0 14px;
}

.waf-mode-group {
    display: inline-flex;
}

/* 检测器：两列以上网格，15 项能在一屏内看完 */
.waf-detector-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
    gap: 2px 16px;
    width: 100%;
}

.waf-table {
    width: 100%;
}

/* 日志筛选：grid 而不是 el-form inline。inline 布局下日期区间宽度过大时
   换行顺序不可控（实测「搜索/重置」会被挤到下一行左侧、日期跑到右边）。 */
.waf-filter {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
    gap: 0 16px;
    align-items: start;
    margin-bottom: 4px;
}

.waf-filter :deep(.el-form-item) {
    margin-right: 0;
    margin-bottom: 12px;
}

.waf-filter-range {
    grid-column: span 2;
}

.waf-filter-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-bottom: 12px;
}

.mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

/* ============ 统计 ============ */
.stat-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
}

.stat-kpi-row {
    margin-bottom: 4px;
}

.stat-kpi-card {
    margin-bottom: 12px;
    border: 1px solid var(--el-border-color-lighter);
}

.stat-kpi-card :deep(.el-card__body) {
    padding: 14px 16px;
}

.stat-kpi-value {
    font-size: 24px;
    font-weight: 600;
    line-height: 1.2;
    color: var(--el-text-color-primary);
}

.stat-kpi-value.danger {
    color: var(--el-color-danger);
}

.stat-kpi-value.warn {
    color: var(--el-color-warning);
}

.stat-kpi-label {
    margin-top: 4px;
    font-size: 12px;
    color: var(--el-text-color-secondary);
}

.stat-dim-card {
    height: calc(100% - 12px);
    margin-bottom: 12px;
    border: 1px solid var(--el-border-color-lighter);
}

.stat-dim-card :deep(.el-card__header) {
    padding: 10px 16px;
}

.stat-dim-card :deep(.el-card__body) {
    padding: 12px 16px;
}

/* 横向条形：比一列 el-tag 更易比较大小，且长 IP 不会撑破布局 */
.waf-bars {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.waf-bar-row {
    display: flex;
    align-items: center;
    gap: 10px;
}

.waf-bar-name {
    flex: 0 0 110px;
    overflow: hidden;
    font-size: 13px;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.waf-bar-track {
    flex: 1;
    height: 8px;
    overflow: hidden;
    border-radius: 4px;
    background-color: var(--el-fill-color);
}

.waf-bar-fill {
    height: 100%;
    border-radius: 4px;
    background-color: var(--el-color-danger);
}

.waf-bar-value {
    flex: 0 0 auto;
    min-width: 36px;
    font-size: 13px;
    text-align: right;
    color: var(--el-text-color-regular);
}

/* 拖动手柄：只在排序模式出现 */
.rule-drag-handle {
    cursor: grab;
    color: var(--el-text-color-placeholder);
    letter-spacing: -2px;
    user-select: none;
}

.rule-drag-handle:active {
    cursor: grabbing;
}

.rule-drag-ghost {
    opacity: 0.5;
    background: var(--el-color-primary-light-9);
}
</style>

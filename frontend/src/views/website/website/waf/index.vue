<template>
    <div v-loading="loading">
        <!-- 总开关在容器页标题栏右侧（与站点选择器同一行），
             本页只承载启用后的配置与数据：防护配置一个页签，
             日志独立一个页签，结构与其它带列表的功能页保持一致。 -->
        <el-empty v-if="!wafEnabled" :description="$t('website.wafDisabledTip')" :image-size="80" />
        <el-tabs v-else v-model="activeTab" class="waf-tabs" @tab-change="onTabChange">
            <!-- 外层容器页签已叫「WAF 防护」，这里第一个内层页签必须换文案，
                 否则用户看到两行「WAF 防护」。 -->
            <el-tab-pane :label="$t('website.wafProtect')" name="protect">
                <el-card shadow="never">
                    <template #header>
                        <div class="card-header">
                            <span>{{ $t('website.wafStat') }}</span>
                            <el-button link type="primary" @click="loadStat">
                                {{ $t('commons.button.refresh') }}
                            </el-button>
                        </div>
                    </template>
                    <!-- 概览数字先给结论，再给分布：三个 KPI 平铺一行，
                         趋势独占整行（时间维度需要宽度），类型与来源 IP 并排。 -->
                    <div class="waf-kpi">
                        <div class="waf-kpi-item">
                            <span class="waf-kpi-value">{{ statTotal }}</span>
                            <span class="waf-kpi-label">{{ $t('website.wafStatTotal') }}</span>
                        </div>
                        <div class="waf-kpi-item">
                            <span class="waf-kpi-value">{{ stat.attackType?.length || 0 }}</span>
                            <span class="waf-kpi-label">{{ $t('website.wafAttackType') }}</span>
                        </div>
                        <div class="waf-kpi-item">
                            <span class="waf-kpi-value">{{ stat.topIP?.length || 0 }}</span>
                            <span class="waf-kpi-label">{{ $t('website.wafTopIP') }}</span>
                        </div>
                    </div>

                    <div class="waf-stat-trend">
                        <div class="waf-stat-title">
                            {{ $t('website.wafTrend') }}
                            <!-- 后端已支持 hour 粒度（trendGranularity），此前前端从未发送过，
                                 一直是死代码。日粒度下小时级的峰值完全看不出来。 -->
                            <el-radio-group v-model="trendGranularity" size="small" @change="loadStat">
                                <el-radio-button value="day">{{ $t('website.wafTrendByDay') }}</el-radio-button>
                                <el-radio-button value="hour">{{ $t('website.wafTrendByHour') }}</el-radio-button>
                            </el-radio-group>
                        </div>
                        <VCharts
                            v-if="stat.trend?.length"
                            type="line"
                            height="180px"
                            :option="trendOption"
                            class="waf-stat-chart"
                        />
                        <el-empty v-else :image-size="60" :description="$t('website.wafNoData')" />
                    </div>

                    <el-row :gutter="16" class="mt-3">
                        <el-col :xs="24" :md="12">
                            <div class="waf-stat-title">{{ $t('website.wafAttackType') }}</div>
                            <div v-if="stat.attackType?.length" class="waf-bars">
                                <div v-for="item in stat.attackType" :key="item.key" class="waf-bar-row">
                                    <span class="waf-bar-name">{{ item.key || '-' }}</span>
                                    <div class="waf-bar-track">
                                        <div class="waf-bar-fill" :style="{ width: barWidth(item.count) }" />
                                    </div>
                                    <span class="waf-bar-value">{{ item.count }}</span>
                                </div>
                            </div>
                            <el-empty v-else :image-size="60" :description="$t('website.wafNoData')" />
                        </el-col>
                        <el-col :xs="24" :md="12">
                            <div class="waf-stat-title">{{ $t('website.wafTopIP') }}</div>
                            <div v-if="stat.topIP?.length" class="waf-bars">
                                <div v-for="item in stat.topIP" :key="item.key" class="waf-bar-row">
                                    <span class="waf-bar-name waf-bar-ip">{{ item.key }}</span>
                                    <div class="waf-bar-track">
                                        <div
                                            class="waf-bar-fill waf-bar-fill-ip"
                                            :style="{ width: barWidth(item.count) }"
                                        />
                                    </div>
                                    <span class="waf-bar-value">{{ item.count }}</span>
                                </div>
                            </div>
                            <el-empty v-else :image-size="60" :description="$t('website.wafNoData')" />
                        </el-col>
                    </el-row>
                </el-card>

                <!-- 攻击通知：后端 pushWebhooks 自上线起就实现了（企微/钉钉/飞书/custom），
                     但一直没有任何界面能配，等于功能闲置。这里补上配置入口。 -->
                <el-card shadow="never" class="mt-2">
                    <template #header>
                        <div class="card-header">
                            <span>{{ $t('website.wafNotify') }}</span>
                            <div class="flex items-center gap-3">
                                <el-switch v-model="notify.enable" @change="onNotifyToggle" />
                                <el-button type="primary" plain @click="saveNotify">
                                    {{ $t('commons.button.save') }}
                                </el-button>
                            </div>
                        </div>
                    </template>
                    <el-form label-width="140px">
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
                            <!-- 启用时地址必填：后端 required_if 也会拦一道，
                                 这里是提前给反馈，不让用户提交完才看到报错。 -->
                            <el-input
                                v-model="notify.url"
                                :disabled="!notify.enable"
                                :placeholder="$t('website.wafNotifyURLPlaceholder')"
                            />
                        </el-form-item>
                    </el-form>
                    <el-alert :title="$t('website.wafNotifyTip')" type="info" :closable="false" />
                </el-card>

                <el-card shadow="never" class="mt-2">
                    <template #header>
                        <div class="card-header">
                            <span>CC {{ $t('website.wafProtect') }}</span>
                            <div class="flex items-center gap-3">
                                <el-switch v-model="cc.enabled" @change="saveCC" />
                                <el-button type="primary" plain :disabled="!cc.enabled" @click="saveCC">
                                    {{ $t('commons.button.save') }}
                                </el-button>
                            </div>
                        </div>
                    </template>
                    <!-- 关闭时把阈值等参数置灰但保留取值：直接隐藏会让用户
                         重新开启后要再填一遍，配置也就无法"备而不用"。 -->
                    <el-row :gutter="24">
                        <el-col :xs="24" :md="12">
                            <el-form label-width="120px">
                                <el-form-item :label="$t('website.wafCCLimit')">
                                    <el-input-number v-model="cc.limit" :min="1" :disabled="!cc.enabled" />
                                </el-form-item>
                                <el-form-item :label="$t('website.wafCCWindow')">
                                    <el-input-number v-model="cc.window" :min="1" :disabled="!cc.enabled" />
                                </el-form-item>
                            </el-form>
                        </el-col>
                        <el-col :xs="24" :md="12">
                            <el-form label-width="120px">
                                <el-form-item :label="$t('website.wafAction')">
                                    <el-select v-model="cc.action" :disabled="!cc.enabled" class="p-w-150">
                                        <el-option label="deny" value="deny" />
                                        <el-option label="challenge" value="challenge" />
                                        <el-option label="log" value="log" />
                                    </el-select>
                                </el-form-item>
                                <el-form-item :label="$t('website.wafCCByUri')">
                                    <el-switch v-model="cc.byUri" :disabled="!cc.enabled" @change="saveCC" />
                                </el-form-item>
                            </el-form>
                        </el-col>
                    </el-row>
                    <el-alert :title="$t('website.wafCCTip')" type="info" :closable="false" />
                </el-card>

                <!-- IP 组：可复用的 IP/CIDR 集合。
                     一个「公司出口 IP 段」往往几十上百条，此前只能一条条建规则 ——
                     规则表膨胀、界面上一片重复行。规则里用 match_type=ip_group 引用组名。 -->
                <el-card shadow="never" class="mt-2">
                    <template #header>
                        <div class="card-header">
                            <span>{{ $t('website.wafIPGroupTitle') }}</span>
                            <el-button type="primary" plain @click="onNewIPGroup">
                                {{ $t('commons.button.create') }}
                            </el-button>
                        </div>
                    </template>
                    <el-form label-width="140px">
                        <el-form-item :label="$t('website.wafIPGroupName')" prop="name" :rules="ipGroupNameRules">
                            <el-input
                                v-model="ipGroupDraft.name"
                                class="p-w-200"
                                :placeholder="$t('website.wafIPGroupNamePlaceholder')"
                            />
                        </el-form-item>
                        <el-form-item :label="$t('website.wafIPGroupScope')">
                            <el-radio-group v-model="ipGroupDraft.scope">
                                <el-radio value="global">{{ $t('website.wafScopeGlobal') }}</el-radio>
                                <el-radio value="site">{{ $t('website.wafScopeSite') }}</el-radio>
                            </el-radio-group>
                        </el-form-item>
                        <el-form-item :label="$t('website.wafIPGroupCIDRs')">
                            <el-input
                                v-model="ipGroupDraft.cidrs"
                                type="textarea"
                                :rows="5"
                                :placeholder="$t('website.wafIPGroupCIDRsPlaceholder')"
                            />
                            <div class="text-xs text-gray-400 mt-1">
                                {{ $t('website.wafIPGroupCIDRsTip') }}
                            </div>
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" @click="onSaveIPGroup">
                                {{ $t('commons.button.save') }}
                            </el-button>
                            <el-button @click="onResetIPGroupDraft">{{ $t('commons.button.reset') }}</el-button>
                        </el-form-item>
                    </el-form>

                    <el-table :data="ipGroups" class="mt-2">
                        <el-table-column prop="name" :label="$t('website.wafIPGroupName')" min-width="120" />
                        <el-table-column :label="$t('website.wafIPGroupScope')" width="90">
                            <template #default="{ row }">
                                <el-tag size="small" type="info">
                                    {{ $t(row.scope === 'site' ? 'website.wafScopeSite' : 'website.wafScopeGlobal') }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('website.wafIPGroupCount')" width="90">
                            <template #default="{ row }">{{ countCIDRs(row.cidrs) }}</template>
                        </el-table-column>
                        <el-table-column :label="$t('commons.table.operate')" width="140" fixed="right">
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

                <!-- 防护模式三态 + 拦截页定制 + 检测器开关。
                     后端 model / exporter / Lua 数据面都已支持，
                     此前界面上没有任何入口，等于三个功能都不可用。 -->
                <el-card shadow="never" class="mt-2">
                    <template #header>
                        <div class="card-header">
                            <span>{{ $t('website.wafModeTitle') }}</span>
                            <el-button type="primary" plain @click="saveOption">
                                {{ $t('commons.button.save') }}
                            </el-button>
                        </div>
                    </template>
                    <el-form label-width="140px">
                        <el-form-item :label="$t('website.wafMode')">
                            <el-radio-group v-model="option.mode" class="waf-mode-group">
                                <el-radio-button v-for="m in modeOptions" :key="m.value" :value="m.value">
                                    {{ $t(m.labelKey) }}
                                </el-radio-button>
                            </el-radio-group>
                            <div class="text-xs text-gray-400 mt-1">
                                {{ $t(currentModeDescKey) }}
                            </div>
                        </el-form-item>

                        <el-divider class="my-1" />

                        <!-- 拦截页定制。标题与正文会展示给所有访问者（含攻击者），
                             后端已做 HTML 转义，这里只做长度与颜色格式的前置校验。 -->
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
                        <el-form-item :label="$t('website.wafBlockPageBgColor')">
                            <el-input v-model="option.blockPageBgColor" class="p-w-200">
                                <template #append>
                                    <el-color-picker
                                        v-model="option.blockPageBgColor"
                                        :validate="isValidPageColorValue"
                                    />
                                </template>
                            </el-input>
                        </el-form-item>
                        <el-form-item :label="$t('website.wafBlockPageTextColor')">
                            <el-input v-model="option.blockPageTextColor" class="p-w-200">
                                <template #append>
                                    <el-color-picker
                                        v-model="option.blockPageTextColor"
                                        :validate="isValidPageColorValue"
                                    />
                                </template>
                            </el-input>
                        </el-form-item>
                        <el-form-item v-if="pageColorInvalid">
                            <el-alert :title="$t('website.wafBlockPageColorTip')" type="warning" :closable="false" />
                        </el-form-item>

                        <el-divider class="my-1" />

                        <!-- 保护强度分档。四档的差异都对应真实机制：
                             语义层 high = 绕过前置快速筛（召回更高、CPU 更大）；
                             bot 层 high = 额外把空 User-Agent 当可疑。
                             CC 防护的 action（deny/challenge/log）是另一维度
                             （命中后怎么处置），在上面那张卡里单独配。 -->
                        <el-row :gutter="24">
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafSemanticLevel')">
                                    <el-select v-model="option.semanticLevel" class="p-w-200">
                                        <el-option
                                            v-for="lv in levelOptions"
                                            :key="lv.value"
                                            :label="$t(lv.labelKey)"
                                            :value="lv.value"
                                        />
                                    </el-select>
                                    <div class="text-xs text-gray-400 mt-1">
                                        {{ $t(levelDescKey(option.semanticLevel)) }}
                                    </div>
                                </el-form-item>
                            </el-col>
                            <el-col :xs="24" :md="12">
                                <el-form-item :label="$t('website.wafBotLevel')">
                                    <el-select v-model="option.botLevel" class="p-w-200">
                                        <el-option
                                            v-for="lv in levelOptions"
                                            :key="lv.value"
                                            :label="$t(lv.labelKey)"
                                            :value="lv.value"
                                        />
                                    </el-select>
                                    <div class="text-xs text-gray-400 mt-1">
                                        {{ $t(levelDescKey(option.botLevel)) }}
                                    </div>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-divider class="my-1" />

                        <!-- 检测器开关。默认全关（即全部启用）——
                             故意用「关掉哪些」而不是「启用哪些」的表述：
                             新增检测器时老配置不需要跟着改，默认就是启用。 -->
                        <el-form-item :label="$t('website.wafDetectors')">
                            <div class="waf-detector-grid">
                                <el-checkbox
                                    v-for="d in detectorOptions"
                                    :key="d.name"
                                    :value="d.name"
                                    :label="$t(d.labelKey)"
                                    @change="onDetectorToggle(d.name, $event)"
                                />
                            </div>
                        </el-form-item>
                        <el-form-item>
                            <div class="text-xs text-gray-400">
                                {{ $t('website.wafDetectorsTip') }}
                            </div>
                        </el-form-item>
                    </el-form>
                </el-card>

                <el-card shadow="never" class="mt-2">
                    <template #header>
                        <div class="card-header">
                            <span>{{ $t('website.wafBotProbe') }}</span>
                            <div class="flex items-center gap-3">
                                <el-switch v-model="option.botEnabled" @change="saveOption" />
                                <el-button type="primary" plain @click="saveOption">
                                    {{ $t('commons.button.save') }}
                                </el-button>
                            </div>
                        </div>
                    </template>
                    <el-row :gutter="24">
                        <el-col :xs="24" :md="12">
                            <el-form label-width="180px">
                                <el-form-item :label="$t('website.wafBotAllowGood')">
                                    <el-switch v-model="option.allowGoodBots" :disabled="!option.botEnabled" />
                                </el-form-item>
                                <el-form-item :label="$t('website.wafBotBlockBad')">
                                    <el-switch v-model="option.blockBadBots" :disabled="!option.botEnabled" />
                                </el-form-item>
                                <el-form-item :label="$t('website.wafProbeEnable')">
                                    <el-switch v-model="option.probeEnabled" @change="saveOption" />
                                </el-form-item>
                            </el-form>
                        </el-col>
                        <el-col :xs="24" :md="12">
                            <el-form label-width="180px">
                                <el-form-item :label="$t('website.wafProbeMaxURIs')">
                                    <el-input-number
                                        v-model="option.probeMaxURIs"
                                        :min="1"
                                        :disabled="!option.probeEnabled"
                                    />
                                </el-form-item>
                                <el-form-item :label="$t('website.wafProbeWindow')">
                                    <el-input-number
                                        v-model="option.probeWindow"
                                        :min="10"
                                        :disabled="!option.probeEnabled"
                                    />
                                </el-form-item>
                                <el-form-item :label="$t('website.wafProbeMaxRPS')">
                                    <el-input-number
                                        v-model="option.probeMaxRPS"
                                        :min="1"
                                        :disabled="!option.probeEnabled"
                                    />
                                </el-form-item>
                            </el-form>
                        </el-col>
                    </el-row>
                </el-card>

                <el-card shadow="never" class="mt-2">
                    <template #header>
                        <div class="card-header">
                            <span>{{ $t('website.wafRules') }}</span>
                            <div class="flex items-center gap-2">
                                <!-- 拖动排序做成显式开关而非常驻：默认状态下拖手柄会
                                     与表格的文本选择冲突，开着时整表可拖并给出保存入口。 -->
                                <el-select v-if="ruleSortMode" v-model="ruleScope" class="p-w-120" @change="loadRules">
                                    <el-option :label="$t('website.wafScopeSite')" value="site" />
                                    <el-option :label="$t('website.wafScopeGlobal')" value="global" />
                                </el-select>
                                <el-switch v-model="ruleSortMode" />
                                <el-button v-if="ruleSortMode" type="primary" plain @click="onSaveRuleOrder">
                                    {{ $t('commons.button.save') }}
                                </el-button>
                                <el-button v-if="ruleSortMode" @click="onResetRuleOrder">
                                    {{ $t('website.wafSortReset') }}
                                </el-button>
                                <el-button v-if="!ruleSortMode" type="primary" plain @click="openRuleDialog()">
                                    {{ $t('commons.button.create') }}
                                </el-button>
                            </div>
                        </div>
                    </template>
                    <el-alert
                        v-if="ruleSortMode"
                        :title="$t('website.wafSortTip')"
                        type="info"
                        :closable="false"
                        class="mb-2"
                    />
                    <!-- 排序模式下只展示当前 scope 那一组。
                         混合展示时拖动顺序会跨 scope，无法表达"本站规则优先于全局"
                         这类真实语义，还容易在提交时误改全局规则的优先级。 -->
                    <el-table ref="ruleTableRef" :data="displayRules" :row-key="'id'">
                        <el-table-column v-if="ruleSortMode" width="44" class-name="rule-drag-col">
                            <template #default>
                                <span class="rule-drag-handle" title="drag">⋮⋮</span>
                            </template>
                        </el-table-column>
                        <el-table-column prop="priority" :label="$t('website.wafPriority')" width="80" />
                        <el-table-column prop="name" :label="$t('commons.table.name')" min-width="120" />
                        <el-table-column prop="scope" :label="$t('website.wafScope')" width="90" />
                        <el-table-column prop="matchType" :label="$t('website.wafMatchType')" width="100" />
                        <el-table-column
                            prop="matchValue"
                            :label="$t('website.wafMatchValue')"
                            min-width="160"
                            show-overflow-tooltip
                        />
                        <el-table-column prop="matchOp" :label="$t('website.wafMatchOp')" width="90" />
                        <el-table-column prop="action" :label="$t('website.wafAction')" width="90">
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
                        <el-table-column prop="enabled" :label="$t('commons.table.status')" width="80">
                            <template #default="{ row }">
                                <el-tag :type="row.enabled ? 'success' : 'info'">
                                    {{ row.enabled ? 'on' : 'off' }}
                                </el-tag>
                            </template>
                        </el-table-column>
                        <!-- 排序模式下隐藏编辑/删除：编辑保存会触发 @reload=loadRules，
                             静默丢弃用户还没保存的拖动结果，且没有任何提示。
                             先保存或恢复默认顺序，再切回普通模式操作。 -->
                        <el-table-column
                            v-if="!ruleSortMode"
                            :label="$t('commons.table.operate')"
                            width="140"
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

            <el-tab-pane :label="$t('website.wafLogs')" name="logs">
                <el-card shadow="never">
                    <template #header>
                        <div class="card-header">
                            <span>{{ $t('website.wafLogs') }}</span>
                            <div>
                                <el-button plain @click="onExport('csv')">CSV</el-button>
                                <el-button plain @click="onExport('json')">JSON</el-button>
                            </div>
                        </div>
                    </template>
                    <el-form inline class="mb-2">
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
                        <el-form-item>
                            <el-date-picker
                                v-model="logTimeRange"
                                type="datetimerange"
                                range-separator="-"
                                :start-placeholder="$t('commons.search.timeStart')"
                                :end-placeholder="$t('commons.search.timeEnd')"
                            />
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" @click="searchLogs">{{ $t('commons.button.search') }}</el-button>
                            <el-button @click="resetLogSearch">{{ $t('commons.button.reset') }}</el-button>
                        </el-form-item>
                    </el-form>
                    <el-table :data="logs">
                        <el-table-column type="expand" width="44">
                            <template #default="{ row }">
                                <el-descriptions :column="1" border class="m-2">
                                    <!-- layer 与 durationMs 后端一直有值，但此前一列都没展示：
                                         排查时看不出「是哪一层拦的」和「处理耗时多久」，
                                         这两项恰恰是判断防护是否生效的关键。 -->
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
                        <el-table-column prop="createdAt" :label="$t('commons.table.date')" width="170" />
                        <el-table-column prop="attackType" :label="$t('website.wafAttackType')" width="110" />
                        <el-table-column prop="action" :label="$t('website.wafAction')" width="80" />
                        <el-table-column :label="$t('website.wafLayer')" width="110">
                            <template #default="{ row }">
                                <el-tag size="small" type="info">{{ $t(layerLabelKey(row.layer)) }}</el-tag>
                            </template>
                        </el-table-column>
                        <el-table-column prop="ip" label="IP" width="130" />
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
                            <!-- 只有命中名单规则的记录才有规则名；语义/CC/bot/订阅
                                 层拦截时没有对应规则，显示占位符而不是空白单元格，
                                 否则整列看上去像数据没加载出来。 -->
                            <template #default="{ row }">
                                <span v-if="row.ruleName">{{ row.ruleName }}</span>
                                <span v-else class="text-gray-400 text-xs">{{ $t('website.wafNoRule') }}</span>
                            </template>
                        </el-table-column>
                        <el-table-column :label="$t('commons.table.operate')" width="270" fixed="right">
                            <template #default="{ row }">
                                <el-button link type="primary" @click="onLogRule(row, 'allow')">
                                    {{ $t('website.wafAddAllow') }}
                                </el-button>
                                <el-tag v-if="row.falsePositive" type="success" size="small">
                                    {{ $t('website.wafFalsePositiveMarked') }}
                                </el-tag>
                                <el-button v-else link type="warning" @click="onFalsePositive(row)">
                                    {{ $t('website.wafFalsePositive') }}
                                </el-button>
                            </template>
                        </el-table-column>
                    </el-table>
                    <el-pagination
                        class="mt-2"
                        layout="total, prev, pager, next"
                        :total="logTotal"
                        :page-size="logReq.pageSize"
                        v-model:current-page="logReq.page"
                        @current-change="loadLogs"
                    />
                </el-card>
            </el-tab-pane>
        </el-tabs>

        <RuleDialog ref="ruleDialogRef" @reload="loadRules" />
    </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import Sortable from 'sortablejs';
import { ElMessageBox } from 'element-plus';
import i18n from '@/lang';
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
    reorderWAFRules,
    listWAFIPGroups,
    createWAFIPGroup,
    updateWAFIPGroup,
    deleteWAFIPGroup,
    WAF_IP_GROUP_NAME_PATTERN,
    type WAFWebhookMethod,
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

const props = defineProps({ websiteId: { type: Number, default: 0 }, wafEnabled: { type: Boolean, default: false } });

const loading = ref(false);
const activeTab = ref<'protect' | 'logs'>('protect');
const rules = ref<any[]>([]);
const logs = ref<any[]>([]);
const logTotal = ref(0);
const ruleDialogRef = ref();
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

// 当前关掉的检测器（Set 便于 O(1) 判断，保存时才序列化成逗号串）。
// 刻意不直接绑 option.disabledDetectors 字符串：用户点一次勾选框
// 就要做一次字符串切分与重组，中间态容易出现重复逗号或空项。
const disabledDetectors = ref<Set<string>>(new Set());

const currentModeDescKey = computed(() => {
    const m = WAF_MODES.find((x) => x.value === option.value.mode);
    return m?.descKey ?? 'website.wafModeBlockDesc';
});

// 拦截页颜色的前置校验。后端 Lua 侧也有校验（safe_color），
// 但那里是静默回退默认色 —— 用户填了不生效却不知道原因。
// 所以这里提前给出提示，让用户知道填错了。
const pageColorInvalid = computed(
    () =>
        isInvalidPageColor(option.value.blockPageBgColor || '') ||
        isInvalidPageColor(option.value.blockPageTextColor || ''),
);

// el-color-picker 的 validate：只接受后端 safe_color 也认的格式，
// 否则选色器选了 #RGB 短格式，后端静默回退默认色。
const isValidPageColorValue = (color: string) =>
    /^#[0-9a-fA-F]{6}$/.test(color) || NAMED_PAGE_COLORS.includes(color.toLowerCase());

const onDetectorToggle = (name: string, checked: boolean | (string | number)[]) => {
    // Element Plus 的 checkbox 在无 group 时 @change 第二个参数是 boolean
    const on = checked === true;
    if (on) {
        disabledDetectors.value.delete(name);
    } else {
        disabledDetectors.value.add(name);
    }
    // 立即同步到 option：保存按钮用的是 option 快照
    option.value.disabledDetectors = formatDisabledDetectors(disabledDetectors.value);
};

// 排序是独立状态而不是直接塞进 logReq：loadLogs 要把排序映射成
// 后端的 orderBy/order 两个字段，中间这层转换不该污染请求对象的形状。
const logSort = ref<WAFLogSortKey>('time_desc');
const sortOptions = WAF_LOG_SORT_OPTIONS;

// 通知渠道取值必须与后端 constant/alert.go 一致（驼峰），
// 写成小写会被 DTO 的 oneof 校验直接拒绝。
const notifyMethods: { value: WAFWebhookMethod; labelKey: string }[] = [
    { value: 'weCom', labelKey: 'website.wafNotifyMethodWeCom' },
    { value: 'dingTalk', labelKey: 'website.wafNotifyMethodDingTalk' },
    { value: 'feiShu', labelKey: 'website.wafNotifyMethodFeiShu' },
    { value: 'custom', labelKey: 'website.wafNotifyMethodCustom' },
];
const notify = ref<{ enable: boolean; method: WAFWebhookMethod; url: string }>({
    enable: false,
    method: 'custom',
    url: '',
});

// 三个分组各有自己的量级，KPI 的「拦截总数」用趋势之和而不是某一组的最大值，
// 否则「攻击类型 3 种」这种计数会被当成事件总数显示。
const statTotal = computed(() =>
    (stat.value.trend || []).reduce((sum: number, item: any) => sum + (item.count || 0), 0),
);

const statMax = computed(() => {
    const counts = [...(stat.value.attackType || []), ...(stat.value.topIP || [])].map((item: any) => item.count || 0);
    return Math.max(1, ...counts);
});

const barWidth = (count: number) => `${Math.max(3, Math.round(((count || 0) / statMax.value) * 100))}%`;

// VCharts/Line 的入参不是标准 echarts option：它自己拼 series 与 yAxis，
// 只认 xData / yData / formatStr。传标准结构（xAxis/yAxis/series）会让
// `props.option.yAxis ? yAxis : {...}` 命中前一个分支并取到空数组，
// 轴渲染直接抛 "Cannot read properties of undefined (reading 'group')"。
//
// formatStr 必须给：组件用它拼纵轴名 '( xxx )'，tooltip 也会把值与它
// 拼接，缺省就是纵轴 "( undefined )"、tooltip "5undefined"。
// 给"次"而不是空串：空串会让纵轴只剩一对空括号，读起来像渲染坏了。
const trendOption = computed(() => {
    const trend = stat.value.trend || [];
    return {
        xData: trend.map((item: any) => item.key),
        yData: [{ name: i18n.global.t('website.wafTrend'), data: trend.map((item: any) => item.count || 0) }],
        formatStr: i18n.global.t('website.wafTrendUnit'),
        // 只有一个系列，图例是冗余的（右上角那一项还会重复轴标题）。
        legend: { show: false },
        // top 必须容得下轴名 '( 次 )'：echarts 把轴名放在网格外侧，
        // top=16/28 时它被画布上边缘裁掉（实测顶部行有残留像素），
        // 34 起完整。取 36 留一点余量。
        grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
    };
});
const cc = ref<any>({ websiteId: props.websiteId, limit: 0, window: 60, action: 'deny', byUri: false, enabled: false });
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

// IP 组：站点可见的全局组 + 本站组。加载一次，规则抽屉直接复用。
const ipGroups = ref<any[]>([]);

// 编辑草稿。id 为空表示新建。
const ipGroupDraft = ref<any>({
    id: null,
    name: '',
    scope: 'site',
    cidrs: '',
    enabled: true,
    remark: '',
});

// 前端正则必须与后端 service 的 validateIPGroupName 完全一致 ——
// 放宽一点就会让用户配出一个后端拒绝、界面上看不出问题的组。
const ipGroupNameRules = {
    required: true,
    // eslint-disable-next-line @typescript-eslint/no-use-before-define
    validator: (_r: unknown, value: string, cb: (e?: Error) => void) => {
        if (!value || !WAF_IP_GROUP_NAME_PATTERN.test(value)) {
            cb(new Error(i18n.global.t('website.wafIPGroupNameInvalid')));
            return;
        }
        cb();
    },
};

/** 统计组里的条目数。分隔符与后端 parseIPGroupCIDRs 保持一致。 */
const countCIDRs = (raw?: string): number => {
    if (!raw) return 0;
    return raw.split(/[\n\r,;\t ]+/).filter((v) => v.trim()).length;
};

const onResetIPGroupDraft = () => {
    ipGroupDraft.value = {
        id: null,
        name: '',
        scope: 'site',
        cidrs: '',
        enabled: true,
        remark: '',
    };
};

const onNewIPGroup = () => {
    onResetIPGroupDraft();
};

const onEditIPGroup = (row: any) => {
    ipGroupDraft.value = { ...row };
};

const onSaveIPGroup = async () => {
    const d = ipGroupDraft.value;
    if (!WAF_IP_GROUP_NAME_PATTERN.test(d.name || '')) {
        MsgWarning(i18n.global.t('website.wafIPGroupNameInvalid'));
        return;
    }
    const payload = {
        name: d.name,
        scope: d.scope,
        websiteId: d.scope === 'site' ? props.websiteId : 0,
        enabled: d.enabled ?? true,
        remark: d.remark || '',
        cidrs: d.cidrs,
    };
    if (d.id) {
        await updateWAFIPGroup({ ...payload, id: d.id });
    } else {
        await createWAFIPGroup(payload);
    }
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    onResetIPGroupDraft();
    loadIPGroups();
};

const onDelIPGroup = async (row: any) => {
    await deleteWAFIPGroup(row.id);
    MsgSuccess(i18n.global.t('commons.msg.deleteSuccess'));
    loadIPGroups();
};

const loadIPGroups = async () => {
    const res = await listWAFIPGroups(props.websiteId);
    ipGroups.value = res.data || [];
};

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
};
const saveCC = async () => {
    await updateWAFCCConfig({ ...cc.value, websiteId: props.websiteId });
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
};
const loadOption = async () => {
    const res = await getWAFOption(props.websiteId);
    if (res.data) {
        option.value = res.data;
        // mode 兜底：老数据没有这一列时 GetOption 返回空串，
        // 而 Lua 侧空串不等于 "observe"/"maintenance"，行为退化成 block。
        // 这里显式补上，让界面显示与实际行为一致。
        if (!option.value.mode) {
            option.value.mode = 'block';
        }
        // 强度同理：老数据没有这两列时后端返回空串，
        // 归一成 balanced 让界面显示与实际行为一致。
        option.value.semanticLevel = normalizeLevel(option.value.semanticLevel);
        option.value.botLevel = normalizeLevel(option.value.botLevel);
        disabledDetectors.value = parseDisabledDetectors(option.value.disabledDetectors);
    }
};
const saveOption = async () => {
    // 颜色非法时先拦一道。后端 Lua 的 safe_color 会静默回退默认色，
    // 用户填了却不生效，且界面看不出原因 —— 那比报错更难排查。
    if (pageColorInvalid.value) {
        MsgWarning(i18n.global.t('website.wafBlockPageColorTip'));
        return;
    }
    await updateWAFOption({ ...option.value, websiteId: props.websiteId });
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
};
const loadNotify = async () => {
    const res = await getWAFWebhook();
    if (res.data) {
        notify.value = { ...notify.value, ...res.data };
    }
};
// 开关是「一点就发请求」的：请求失败时开关已经翻过去了，
// 而配置没存上 —— UI 显示开启、实际没开，且没有重试入口。
// 所以这里在失败时把开关拨回去。
const onNotifyToggle = async (val: boolean) => {
    try {
        await saveNotify();
    } catch (e) {
        notify.value.enable = !val;
    }
};

const saveNotify = async () => {
    // 后端有 required_if 校验，这里先拦一道给出即时反馈
    if (notify.value.enable && !notify.value.url.trim()) {
        MsgWarning(i18n.global.t('website.wafNotifyURLRequired'));
        return;
    }
    await updateWAFWebhook({ ...notify.value });
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
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
        // 剪贴板 API 在非 HTTPS 环境下不可用。不能用 MsgWarning 展示：
        // 它是 3 秒后自动消失的提示条，而攻击日志的 requestBody 动辄几百 KB，
        // 塞进去既横向溢出又无法选中复制。改用对话框 + 全选，用户自己复制。
        ElMessageBox.alert(cmd, i18n.global.t('website.wafCopyCurl'), {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            type: 'warning',
            customClass: 'waf-curl-fallback',
        }).catch(() => undefined);
    }
};
// ============ 名单拖动排序 ============
// sortable 只在「调整顺序」开关打开时初始化，关闭时销毁：
// 常驻的拖拽手柄会和表格文本选择打架，且用户并不总能预期"拖一下会改配置"。
const ruleSortMode = ref(false);
const ruleTableRef = ref();
// 非排序模式下展示全部（本站+全局），排序模式下只展示当前 scope 那一组
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
            // 只改本地顺序，点「保存」才提交 —— 拖错了可以直接关开关丢弃。
            const list = [...displayRules.value];
            const [moved] = list.splice(evt.oldIndex, 1);
            list.splice(evt.newIndex, 0, moved);
            // 同步重算本地 priority：否则表格里的数字还是拖动前的旧值，
            // 用户看到"顺序变了但数字没变"，而提示文案恰好写的是"数字越小越先生效"。
            list.forEach((r: any, i: number) => {
                r.priority = (i + 1) * 10;
            });
            rules.value = rules.value.map((r: any) => list.find((x: any) => x.id === r.id) || r);
        },
    });
};

// 规则列表是「本站 + 全局」混合的（后端 ListRules 的过滤就是
// scope=global OR website_id=当前站）。若把两类一起提交重排，
// 在 A 站拖一下就会改到全局规则的优先级 —— B 站、C 站的行为跟着变，
// 而那边的用户完全不知情。所以按 scope 分组，只提交当前 scope 那一组。
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
        // 关闭时重拉一次：丢弃未保存的拖动结果。
        loadRules();
    }
});

onUnmounted(destroyRuleSortable);

const openRuleDialog = (rule?: any) => {
    ruleDialogRef.value.acceptParams({
        websiteId: props.websiteId,
        rule: rule ? { ...rule } : null,
        // 规则里的 ip_group 匹配类型要从这里选组名
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
    // 导出必须带上当前排序：漏掉的话表格按"耗时"排、导出文件却按时间排，
    // 用户拿导出做分析会得出相反的结论 —— 这比报错危险得多。
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

// 日志页签每次切入都重查一次：拦截事件由 cron 约每分钟入库，
// 停留防护页签期间日志会持续增长，切回时若沿用旧数据会误导计数。
const onTabChange = (name: string | number) => {
    if (name === 'logs') {
        loadLogs();
    }
};

// 排序改变后要回到第一页：停在第 5 页再改排序，页码对新顺序往往越界，
// 用户看到的是空列表而不是"排序变了"。
watch(logSort, () => {
    logReq.value.page = 1;
    loadLogs();
});

const loadAll = () => {
    loadRules();
    loadIPGroups();
    loadLogs();
    loadStat();
    loadCC();
    loadOption();
    // 通知是全局配置（不区分站点），但这个页面是站点维度的入口，
    // 放这里是因为 WAF 的配置项原本就都集中在这一个页签里。
    loadNotify();
};

// 总开关移到了容器页标题栏：启用/禁用后这里靠 prop 变化感知，
// 启用时拉全量配置（禁用时模板直接渲染空态，无需请求）。
watch(
    () => props.wafEnabled,
    (val) => {
        if (val) {
            activeTab.value = 'protect';
            loadAll();
        }
    },
);

onMounted(() => {
    if (props.wafEnabled) {
        loadAll();
    }
});
</script>

<style scoped>
.card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.mt-2 {
    margin-top: 12px;
}
.mt-3 {
    margin-top: 16px;
}
/* KPI 平铺：先给结论，再给分布 */
.waf-kpi {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}
.waf-kpi-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 14px 16px;
    border: 1px solid var(--el-border-color-lighter);
    border-radius: 6px;
    background-color: var(--el-fill-color-blank);
}
.waf-kpi-value {
    font-size: 24px;
    font-weight: 600;
    line-height: 1.2;
}
.waf-kpi-label {
    font-size: 12px;
    color: var(--el-text-color-secondary);
}
.waf-stat-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 10px;
    font-size: 14px;
    font-weight: 600;
    color: var(--el-text-color-regular);
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
    flex: 0 0 96px;
    overflow: hidden;
    font-size: 13px;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.waf-bar-ip {
    flex-basis: 130px;
    font-family: monospace;
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
.waf-bar-fill-ip {
    background-color: var(--el-color-primary);
}
/* 防护模式：三态按钮组，纵向排列让说明文字有位置 */
.waf-mode-group {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

/* 检测器开关：两列网格，15 项在一屏内看得完 */
.waf-detector-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 4px 12px;
    width: 100%;
}

/* 拖动手柄：只在排序模式出现，视觉上要明显可抓 */
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

.waf-bar-value {
    flex: 0 0 auto;
    min-width: 32px;
    font-size: 13px;
    text-align: right;
    color: var(--el-text-color-regular);
}
</style>

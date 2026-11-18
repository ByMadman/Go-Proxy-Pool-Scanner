<template>
  <div>
    <!-- 统计卡片 -->
    <el-row :gutter="14">
      <el-col :span="6" v-for="c in cards" :key="c.label">
        <div class="stat" :style="{ '--c': c.color }">
          <div class="label">{{ c.label }}</div>
          <div class="value">{{ c.value }}<em>{{ c.unit }}</em></div>
          <div class="hint">{{ c.hint }}</div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="14" class="mt">
      <el-col :span="14">
        <div class="panel">
          <div class="card-title">
            <span>国家/地区分布（前 12）</span>
            <el-button link type="primary" @click="load">刷新</el-button>
          </div>
          <div v-for="c in topCountries" :key="c.name" class="bar-row">
            <div class="bar-name" :title="c.name">{{ c.name }}</div>
            <div class="bar-track">
              <div class="bar-fill" :style="{ width: barWidth(c.count) + '%' }" />
            </div>
            <div class="bar-val mono">{{ c.count }}</div>
          </div>
          <el-empty v-if="!topCountries.length" description="暂无数据，先去扫描任务吧" :image-size="70" />
        </div>
      </el-col>

      <el-col :span="10">
        <div class="panel">
          <div class="card-title"><span>当前任务</span><span class="muted mono">{{ fmtElapsed }}</span></div>
          <template v-if="rt.progress.running">
            <div class="task-name">{{ rt.progress.name }}</div>
            <el-progress :percentage="pct" :stroke-width="12" striped :text-inside="true" />
            <div class="kv">
              <span>已检查 <b class="mono">{{ rt.progress.scanned }}</b> / {{ rt.progress.total }}</span>
              <span>命中 <b class="mono">{{ rt.progress.found }}</b></span>
              <span v-if="rt.progress.type === 'verify'">删除 <b class="mono">{{ rt.progress.deleted }}</b></span>
              <span>速率 <b class="mono">{{ rt.progress.ratePerSec }}</b>/s</span>
            </div>
          </template>
          <el-empty v-else description="没有正在运行的任务" :image-size="70" />
        </div>

        <div class="panel mt">
          <div class="card-title"><span>运行日志</span></div>
          <div class="logs">
            <div v-for="(l, i) in rt.logs.slice(0, 8)" :key="i" class="log-line">
              <span class="muted mono">{{ fmtTime(l.time) }}</span>
              <el-tag size="small" :type="l.level === 'warn' ? 'warning' : 'info'">{{ l.level }}</el-tag>
              <span>{{ l.msg }}</span>
            </div>
            <el-empty v-if="!rt.logs.length" description="暂无日志" :image-size="60" />
          </div>
        </div>
      </el-col>
    </el-row>

    <div class="panel mt">
      <div class="card-title">
        <span>最新入库</span>
        <el-button link type="primary" @click="loadLatest(true)">刷新</el-button>
      </div>
      <el-table :data="rt.latest.slice(0, 8)" size="small" max-height="260">
        <el-table-column prop="ip" label="IP" width="140">
          <template #default="{ row }"><span class="mono">{{ row.ip }}:{{ row.port }}</span></template>
        </el-table-column>
        <el-table-column label="协议" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.httpsOk ? 'success' : 'primary'">{{ row.httpsOk ? 'HTTPS' : 'HTTP' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="匿名" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="levelType(row.anonymity)">{{ levelText(row.anonymity) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="延迟" width="90">
          <template #default="{ row }"><span class="mono">{{ row.latency }} ms</span></template>
        </el-table-column>
        <el-table-column prop="region" label="归属地" />
        <el-table-column label="出口 IP" width="130">
          <template #default="{ row }"><span class="mono muted">{{ row.exitIp || '-' }}</span></template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { getProxies, getStats } from '../api'
import { on, rt } from '../realtime'
import { levelText, levelType } from '../utils'

const stats = ref({ total: 0, elite: 0, anonymous: 0, httpsOk: 0, todayAdded: 0, avgLatency: 0, countries: [] })

const cards = computed(() => [
  { label: '代理总数', value: stats.value.total ?? 0, unit: '条', color: '#3b82f6', hint: '代理池中的可用记录' },
  { label: '高匿名', value: stats.value.elite ?? 0, unit: '条', color: '#22c55e', hint: '未泄露任何代理痕迹' },
  { label: '支持 HTTPS', value: stats.value.httpsOk ?? 0, unit: '条', color: '#a855f7', hint: '可通过 CONNECT 隧道转发' },
  { label: '平均延迟', value: stats.value.avgLatency ?? 0, unit: 'ms', color: '#f59e0b', hint: `今日新增 ${stats.value.todayAdded ?? 0} 条` }
])

const topCountries = computed(() => (stats.value.countries || []).slice(0, 12))

function barWidth(count) {
  const max = Math.max(1, ...topCountries.value.map((c) => c.count))
  return Math.max(2, Math.round((count / max) * 100))
}

const pct = computed(() => {
  const p = rt.progress
  if (!p.total) return 0
  return Math.min(100, Math.round((p.scanned / p.total) * 100))
})

const fmtElapsed = computed(() => {
  const ms = rt.progress.elapsedMs || 0
  const s = Math.floor(ms / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return `${h}h ${m}m ${s % 60}s`
})

function fmtTime(t) {
  const d = new Date(t)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

async function load() {
  try {
    // 接口返回 { stats, progress, publicIp }，统计数字在 stats 里
    const r = await getStats()
    stats.value = r?.stats || {}
  } catch (e) {
    /* 忽略 */
  }
}

// 最新入库：SSE 只推送「本次运行」新增，刷新页面后要回源数据库补历史
async function loadLatest(force = false) {
  if (rt.latest.length && !force) return
  try {
    const res = await getProxies({ page: 1, size: 12, sortBy: 'id', order: 'desc' })
    rt.latest = res?.list || []
  } catch (e) {
    /* 忽略 */
  }
}

// 扫描过程中有新命中就节流刷新统计，避免「数字一直不变」
let refreshTimer = null
function scheduleRefresh() {
  if (refreshTimer) return
  refreshTimer = setTimeout(() => {
    refreshTimer = null
    load()
  }, 3000)
}

const offFns = [
  on('found', scheduleRefresh),
  on('done', () => {
    load()
    loadLatest()
  })
]

onMounted(async () => {
  await Promise.all([load(), loadLatest()])
})

onUnmounted(() => {
  offFns.forEach((fn) => fn && fn())
  if (refreshTimer) clearTimeout(refreshTimer)
})
</script>

<style scoped>
.mt {
  margin-top: 14px;
}

.panel {
  background: #fff;
  border: 1px solid #e8ebf0;
  border-radius: 10px;
  padding: 14px 16px;
}

.stat {
  background: #fff;
  border: 1px solid #e8ebf0;
  border-radius: 10px;
  padding: 14px 16px;
  border-left: 4px solid var(--c);
}

.stat .label {
  font-size: 12px;
  color: #6b7280;
}

.stat .value {
  font-size: 26px;
  font-weight: 700;
  margin: 4px 0 2px;
  color: #111827;
}

.stat .value em {
  font-size: 12px;
  font-style: normal;
  font-weight: 400;
  margin-left: 4px;
  color: #6b7280;
}

.stat .hint {
  font-size: 11px;
  color: #9ca3af;
}

.bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 7px 0;
  font-size: 12px;
}

.bar-name {
  width: 104px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.bar-track {
  flex: 1;
  height: 8px;
  background: #eef2f7;
  border-radius: 4px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  background: linear-gradient(90deg, #3b82f6, #06b6d4);
  border-radius: 4px;
}

.bar-val {
  width: 48px;
  text-align: right;
  color: #4b5563;
}

.task-name {
  font-weight: 600;
  margin-bottom: 8px;
}

.kv {
  display: flex;
  gap: 14px;
  font-size: 12px;
  color: #6b7280;
  margin-top: 10px;
}

.logs {
  max-height: 190px;
  overflow: auto;
}

.log-line {
  display: flex;
  gap: 8px;
  align-items: center;
  font-size: 12px;
  padding: 3px 0;
  border-bottom: 1px dashed #f1f3f6;
}
</style>

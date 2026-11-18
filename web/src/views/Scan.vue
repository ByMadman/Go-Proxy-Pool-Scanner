<template>
  <div>
    <el-row :gutter="14">
      <el-col :span="16">
        <div class="panel">
          <div class="card-title">
            <span>扫描范围</span>
            <el-button link type="primary" @click="estimate">估算覆盖范围</el-button>
          </div>

          <el-form label-width="96px">
            <el-form-item label="国家/地区">
              <el-select
                v-model="cfg.countries"
                multiple
                filterable
                clearable
                collapse-tags
                collapse-tags-tooltip
                placeholder="从 ip2region 中选择（可多选，留空=全部）"
                style="width: 100%"
                @change="onCountryChange"
              >
                <el-option v-for="c in regions" :key="c.name" :label="`${c.name}${c.code ? ' · ' + c.code : ''}`" :value="c.name">
                  <span>{{ c.name }}</span>
                  <span class="muted mono" style="float: right; font-size: 11px">
                    {{ c.code }} · {{ humanCount(c.ips) }} IP · {{ c.segments }} 段
                  </span>
                </el-option>
              </el-select>
            </el-form-item>

            <el-form-item label="省份/州">
              <el-select
                v-model="cfg.provinces"
                multiple
                filterable
                clearable
                collapse-tags
                collapse-tags-tooltip
                :disabled="!cfg.countries.length"
                :placeholder="cfg.countries.length ? '可选：进一步限定到省份/州' : '请先选择国家/地区'"
                style="width: 100%"
              >
                <el-option v-for="p in provinceOptions" :key="p.name" :label="p.name" :value="p.name">
                  <span>{{ p.name }}</span>
                  <span class="muted mono" style="float: right; font-size: 11px">{{ humanCount(p.ips) }} IP</span>
                </el-option>
              </el-select>
            </el-form-item>

            <el-form-item label="归属地关键字">
              <el-input v-model="cfg.keyword" placeholder="模糊匹配运营商/城市等，如：电信 / 联通 / Seoul" />
            </el-form-item>

            <el-form-item label="自定义 IP 段">
              <el-input
                v-model="rangeText"
                type="textarea"
                :rows="2"
                placeholder="每行一段，支持 CIDR(1.2.3.0/24) 或区间(1.2.3.1-1.2.3.254)；填写后将优先于国家筛选"
              />
            </el-form-item>

            <el-form-item label="端口">
              <el-select v-model="cfg.ports" multiple filterable allow-create default-first-option placeholder="选择或输入端口后回车" style="width: 100%">
                <el-option v-for="p in commonPorts" :key="p" :label="p" :value="p" />
              </el-select>
              <div class="presets">
                <el-button v-for="p in presets" :key="p.label" size="small" text bg @click="applyPreset(p)">{{ p.label }}</el-button>
                <el-button size="small" text bg @click="cfg.ports = []">清空</el-button>
              </div>
            </el-form-item>
          </el-form>
        </div>

        <div class="panel mt">
          <div class="card-title"><span>抽样与性能</span></div>
          <el-form label-width="96px">
            <el-col :span="12">
              <el-form-item label="并发数">
                <el-slider v-model="cfg.concurrency" :min="20" :max="2000" :step="10" show-input :show-input-controls="false" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="单次超时">
                <el-input-number v-model="cfg.timeoutMs" :min="500" :max="30000" :step="500" /> ms
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="网段全覆盖">
                <el-switch v-model="cfg.fullCover" />
                <span class="hint-inline">开启后逐 /24 块整段扫描（命中率更高），适合单省/单州精扫</span>
              </el-form-item>
            </el-col>
            <template v-if="!cfg.fullCover">
              <el-col :span="12">
                <el-form-item label="抽样 IP 数">
                  <el-input-number v-model="cfg.maxCandidates" :min="100" :max="5000000" :step="1000" />
                  <span class="hint-inline">全区域抽样的 IP 总数；候选数 = 该数 × 端口数</span>
                </el-form-item>
              </el-col>
              <el-col :span="12">
                <el-form-item label="单段上限">
                  <el-input-number v-model="cfg.perSegment" :min="1" :max="200" />
                </el-form-item>
              </el-col>
            </template>
            <el-col v-else :span="12">
              <el-form-item label="扫描范围">
                <span class="hint-inline">扫所选范围（国家 / 省份）的全部网段，不做 IP 上限截断</span>
              </el-form-item>
            </el-col>
          </el-form>
        </div>
      </el-col>

      <el-col :span="8">
        <div class="panel">
          <div class="card-title"><span>入库条件</span></div>
          <el-form label-width="96px">
            <el-form-item label="匿名等级">
              <el-radio-group v-model="cfg.minAnonymity">
                <el-radio :value="3">仅高匿名</el-radio>
                <el-radio :value="2">普通匿名及以上</el-radio>
                <el-radio :value="0">不限</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="未知等级">
              <el-switch v-model="cfg.allowUnknown" active-text="允许入库" inactive-text="丢弃" />
              <div class="tip">回显站点无法回显请求头时，匿名等级为「未知」</div>
            </el-form-item>
            <el-form-item label="出口去重">
              <el-switch v-model="cfg.dedupExitIp" active-text="同一出口保留一条" />
            </el-form-item>
          </el-form>
        </div>

        <div class="panel mt">
          <div class="card-title"><span>执行</span></div>
          <div class="est" v-if="est">
            网段 <b>{{ est.segments }}</b> 个 · 地址池 IP <b>{{ humanCount(est.ips) }}</b>
            <div class="est-sub" v-if="est.full">
              整段扫描：约 <b>{{ humanCount(est.maxIps) }}</b> 个 IP（{{ est.blocks }} 个 /24 块）×
              {{ est.ports || cfg.ports.length }} 端口 = <b>{{ humanCount(est.candidates || 0) }}</b> 候选
            </div>
            <div class="est-sub" v-else>
              本次候选 <b>{{ humanCount(est.candidates || 0) }}</b> 个
              （抽样 {{ est.maxIps || 0 }} IP × {{ est.ports || cfg.ports.length }} 端口）
            </div>
            <div class="est-sub muted" v-if="est.full">逐 /24 块整段扫描所选范围的全部网段（{{ est.blocks }} 个块），不做 IP 上限截断</div>
            <div class="est-sub muted" v-else>本次仅扫描地址池的 {{ (est.coveragePct || 0).toFixed(2) }}%</div>
            <div v-if="candidateHint" class="tip warn-tip">{{ candidateHint }}</div>
          </div>
          <div class="est muted" v-else>点击上方「估算覆盖范围」查看将要扫描的规模</div>
          <div class="btns">
            <el-button type="primary" size="large" @click="addTask">
              <el-icon><Promotion /></el-icon> 新增任务
            </el-button>
            <el-button type="danger" size="large" plain :disabled="!rt.progress.running" @click="stop">停止</el-button>
          </div>
          <div class="tip">
            点击「新增任务」会把当前配置加入任务队列；正在运行时也可继续添加，当前任务跑完会自动执行下一个。
          </div>
        </div>
      </el-col>
    </el-row>

    <div class="panel mt">
      <div class="card-title">
        <span>进度</span>
        <span class="muted mono" v-if="rt.progress.running">速率 {{ rt.progress.ratePerSec }}/s</span>
      </div>
      <template v-if="rt.progress.running || rt.progress.taskId">
        <el-progress :percentage="pct" :stroke-width="14" :text-inside="true" :status="rt.progress.running ? undefined : 'success'" />
        <div class="kv">
          <span>任务 <b>{{ rt.progress.name || '-' }}</b></span>
          <span>已检查 <b class="mono">{{ rt.progress.scanned }}</b> / {{ rt.progress.total }}</span>
          <span>入库 <b class="mono">{{ rt.progress.found }}</b></span>
          <span>失败 <b class="mono">{{ rt.progress.failed }}</b></span>
          <span v-if="rt.progress.deleted">删除 <b class="mono">{{ rt.progress.deleted }}</b></span>
        </div>
        <div class="kv" v-if="rt.progress.verified">
          <span>验证通过 <b class="mono">{{ rt.progress.verified }}</b></span>
          <span v-if="rt.progress.rejectAnon">匿名不足 <b class="mono warn">{{ rt.progress.rejectAnon }}</b></span>
          <span v-if="rt.progress.rejectUnknown">未知等级 <b class="mono warn">{{ rt.progress.rejectUnknown }}</b></span>
          <span v-if="rt.progress.rejectDedup">出口重复 <b class="mono warn">{{ rt.progress.rejectDedup }}</b></span>
        </div>
        <div class="tip warn-tip" v-if="filterHint">{{ filterHint }}</div>
      </template>
      <el-empty v-else description="暂无运行中的任务" :image-size="60" />
    </div>

    <div class="panel mt">
      <div class="card-title">
        <span>任务队列与历史</span>
        <span class="muted mono">排队 {{ rt.queue.length }} · 运行中 {{ rt.progress.running ? 1 : 0 }}</span>
        <el-button link type="primary" @click="loadTasks">刷新</el-button>
      </div>
      <el-table :data="taskRows" size="small" max-height="320" row-key="id">
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="statusType(row)">{{ statusText(row) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="任务" min-width="150" />
        <el-table-column label="候选/进度" width="150">
          <template #default="{ row }">
            <span class="mono" v-if="row.status === 'running'">{{ row.scanned }}/{{ row.total }}</span>
            <span class="mono" v-else>{{ row.total }}</span>
          </template>
        </el-table-column>
        <el-table-column label="入库" width="80">
          <template #default="{ row }"><span class="mono">{{ row.found ?? 0 }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="170">
          <template #default="{ row }">
            <el-button v-if="row.status === 'running'" size="small" type="danger" plain @click="stop">停止</el-button>
            <el-button v-if="row.status === 'queued'" size="small" type="warning" plain @click="cancelQueued(row)">取消</el-button>
            <el-button size="small" type="danger" link @click="del(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!taskRows.length" description="暂无任务，点击「新增任务」加入队列" :image-size="70" />
    </div>

    <div class="panel mt">
      <div class="card-title">
        <span>实时命中（最近 30 条）</span>
        <el-switch v-model="autoScroll" active-text="自动滚动" size="small" />
      </div>
      <el-table :data="rt.latest.slice(0, 30)" size="small" max-height="300">
        <el-table-column label="代理" width="160">
          <template #default="{ row }"><span class="mono">{{ row.ip }}:{{ row.port }}</span></template>
        </el-table-column>
        <el-table-column label="协议" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.httpsOk ? 'success' : 'primary'">{{ row.httpsOk ? 'HTTPS' : 'HTTP' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="匿名度" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="levelType(row.anonymity)">{{ levelText(row.anonymity) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="延迟" width="90">
          <template #default="{ row }"><span class="mono">{{ row.latency }} ms</span></template>
        </el-table-column>
        <el-table-column prop="region" label="归属地(ip2region)" />
        <el-table-column label="出口 IP" width="130">
          <template #default="{ row }"><span class="mono muted">{{ row.exitIp || '-' }}</span></template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!rt.latest.length" description="还没有命中结果" :image-size="70" />
    </div>

    <div class="panel mt">
      <div class="card-title"><span>日志</span><el-button link type="primary" @click="rt.logs = []">清空</el-button></div>
      <div class="logs">
        <div v-for="(l, i) in rt.logs" :key="i" class="log-line">
          <span class="muted mono">{{ fmtTime(l.time) }}</span>
          <el-tag size="small" :type="l.level === 'warn' ? 'warning' : 'info'">{{ l.level }}</el-tag>
          <span>{{ l.msg }}</span>
        </div>
        <el-empty v-if="!rt.logs.length" description="暂无日志" :image-size="60" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Promotion } from '@element-plus/icons-vue'
import { enqueueScan, estimateSegments, getConfig, getRegions, listTasks, removeScanTask, deleteTask, stopScan } from '../api'
import { on, rt } from '../realtime'
import { COMMON_PORTS, PORT_PRESETS, humanCount, levelText, levelType } from '../utils'

const regions = ref([])
const est = ref(null)
const rangeText = ref('')
const autoScroll = ref(true)
const commonPorts = ref(COMMON_PORTS)
const presets = PORT_PRESETS

const defaultCfg = () => ({
  countries: ['中国'],
  provinces: [],
  keyword: '',
  ranges: [],
  ports: [80, 8080, 8081, 3128, 8888, 1080, 7890],
  concurrency: 300,
  timeoutMs: 6000,
  maxCandidates: 20000,
  perSegment: 4,
  fullCover: false,
  fullCoverMaxIPs: 0,
  minAnonymity: 2,
  allowUnknown: true,
  requireHttps: false,
  dedupExitIp: false,
  maxLatency: 0
})

const cfg = reactive(defaultCfg())

const provinceOptions = computed(() => {
  const set = new Set(cfg.countries || [])
  const list = []
  regions.value.forEach((c) => {
    if (set.size && !set.has(c.name)) return
    ;(c.provinces || []).forEach((p) => list.push(p))
  })
  // 按 IP 量合并去重
  const map = new Map()
  list.forEach((p) => {
    const cur = map.get(p.name)
    if (cur) {
      cur.ips += p.ips
      cur.segments += p.segments
    } else map.set(p.name, { ...p })
  })
  return [...map.values()].sort((a, b) => b.ips - a.ips)
})

const pct = computed(() => {
  const p = rt.progress
  if (!p.total) return 0
  return Math.min(100, Math.round((p.scanned / p.total) * 100))
})

// 当"验证通过却 0 入库"时，直接点出是谁在卡人
const filterHint = computed(() => {
  const p = rt.progress
  if (!p.verified || p.found > 0) return ''
  const parts = []
  if (p.rejectUnknown) parts.push(`未知等级 ${p.rejectUnknown}（回显站点拿不到请求头，可勾选「允许入库」）`)
  if (p.rejectAnon) parts.push(`匿名不足 ${p.rejectAnon}（当前要求${cfg.minAnonymity === 3 ? '仅高匿名' : '普通匿名及以上'}）`)
  if (p.rejectDedup) parts.push(`出口重复 ${p.rejectDedup}`)
  if (!parts.length) return ''
  return `已有 ${p.verified} 个代理验证通过，但全部被入库条件过滤：${parts.join('；')}。`
})

// 候选数过小时提示：用户常把「覆盖 IP」误当成「本次会扫的 IP」，
// 结果任务几十秒就完成，看起来像「没跑完」。
const candidateHint = computed(() => {
  const e = est.value
  if (!e) return ''
  const cand = Number(e.candidates || 0)
  if (cand <= 0) return ''
  if (cand < 20000) {
    return `注意：当前配置只会探测 ${humanCount(cand)} 个候选（抽样 ${e.maxIps || 0} 个 IP × ${e.ports || cfg.ports.length} 端口），通常数十秒内就会结束，这是正常的。想覆盖更多地址请调大「抽样 IP 数」。`
  }
  return ''
})

function onCountryChange() {
  cfg.provinces = (cfg.provinces || []).filter((p) => provinceOptions.value.some((o) => o.name === p))
}

// 后端已把国家/省份名统一成中文，但历史保存的配置里可能是英文原文
// （如 "United States" / "Ohio"），这里用别名把它们换算成当前显示名，
// 否则界面上会显示成「选了国家但省份列表匹配不到」。
function normalizeRegionNames() {
  const countryByAlias = new Map()
  regions.value.forEach((c) => {
    countryByAlias.set(c.name, c)
    if (c.code) countryByAlias.set(c.code, c)
    ;(c.aliases || []).forEach((a) => countryByAlias.set(a, c))
  })
  cfg.countries = (cfg.countries || []).map((v) => countryByAlias.get(v)?.name || v)

  const want = new Set(cfg.countries || [])
  const provByAlias = new Map()
  regions.value.forEach((c) => {
    if (want.size && !want.has(c.name)) return
    ;(c.provinces || []).forEach((p) => {
      provByAlias.set(p.name, p.name)
      ;(p.aliases || []).forEach((a) => provByAlias.set(a, p.name))
    })
  })
  cfg.provinces = (cfg.provinces || []).map((v) => provByAlias.get(v) || v)
}

function applyPreset(p) {
  const merged = new Set([...(cfg.ports || []), ...p.ports])
  cfg.ports = [...merged].sort((a, b) => a - b)
}

function parseRanges() {
  const list = (rangeText.value || '')
    .split(/[\r\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
  cfg.ranges = list
}

async function estimate() {
  parseRanges()
  try {
    // 带上抽样参数，估算才能给出「本次真正会探测的候选数」（抽样 IP × 端口）
    est.value = await estimateSegments({
      country: cfg.countries,
      province: cfg.provinces,
      keyword: cfg.keyword,
      range: cfg.ranges,
      perSegment: cfg.perSegment,
      maxCandidates: cfg.maxCandidates,
      fullCover: cfg.fullCover ? 1 : 0,
      fullCoverMaxIPs: cfg.fullCoverMaxIPs,
      portCount: cfg.ports.length
    })
    if (cfg.ranges.length) ElMessage.info('已包含自定义 IP 段，估算值仅供参考')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

// addTask：校验后把配置加入队列，并显示排队位置
async function addTask() {
  parseRanges()
  if (!cfg.countries?.length && !cfg.keyword && !cfg.ranges.length) {
    ElMessage.warning('请至少选择一个国家/地区，或填写自定义 IP 段')
    return
  }
  if (!cfg.ports?.length) {
    ElMessage.warning('请至少选择一个端口')
    return
  }
  if (cfg.timeoutMs > 0 && cfg.timeoutMs < 1000) {
    ElMessage.warning(`单次超时 ${cfg.timeoutMs}ms 过短：慢速代理会全部超时，建议 ≥1500ms`)
  }
  try {
    const r = await enqueueScan({ ...cfg })
    const pos = r?.position || 0
    ElMessage.success(pos > 0 ? `已加入任务队列（第 ${pos} 位），将自动依次执行` : '已加入任务队列')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function stop() {
  try {
    await stopScan()
    ElMessage.success('已请求停止')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

// ---------- 任务队列与历史 ----------
const history = ref([])

async function loadTasks() {
  try {
    history.value = (await listTasks()) || []
  } catch (e) {
    /* 忽略 */
  }
}

// running(实时) + queued(SSE) + history(历史) 合并展示，按 id 去重
const taskRows = computed(() => {
  const rows = []
  if (rt.progress.running) {
    rows.push({
      id: rt.progress.taskId,
      name: rt.progress.name,
      status: 'running',
      total: rt.progress.total,
      scanned: rt.progress.scanned,
      found: rt.progress.found,
      type: rt.progress.type
    })
  }
  rt.queue.forEach((q) => {
    rows.push({ id: q.id, name: q.name, status: 'queued', total: q.total, found: 0 })
  })
  history.value.forEach((t) => {
    if (rows.some((r) => r.id === t.id)) return
    rows.push({
      id: t.id,
      name: t.name,
      status: t.status,
      total: t.total,
      scanned: t.scanned,
      found: t.found,
      type: t.type
    })
  })
  return rows
})

function statusType(row) {
  return { running: 'warning', queued: 'info', completed: 'success', stopped: 'info', failed: 'danger' }[row.status] || 'info'
}
function statusText(row) {
  return { running: '执行中', queued: '排队中', completed: '已完成', stopped: '已停止', failed: '失败' }[row.status] || row.status
}

// 取消排队中的任务
async function cancelQueued(row) {
  try {
    await removeScanTask(row.id)
    ElMessage.success('已取消排队任务')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

// 删除任务：运行中先停止再删；排队中直接取消；历史直接删
async function del(row) {
  try {
    if (row.status === 'queued') {
      await removeScanTask(row.id)
    } else {
      if (row.status === 'running') await stopScan()
      await deleteTask(row.id)
    }
    ElMessage.success('已删除')
    loadTasks()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

const offFns = [on('done', () => loadTasks())]
onUnmounted(() => offFns.forEach((f) => f && f()))

function fmtTime(t) {
  const d = new Date(t)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

onMounted(async () => {
  try {
    regions.value = await getRegions()
  } catch (e) {
    ElMessage.error('区域列表加载失败: ' + e.message)
  }
  try {
    const saved = await getConfig()
    if (saved?.scan) Object.assign(cfg, saved.scan)
    // 「必须 HTTPS」与「延迟上限」已移除：双协议自动识别 HTTPS，延迟不再作为入库门槛
    cfg.requireHttps = false
    cfg.maxLatency = 0
    cfg.fullCoverMaxIPs = 0
  } catch (e) {
    /* 使用默认值 */
  }
  normalizeRegionNames()
  loadTasks()
})
</script>

<style scoped>
.panel {
  background: #fff;
  border: 1px solid #e8ebf0;
  border-radius: 10px;
  padding: 14px 16px;
}

.mt {
  margin-top: 14px;
}

.presets {
  margin-top: 8px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.tip {
  font-size: 11px;
  color: #9ca3af;
  line-height: 1.5;
}

.est {
  margin: 6px 0 12px;
  font-size: 13px;
}

.est-sub {
  margin-top: 4px;
  font-size: 12px;
  color: #6b7280;
}

.hint-inline {
  margin-left: 8px;
  font-size: 12px;
  color: #9aa1ac;
}

.btns {
  display: flex;
  gap: 10px;
  margin-top: 10px;
}

.kv {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  font-size: 12px;
  color: #6b7280;
  margin-top: 10px;
}

.kv .warn {
  color: #e6a23c;
}

.warn-tip {
  margin-top: 8px;
  padding: 8px 10px;
  border-radius: 6px;
  background: #fdf6ec;
  color: #b88230;
  line-height: 1.6;
}

.logs {
  max-height: 220px;
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

<template>
  <div class="panel">
    <div class="card-title">
      <span>定时任务</span>
      <el-space>
        <el-button type="primary" size="small" @click="openCreate"><el-icon><Plus /></el-icon> 新建定时任务</el-button>
        <el-button size="small" plain @click="load">刷新</el-button>
      </el-space>
    </div>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      title="到点后自动触发对应任务；同一时刻只允许一个任务运行，若已有任务在执行会自动顺延 1 分钟"
      style="margin-bottom: 12px"
    />

    <el-table :data="list" size="small" stripe v-loading="loading">
      <el-table-column prop="name" label="任务名称" min-width="160" />
      <el-table-column label="类型" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="row.kind === 'scan' ? 'primary' : 'warning'">{{ row.kind === 'scan' ? '扫描' : '验证代理池' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="触发规则" min-width="170">
        <template #default="{ row }">
          <span>{{ repeatText(row) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="下次执行" width="160">
        <template #default="{ row }">
          <span class="mono">{{ row.enabled ? fmtDateTime(row.nextRunAt) : '—' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="上次执行" width="160">
        <template #default="{ row }"><span class="muted mono">{{ row.runCount ? fmtDateTime(row.lastRunAt) : '从未执行' }}</span></template>
      </el-table-column>
      <el-table-column prop="runCount" label="次数" width="80" />
      <el-table-column label="最近结果" min-width="140">
        <template #default="{ row }"><span class="muted">{{ row.lastResult || '-' }}</span></template>
      </el-table-column>
      <el-table-column label="启用" width="80">
        <template #default="{ row }">
          <el-switch v-model="row.enabled" size="small" @change="(v) => onToggle(row, v)" />
        </template>
      </el-table-column>
      <el-table-column label="操作" width="180" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="run(row.id)">立即执行</el-button>
          <el-button link type="warning" @click="openEdit(row)">编辑</el-button>
          <el-button link type="danger" @click="remove(row.id)">删除</el-button>
        </template>
      </el-table-column>
      <template #empty>
        <el-empty description="还没有定时任务" :image-size="80" />
      </template>
    </el-table>

    <!-- 编辑/新增弹窗 -->
    <el-dialog v-model="dialog" :title="form.id ? '编辑定时任务' : '新建定时任务'" width="620px">
      <el-form label-width="110px">
        <el-form-item label="任务名称">
          <el-input v-model="form.name" placeholder="例如：每日凌晨扫描中国代理" />
        </el-form-item>
        <el-form-item label="任务类型">
          <el-radio-group v-model="form.kind">
            <el-radio value="scan">扫描代理</el-radio>
            <el-radio value="verify">验证代理池</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="执行方式">
          <el-select v-model="form.repeat" style="width: 100%">
            <el-option label="每天" value="daily" />
            <el-option label="每周指定星期" value="weekly" />
            <el-option label="按间隔循环" value="interval" />
            <el-option label="仅一次" value="once" />
          </el-select>
        </el-form-item>

        <el-form-item v-if="form.repeat === 'daily' || form.repeat === 'weekly'" label="执行时间">
          <el-time-picker v-model="timeVal" format="HH:mm" placeholder="选择时间" style="width: 100%" />
        </el-form-item>
        <el-form-item v-if="form.repeat === 'weekly'" label="星期">
          <el-select v-model="form.weekday" style="width: 100%">
            <el-option v-for="d in weekdays" :key="d.value" :label="d.label" :value="d.value" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.repeat === 'interval'" label="间隔分钟">
          <el-input-number v-model="form.intervalMin" :min="1" :max="10080" />
        </el-form-item>
        <el-form-item v-if="form.repeat === 'once'" label="执行时刻">
          <el-date-picker v-model="onceVal" type="datetime" placeholder="选择日期时间" format="YYYY-MM-DD HH:mm" value-format="YYYY-MM-DD HH:mm" style="width: 100%" />
        </el-form-item>

        <el-form-item v-if="form.kind === 'scan'" label="扫描配置">
          <el-space wrap>
            <el-button size="small" @click="fillCurrent">使用「扫描任务」页当前配置</el-button>
            <el-button size="small" plain @click="paramsMode = paramsMode === 'json' ? 'summary' : 'json'">
              {{ paramsMode === 'json' ? '查看摘要' : '编辑 JSON' }}
            </el-button>
          </el-space>
        </el-form-item>
        <el-form-item v-if="form.kind === 'scan' && paramsMode === 'json'" label="配置 JSON">
          <el-input v-model="form.params" type="textarea" :rows="6" />
        </el-form-item>
        <el-form-item v-if="form.kind === 'scan' && paramsMode !== 'json'" label="配置摘要">
          <div class="summary">{{ summary }}</div>
        </el-form-item>

        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" @click="submit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { deleteSchedule, getConfig, listSchedules, runSchedule, saveSchedule, toggleSchedule } from '../api'
import { fmtDateTime, humanCount } from '../utils'

const list = ref([])
const loading = ref(false)
const dialog = ref(false)
const paramsMode = ref('summary')
const timeVal = ref('03:00')
const onceVal = ref('')

const weekdays = [
  { label: '周日', value: 0 },
  { label: '周一', value: 1 },
  { label: '周二', value: 2 },
  { label: '周三', value: 3 },
  { label: '周四', value: 4 },
  { label: '周五', value: 5 },
  { label: '周六', value: 6 }
]

const defaultForm = () => ({
  id: 0,
  name: '',
  kind: 'scan',
  repeat: 'daily',
  runTime: '03:00',
  onceAt: '',
  intervalMin: 120,
  weekday: 1,
  params: '',
  enabled: true
})

const form = reactive(defaultForm())

const summary = computed(() => {
  try {
    const c = JSON.parse(form.params || '{}')
    const ports = (c.ports || []).slice(0, 6).join(',') + ((c.ports || []).length > 6 ? '…' : '')
    return [
      `国家/地区: ${(c.countries || []).join('、') || '未指定'}`,
      c.keyword ? `关键字: ${c.keyword}` : '',
      `端口: ${ports || '未指定'}`,
      `并发 ${c.concurrency} · 超时 ${c.timeoutMs}ms · 抽样 ${humanCount(c.maxCandidates)}`,
      `匿名要求: ${{ 3: '仅高匿名', 2: '普通匿名及以上', 0: '不限' }[c.minAnonymity] || '不限'}${c.requireHttps ? ' · 必须HTTPS' : ''}`
    ]
      .filter(Boolean)
      .join(' | ')
  } catch (e) {
    return '配置 JSON 解析失败'
  }
})

function repeatText(row) {
  switch (row.repeat) {
    case 'daily':
      return `每天 ${row.runTime}`
    case 'weekly':
      return `每周${weekdays.find((w) => w.value === row.weekday)?.label || ''} ${row.runTime}`
    case 'interval':
      return `每 ${row.intervalMin} 分钟`
    case 'once':
      return `仅一次 ${row.runTime}`
    default:
      return row.repeat
  }
}

async function load() {
  loading.value = true
  try {
    list.value = await listSchedules()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function openCreate() {
  Object.assign(form, defaultForm())
  timeVal.value = '03:00'
  onceVal.value = ''
  paramsMode.value = 'summary'
  fillCurrent(true)
  dialog.value = true
}

function openEdit(row) {
  Object.assign(form, defaultForm(), row)
  const repeats = ['daily', 'weekly']
  if (repeats.includes(row.repeat)) timeVal.value = row.runTime || '03:00'
  if (row.repeat === 'once') onceVal.value = row.onceAt || row.runTime || ''
  dialog.value = true
}

async function fillCurrent(silent) {
  try {
    const cfg = await getConfig()
    if (cfg?.scan) form.params = JSON.stringify(cfg.scan)
    else form.params = '{}'
    if (!silent) ElMessage.success('已填入扫描页当前配置')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function submit() {
  if (!form.name.trim()) {
    ElMessage.warning('请填写任务名称')
    return
  }
  if (form.repeat === 'daily' || form.repeat === 'weekly') {
    if (!timeVal.value) {
      ElMessage.warning('请选择执行时间')
      return
    }
    // el-time-picker 返回 Date 或字符串，统一取 HH:mm
    form.runTime = typeof timeVal.value === 'string' ? timeVal.value : hhmm(timeVal.value)
  }
  if (form.repeat === 'once') {
    if (!onceVal.value) {
      ElMessage.warning('请选择执行时刻')
      return
    }
    form.onceAt = onceVal.value
    form.runTime = onceVal.value
  }
  if (form.kind === 'verify') form.params = ''
  if (form.kind === 'scan' && !form.params) {
    ElMessage.warning('请点击「使用扫描任务页当前配置」或填写配置 JSON')
    return
  }
  try {
    await saveSchedule({ ...form })
    ElMessage.success('已保存')
    dialog.value = false
    load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

function hhmm(d) {
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}`
}

async function onToggle(row, v) {
  try {
    await toggleSchedule(row.id, v)
    ElMessage.success(v ? '已启用' : '已停用')
    load()
  } catch (e) {
    row.enabled = !v
    ElMessage.error(e.message)
  }
}

async function run(id) {
  try {
    await runSchedule(id)
    ElMessage.success('已触发，请到扫描任务页查看进度')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function remove(id) {
  try {
    await ElMessageBox.confirm('确认删除该定时任务？', '提示', { type: 'warning' })
  } catch {
    return
  }
  try {
    await deleteSchedule(id)
    ElMessage.success('已删除')
    load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

onMounted(load)
</script>

<style scoped>
.panel {
  background: #fff;
  border: 1px solid #e8ebf0;
  border-radius: 10px;
  padding: 14px 16px;
}

.summary {
  font-size: 12px;
  color: #4b5563;
  line-height: 1.7;
  word-break: break-all;
}
</style>

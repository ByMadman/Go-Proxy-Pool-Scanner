<template>
  <div class="panel">
    <div class="filters">
      <el-input v-model="q.keyword" placeholder="IP / 归属地 / 出口IP" clearable style="width: 200px" @keyup.enter="reload" />
      <el-select v-model="q.country" clearable filterable placeholder="国家/地区" style="width: 160px" @change="reload">
        <el-option v-for="c in countries" :key="c.name" :label="c.name" :value="c.name" />
      </el-select>
      <el-input v-model="q.province" placeholder="省（为空不限）" clearable style="width: 130px" @keyup.enter="reload" @change="reload" />
      <el-input v-model="q.city" placeholder="市（为空不限）" clearable style="width: 130px" @keyup.enter="reload" @change="reload" />
      <el-input v-model="q.district" placeholder="区（为空不限）" clearable style="width: 130px" @keyup.enter="reload" @change="reload" />
      <el-select v-model="q.protocol" clearable placeholder="协议" style="width: 130px" @change="reload">
        <el-option label="HTTP" value="http" />
        <el-option label="HTTPS" value="https" />
      </el-select>
      <el-select v-model="q.level" clearable placeholder="匿名等级" style="width: 140px" @change="reload">
        <el-option label="高匿名" :value="3" />
        <el-option label="普通匿名" :value="2" />
        <el-option label="透明" :value="1" />
        <el-option label="未知（未判定）" :value="0" />
      </el-select>
      <el-input-number v-model="q.maxLatency" :min="0" :max="30000" :step="500" placeholder="延迟≤ms" style="width: 150px" @change="reload" />
      <el-select v-model="sort" placeholder="排序" style="width: 170px" @change="reload">
        <el-option label="延迟升序" value="latency-asc" />
        <el-option label="延迟降序" value="latency-desc" />
        <el-option label="最近验证" value="verified_at-desc" />
        <el-option label="最早添加" value="id-asc" />
      </el-select>
      <el-button type="primary" @click="reload">查询</el-button>
      <el-button @click="reset">重置</el-button>
    </div>

    <div class="ops">
      <el-space wrap>
        <el-button type="success" :loading="verifying" @click="doVerify([])">
          <el-icon><Refresh /></el-icon> 一键验证（全部）
        </el-button>
        <el-button type="warning" plain :disabled="!selection.length" :loading="verifying" @click="doVerify(selection.map((r) => r.id))">
          验证选中({{ selection.length }})
        </el-button>
        <el-button type="danger" plain :disabled="!selection.length" @click="doDeleteSelected">删除选中({{ selection.length }})</el-button>
        <el-dropdown trigger="click" @command="doExport">
          <el-button><el-icon><Download /></el-icon> 导出<el-icon><ArrowDown /></el-icon></el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="txt">TXT（ip:port）</el-dropdown-item>
              <el-dropdown-item command="json">JSON</el-dropdown-item>
              <el-dropdown-item command="csv">CSV</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button type="danger" plain @click="doClear">清空失效/全部</el-button>
        <el-switch v-model="autoRefresh" active-text="自动刷新(10s)" size="small" />
        <el-tag size="small" effect="plain">共 {{ total }} 条</el-tag>
      </el-space>
    </div>

    <el-table ref="tableRef" v-loading="loading" :data="list" size="small" stripe @selection-change="(v) => (selection = v)">
      <el-table-column type="selection" width="42" />
      <el-table-column label="IP" width="140">
        <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
      </el-table-column>
      <el-table-column label="端口" width="80">
        <template #default="{ row }"><span class="mono">{{ row.port }}</span></template>
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
      <el-table-column label="延迟" width="100" prop="latency" sortable="custom">
        <template #default="{ row }">
          <span class="mono" :class="latencyClass(row.latency)">{{ row.latency }} ms</span>
        </template>
      </el-table-column>
      <el-table-column label="归属地(ip2region)" min-width="180">
        <template #default="{ row }">{{ row.region || '-' }}</template>
      </el-table-column>
      <el-table-column label="出口 IP" width="130">
        <template #default="{ row }"><span class="mono muted">{{ row.exitIp || '-' }}</span></template>
      </el-table-column>
      <el-table-column label="最后验证" width="150">
        <template #default="{ row }"><span class="muted">{{ fmtDateTime(row.verifiedAt) }}</span></template>
      </el-table-column>
      <el-table-column label="操作" width="130" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" :disabled="rt.progress.running" @click="verifyOne(row.id)">验证</el-button>
          <el-button link type="danger" @click="del(row.id)">删除</el-button>
        </template>
      </el-table-column>
      <template #empty>
        <el-empty description="代理池为空，先到「扫描任务」跑一轮" :image-size="80" />
      </template>
    </el-table>

    <div class="pager">
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="size"
        :page-sizes="[20, 50, 100, 200]"
        :total="total"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="reload"
        @current-change="reload"
      />
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, Download, Refresh } from '@element-plus/icons-vue'
import { clearProxies, deleteProxies, deleteProxy, exportURL, getProxies, getRegions, verifyProxies, verifyProxy } from '../api'
import { rt, on } from '../realtime'
import { fmtDateTime, levelText, levelType } from '../utils'

const list = ref([])
const total = ref(0)
const page = ref(1)
const size = ref(20)
const loading = ref(false)
const verifying = ref(false)
const selection = ref([])
const countries = ref([])
const autoRefresh = ref(false)
const sort = ref('latency-asc')

const defaultQuery = () => ({ keyword: '', country: '', province: '', city: '', district: '', protocol: '', level: '', maxLatency: 0 })
const q = reactive(defaultQuery())

let timer = null
const offFns = []

async function reload() {
  loading.value = true
  try {
    const [field, order] = sort.value.split('-')
    const res = await getProxies({
      page: page.value,
      size: size.value,
      keyword: q.keyword,
      country: q.country,
      province: q.province,
      city: q.city,
      district: q.district,
      protocol: q.protocol,
      level: q.level === '' ? '' : q.level,
      maxLatency: q.maxLatency || '',
      sortBy: field,
      order
    })
    list.value = res.list || []
    total.value = res.total || 0
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function reset() {
  Object.assign(q, defaultQuery())
  sort.value = 'latency-asc'
  page.value = 1
  reload()
}

async function doVerify(ids) {
  verifying.value = true
  try {
    await verifyProxies(ids)
    ElMessage.success(ids.length ? '已开始验证选中代理' : '已开始全库验证，失败记录会自动删除')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    verifying.value = false
  }
}

async function verifyOne(id) {
  try {
    await verifyProxy(id)
    ElMessage.success('已提交验证')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function del(id) {
  try {
    await deleteProxy(id)
    list.value = list.value.filter((r) => r.id !== id)
    ElMessage.success('已删除')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function doDeleteSelected() {
  try {
    await ElMessageBox.confirm(`确认删除选中的 ${selection.value.length} 条代理？`, '提示', { type: 'warning' })
  } catch {
    return
  }
  try {
    const n = await deleteProxies(selection.value.map((r) => r.id))
    ElMessage.success(`已删除 ${n} 条`)
    reload()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function doClear() {
  try {
    await ElMessageBox.confirm('清空代理池？该操作不可恢复。', '危险操作', { type: 'error', confirmButtonText: '确认清空' })
  } catch {
    return
  }
  try {
    const n = await clearProxies('')
    ElMessage.success(`已清空 ${n} 条`)
    reload()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

function doExport(fmt) {
  window.open(exportURL({ format: fmt, country: q.country, province: q.province, city: q.city, district: q.district, protocol: q.protocol, level: q.level, maxLatency: q.maxLatency }), '_blank')
}

function latencyClass(ms) {
  if (ms <= 800) return 'ok'
  if (ms <= 2000) return 'mid'
  return 'bad'
}

watch(autoRefresh, (v) => {
  if (timer) clearInterval(timer)
  if (v) timer = setInterval(reload, 10000)
})

// 实时事件：删除/更新后自动同步
offFns.push(on('removed', () => reload()))
offFns.push(
  on('updated', (p) => {
    const idx = list.value.findIndex((r) => r.id === p.id)
    if (idx >= 0) list.value[idx] = p
  })
)
offFns.push(
  on('done', () => {
    reload()
  })
)

onMounted(async () => {
  await reload()
  try {
    countries.value = (await getRegions()).map((c) => ({ name: c.name }))
  } catch (e) {
    /* 忽略 */
  }
})

onUnmounted(() => {
  offFns.forEach((fn) => fn && fn())
  if (timer) clearInterval(timer)
})

const _ = computed(() => rt.progress.running)
</script>

<style scoped>
.panel {
  background: #fff;
  border: 1px solid #e8ebf0;
  border-radius: 10px;
  padding: 14px 16px;
}

.filters {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: 10px;
}

.ops {
  margin-bottom: 10px;
}

.pager {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}

.ok {
  color: #16a34a;
}

.mid {
  color: #d97706;
}

.bad {
  color: #dc2626;
}
</style>

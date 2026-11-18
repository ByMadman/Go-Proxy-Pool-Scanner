<template>
  <div>
    <div class="bar">
      <div>
        <el-input v-model="kw" placeholder="搜索令牌名称" clearable style="width:220px" />
      </div>
      <el-button type="primary" :icon="Plus" @click="openCreate">新建提取令牌</el-button>
    </div>

    <el-table :data="filtered" border stripe v-loading="loading">
      <el-table-column prop="id" label="ID" width="64" />
      <el-table-column prop="name" label="名称" min-width="120" />
      <el-table-column label="令牌" min-width="220">
        <template #default="{ row }">
          <code class="tk">{{ row.token }}</code>
          <el-button link type="primary" size="small" @click="copy(row.token)">复制</el-button>
        </template>
      </el-table-column>
      <el-table-column label="过期时间" width="160">
        <template #default="{ row }">
          <span :class="{ expired: isExpired(row) }">{{ fmt(row.expiresAt) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="单次数量" width="90">
        <template #default="{ row }">{{ row.count > 0 ? row.count : '不限' }}</template>
      </el-table-column>
      <el-table-column label="累计额度" width="110">
        <template #default="{ row }">{{ row.maxTotal > 0 ? row.maxTotal : '不限' }}</template>
      </el-table-column>
      <el-table-column label="已提取" width="90" prop="used" />
      <el-table-column label="剩余" width="90">
        <template #default="{ row }">
          <span v-if="row.maxTotal > 0">{{ Math.max(0, row.maxTotal - row.used) }}</span>
          <span v-else>—</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag :type="row.enabled === 1 ? 'success' : 'info'" size="small">
            {{ row.enabled === 1 ? '启用' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="200" fixed="right">
        <template #default="{ row }">
          <el-button size="small" :type="row.enabled === 1 ? 'warning' : 'success'" @click="toggle(row)">
            {{ row.enabled === 1 ? '停用' : '启用' }}
          </el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="hint">
      提取 API 示例：<code>GET /api/proxies/extract?token=YOUR_TOKEN&amp;format=txt&amp;https=1</code>
      返回数量受令牌「单次数量」限制（0 = 不限），且受过期时间与累计额度约束。
    </div>

    <el-dialog v-model="showCreate" title="新建提取令牌" width="460px">
      <el-form label-width="92px">
        <el-form-item label="名称">
          <el-input v-model="form.name" placeholder="便于识别，如：给A客户" />
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker v-model="form.expiresAt" type="datetime" placeholder="选择过期时间"
            value-format="YYYY-MM-DD HH:mm:ss" format="YYYY-MM-DD HH:mm:ss" :default-value="defaultExp"
            style="width:100%" />
        </el-form-item>
        <el-form-item label="单次数量">
          <el-input-number v-model="form.count" :min="0" :max="10000" />
          <span class="muted"> 每次提取返回的代理条数，0 = 不限</span>
        </el-form-item>
        <el-form-item label="累计额度">
          <el-input-number v-model="form.maxTotal" :min="0" :max="1000000" />
          <span class="muted"> 0 = 不限（按次数无限提取）</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="create">创建</el-button>
      </template>
      <div v-if="createdToken" class="created">
        <el-alert type="success" :closable="false" show-icon>
          <template #title>令牌已创建，请立即复制保存（仅显示一次）</template>
        </el-alert>
        <code class="tk big">{{ createdToken }}</code>
        <el-button link type="primary" @click="copy(createdToken)">复制令牌</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'
import { Plus } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import http from '../api'

const loading = ref(false)
const list = ref([])
const kw = ref('')
const showCreate = ref(false)
const creating = ref(false)
const createdToken = ref('')

const defaultExp = new Date(Date.now() + 7 * 86400000)
const form = reactive({ name: '', expiresAt: '', count: 100, maxTotal: 0 })

const filtered = computed(() => {
  const k = kw.value.trim().toLowerCase()
  if (!k) return list.value
  return list.value.filter((t) => (t.name || '').toLowerCase().includes(k))
})

function fmt(s) {
  if (!s) return '-'
  return String(s).replace('T', ' ').slice(0, 19)
}
function isExpired(row) {
  return new Date(row.expiresAt).getTime() < Date.now()
}

async function load() {
  loading.value = true
  try {
    list.value = await http.get('/tokens')
  } catch (e) {
    ElMessage.error(e.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  createdToken.value = ''
  form.name = ''
  form.expiresAt = ''
  form.count = 100
  form.maxTotal = 0
  showCreate.value = true
}

async function create() {
  if (!form.expiresAt) {
    ElMessage.warning('请选择过期时间')
    return
  }
  creating.value = true
  try {
    const r = await http.post('/tokens', { ...form })
    createdToken.value = r.token
    ElMessage.success('创建成功')
    load()
  } catch (e) {
    ElMessage.error(e.message || '创建失败')
  } finally {
    creating.value = false
  }
}

async function toggle(row) {
  try {
    await http.post(`/tokens/${row.id}/toggle`, { enabled: row.enabled !== 1 })
    ElMessage.success('已更新')
    load()
  } catch (e) {
    ElMessage.error(e.message || '操作失败')
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确定删除令牌「${row.name || row.token}」？`, '提示', { type: 'warning' })
  } catch (e) {
    return
  }
  try {
    await http.delete(`/tokens/${row.id}`)
    ElMessage.success('已删除')
    load()
  } catch (e) {
    ElMessage.error(e.message || '删除失败')
  }
}

function copy(t) {
  navigator.clipboard?.writeText(t).then(
    () => ElMessage.success('已复制'),
    () => ElMessage.warning('复制失败，请手动复制')
  )
}

load()
</script>

<style scoped>
.bar {
  display: flex;
  justify-content: space-between;
  margin-bottom: 14px;
}
.tk {
  background: #f3f4f6;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 12px;
  word-break: break-all;
}
.tk.big {
  display: block;
  margin: 10px 0;
  font-size: 13px;
}
.expired {
  color: #ef4444;
}
.hint {
  margin-top: 16px;
  color: #64748b;
  font-size: 13px;
  line-height: 1.8;
}
.hint code {
  background: #f1f5f9;
  padding: 2px 6px;
  border-radius: 4px;
}
.created {
  margin-top: 10px;
}
.muted {
  color: #94a3b8;
  font-size: 12px;
}
</style>

<template>
  <div class="panel">
    <div class="card-title">
      <span>历史任务</span>
      <el-space>
        <el-button type="primary" plain size="small" @click="load">刷新</el-button>
        <el-button type="danger" plain size="small" :disabled="!tasks.length" @click="clearRecords">清理记录</el-button>
      </el-space>
    </div>
    <el-table :data="tasks" size="small" stripe v-loading="loading">
      <el-table-column prop="id" label="#" width="60" />
      <el-table-column prop="name" label="任务" min-width="200" />
      <el-table-column label="类型" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="row.type === 'scan' ? 'primary' : 'warning'">{{ row.type === 'scan' ? '扫描' : '验证' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="statusType(row.status)">{{ statusText(row.status) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="已检查" width="100">
        <template #default="{ row }"><span class="mono">{{ row.scanned }}/{{ row.total }}</span></template>
      </el-table-column>
      <el-table-column prop="found" label="入库" width="90" />
      <el-table-column prop="failed" label="删除" width="90" />
      <el-table-column label="开始时间" width="160">
        <template #default="{ row }"><span class="muted">{{ fmtDateTime(row.startedAt) }}</span></template>
      </el-table-column>
      <el-table-column prop="message" label="说明" min-width="200" />
    </el-table>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listTasks, clearTasks } from '../api'
import { fmtDateTime } from '../utils'

const tasks = ref([])
const loading = ref(false)

function statusText(s) {
  return { running: '运行中', completed: '已完成', stopped: '已停止', failed: '失败' }[s] || s
}

function statusType(s) {
  return { running: 'warning', completed: 'success', stopped: 'info', failed: 'danger' }[s] || 'info'
}

async function load() {
  loading.value = true
  try {
    tasks.value = await listTasks()
  } finally {
    loading.value = false
  }
}

async function clearRecords() {
  try {
    await ElMessageBox.confirm('确认清空全部历史任务记录？该操作不可恢复。', '危险操作', {
      type: 'error',
      confirmButtonText: '确认清空'
    })
  } catch {
    return
  }
  try {
    await clearTasks()
    ElMessage.success('历史任务记录已清空')
    await load()
  } catch (e) {
    ElMessage.error(e.message || '清理失败')
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
</style>

<template>
  <Login v-if="!loggedIn" @success="onLogin" />
  <div v-else class="layout">
    <aside class="side">
      <div class="brand">
        <div class="logo">PS</div>
        <div class="brand-text">
          <div class="t">ProxyScanner</div>
          <div class="s">高匿名代理扫描器</div>
        </div>
      </div>
      <el-menu :default-active="active" class="menu" text-color="#c7cedb" active-text-color="#ffffff" background-color="transparent" @select="onSelect">
        <el-menu-item index="dashboard">
          <el-icon><DataLine /></el-icon>
          <span>仪表盘</span>
        </el-menu-item>
        <el-menu-item index="scan">
          <el-icon><Promotion /></el-icon>
          <span>扫描任务</span>
        </el-menu-item>
        <el-menu-item index="pool">
          <el-icon><Coin /></el-icon>
          <span>代理池</span>
        </el-menu-item>
        <el-menu-item index="tasks">
          <el-icon><Tickets /></el-icon>
          <span>任务记录</span>
        </el-menu-item>
        <el-menu-item index="schedules">
          <el-icon><Timer /></el-icon>
          <span>定时任务</span>
        </el-menu-item>
        <el-menu-item index="tokens">
          <el-icon><Key /></el-icon>
          <span>提取令牌</span>
        </el-menu-item>
        <el-menu-item index="settings">
          <el-icon><Setting /></el-icon>
          <span>参数配置</span>
        </el-menu-item>
      </el-menu>
      <div class="side-foot">
        <div class="row">
          <span class="dot" :class="rt.connected ? 'ok' : 'bad'" /> {{ rt.connected ? '已连接' : '未连接' }}
        </div>
        <div class="row muted">ip2region · IPv4 离线库</div>
      </div>
    </aside>

    <main class="main">
      <header class="top">
        <div class="title">
          <h2>{{ titles[active] }}</h2>
          <span class="muted">{{ subtitles[active] }}</span>
        </div>
        <div class="right">
          <el-tag v-if="rt.progress.running" type="warning" effect="dark" size="small">
            {{ rt.progress.type === 'verify' ? '验证中' : '扫描中' }} · {{ rt.progress.scanned }}/{{ rt.progress.total }}
          </el-tag>
          <el-tag v-else type="info" size="small">空闲</el-tag>
          <span class="ip">本机公网 IP: <b>{{ appState.publicIp || '未知' }}</b></span>
          <el-dropdown @command="onUserMenu">
            <span class="user">
              <el-icon><User /></el-icon> {{ username }}
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="pass">修改密码</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <section class="content">
        <transition name="fade" mode="out-in">
          <component :is="views[active]" />
        </transition>
      </section>
    </main>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { Coin, DataLine, Key, Promotion, Setting, Tickets, Timer, User } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { rt } from './realtime'
import { detectPublicIP, getMe, logoutUser, changePassword, UNAUTHORIZED_EVENT } from './api'
import Dashboard from './views/Dashboard.vue'
import Scan from './views/Scan.vue'
import Pool from './views/Pool.vue'
import Tasks from './views/Tasks.vue'
import Schedules from './views/Schedules.vue'
import Tokens from './views/Tokens.vue'
import Settings from './views/Settings.vue'
import Login from './views/Login.vue'

const views = { dashboard: Dashboard, scan: Scan, pool: Pool, tasks: Tasks, schedules: Schedules, tokens: Tokens, settings: Settings }
const titles = {
  dashboard: '仪表盘',
  scan: '扫描任务',
  pool: '代理池',
  tasks: '任务记录',
  schedules: '定时任务',
  tokens: '提取令牌',
  settings: '参数配置'
}
const subtitles = {
  dashboard: '运行概览与代理分布',
  scan: '按国家/地区自动提取 IP 段并验证代理',
  pool: '查询、筛选、验证与导出可用代理',
  tasks: '历史扫描与验证任务',
  schedules: '到时间自动触发扫描或验证任务',
  tokens: '创建带过期时间与提取数量限制的代理提取令牌',
  settings: '回显站点、超时、并发等高级参数'
}

const active = ref(localStorage.getItem('ps.active') || 'dashboard')
const appState = reactive({ publicIp: '' })
const loggedIn = ref(!!localStorage.getItem('ps.token'))
const username = ref('')

function onSelect(index) {
  active.value = index
  localStorage.setItem('ps.active', index)
}

function onLogin() {
  loggedIn.value = true
  refreshUser()
}

async function refreshUser() {
  try {
    const me = await getMe()
    username.value = me.username
  } catch (e) {
    username.value = ''
  }
}

async function onUserMenu(cmd) {
  if (cmd === 'logout') {
    try {
      await logoutUser()
    } catch (e) {}
    localStorage.removeItem('ps.token')
    loggedIn.value = false
    return
  }
  if (cmd === 'pass') {
    try {
      const { value } = await ElMessageBox.prompt('请输入原密码', '修改密码', { inputType: 'password', inputPlaceholder: '原密码' })
      const { value: nv } = await ElMessageBox.prompt('请输入新密码（至少 6 位）', '修改密码', { inputType: 'password', inputPlaceholder: '新密码' })
      await changePassword({ oldPassword: value, newPassword: nv })
      ElMessage.success('密码已修改')
    } catch (e) {
      if (e !== 'cancel') ElMessage.error(e.message || '修改失败')
    }
  }
}

window.addEventListener(UNAUTHORIZED_EVENT, () => {
  loggedIn.value = false
})

onMounted(async () => {
  if (loggedIn.value) {
    await refreshUser()
    try {
      appState.publicIp = await detectPublicIP()
    } catch (e) {
      appState.publicIp = ''
    }
  }
})
</script>

<style scoped>
.layout {
  display: flex;
  height: 100%;
}

.side {
  width: 216px;
  flex: 0 0 216px;
  background: linear-gradient(180deg, #1f2937 0%, #111827 100%);
  color: #fff;
  display: flex;
  flex-direction: column;
  padding: 16px 12px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 8px 18px;
}

.logo {
  width: 34px;
  height: 34px;
  border-radius: 9px;
  background: linear-gradient(135deg, #3b82f6, #06b6d4);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 13px;
}

.brand-text .t {
  font-weight: 600;
  font-size: 14px;
}

.brand-text .s {
  font-size: 11px;
  color: #8b97a8;
}

.menu {
  border-right: none;
  flex: 1;
}

:deep(.el-menu-item) {
  border-radius: 8px;
  margin-bottom: 4px;
  height: 42px;
}

:deep(.el-menu-item.is-active) {
  background: rgba(59, 130, 246, 0.22) !important;
}

.side-foot {
  font-size: 12px;
  padding: 10px 8px;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
}

.side-foot .row {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 4px 0;
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #909399;
}

.dot.ok {
  background: #22c55e;
}

.dot.bad {
  background: #ef4444;
}

.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.top {
  height: 60px;
  background: #fff;
  border-bottom: 1px solid #e8ebf0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
}

.top .title {
  display: flex;
  align-items: baseline;
  gap: 10px;
}

.top h2 {
  margin: 0;
  font-size: 17px;
}

.top .right {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
}

.content {
  flex: 1;
  overflow: auto;
  padding: 16px 20px 28px;
}
</style>

<template>
  <div class="login-wrap">
    <div class="login-card">
      <div class="brand">
        <div class="logo">PS</div>
        <div>
          <div class="t">ProxyScanner</div>
          <div class="s">高匿名代理扫描器 · 控制台登录</div>
        </div>
      </div>
      <el-form @submit.prevent="onSubmit" label-position="top">
        <el-form-item label="用户名">
          <el-input v-model="form.username" placeholder="请输入用户名" :prefix-icon="User" autofocus />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="form.password" type="password" show-password placeholder="请输入密码"
            :prefix-icon="Lock" @keyup.enter="onSubmit" />
        </el-form-item>
        <el-button type="primary" :loading="loading" class="submit" @click="onSubmit">登 录</el-button>
        <div v-if="error" class="err">{{ error }}</div>
        <div class="tip">默认账号 admin / admin123，请登录后在「参数配置」中修改密码</div>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { User, Lock } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { loginUser } from '../api'

const emit = defineEmits(['success'])
const form = reactive({ username: '', password: '' })
const loading = ref(false)
const error = ref('')

async function onSubmit() {
  if (!form.username || !form.password) {
    error.value = '请输入用户名和密码'
    return
  }
  error.value = ''
  loading.value = true
  try {
    const data = await loginUser({ username: form.username, password: form.password })
    localStorage.setItem('ps.token', data.token)
    ElMessage.success('登录成功')
    emit('success', data)
  } catch (e) {
    error.value = e.message || '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-wrap {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #1e293b, #0f172a);
}
.login-card {
  width: 360px;
  background: #fff;
  border-radius: 14px;
  padding: 28px 26px 22px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.35);
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 18px;
}
.logo {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: linear-gradient(135deg, #3b82f6, #06b6d4);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  color: #fff;
}
.brand .t {
  font-weight: 600;
  font-size: 16px;
}
.brand .s {
  font-size: 12px;
  color: #8b97a8;
}
.submit {
  width: 100%;
  margin-top: 6px;
}
.err {
  color: #ef4444;
  font-size: 13px;
  margin-top: 10px;
}
.tip {
  color: #94a3b8;
  font-size: 12px;
  margin-top: 14px;
  text-align: center;
}
</style>

<template>
  <el-row :gutter="14">
    <el-col :span="14">
      <div class="panel">
        <div class="card-title">
          <span>验证站点（回显服务器）</span>
          <el-space>
            <el-button size="small" @click="addEcho">新增</el-button>
            <el-button size="small" plain @click="resetEcho">恢复默认</el-button>
          </el-space>
        </div>
        <el-table :data="verify.echoServers" size="small" max-height="360">
          <el-table-column label="URL" min-width="260">
            <template #default="{ row }"><el-input v-model="row.url" size="small" placeholder="http(s)://..." /></template>
          </el-table-column>
          <el-table-column label="类型" width="130">
            <template #default="{ row }">
              <el-select v-model="row.kind" size="small">
                <el-option label="回显请求头" value="headers" />
                <el-option label="仅回显IP" value="ip" />
                <el-option label="连通性" value="connect" />
              </el-select>
            </template>
          </el-table-column>
          <el-table-column label="说明" min-width="180">
            <template #default="{ row }"><el-input v-model="row.note" size="small" /></template>
          </el-table-column>
          <el-table-column label="操作" width="70">
            <template #default="{ $index }">
              <el-button link type="danger" size="small" @click="verify.echoServers.splice($index, 1)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div class="tip">
          已为你预置好回显服务器（自建裸 IP，HTTP/HTTPS 同端口），用于判定代理匿名等级，<b>一般无需修改</b>。<br />
          判定原理：<b>回显请求头</b> 站点把服务端收到的请求头返回，据此区分透明 / 普通匿名 / 高匿名；
          <b>仅回显IP</b> 只能拿到出口 IP，匿名等级记为未知；<b>连通性</b> 仅验证代理能否连通。
        </div>
      </div>

      <div class="panel mt">
        <div class="card-title"><span>HTTPS 连通性目标</span></div>
        <el-select v-model="verify.httpsTargets" multiple filterable allow-create default-first-option style="width: 100%">
          <el-option v-for="t in defaultTargets" :key="t" :label="t" :value="t" />
        </el-select>
        <div class="tip">用于验证代理是否支持 CONNECT 隧道（HTTPS 代理能力）。</div>
      </div>
    </el-col>

    <el-col :span="10">
      <div class="panel">
        <div class="card-title"><span>验证参数</span></div>
        <el-form label-width="120px">
          <el-form-item label="连接超时">
            <el-input-number v-model="verify.dialTimeout" :min="500" :max="20000" :step="500" /> ms
          </el-form-item>
          <el-form-item label="总超时">
            <el-input-number v-model="verify.totalTimeout" :min="1000" :max="60000" :step="500" /> ms
          </el-form-item>
          <el-form-item label="响应体上限">
            <el-input-number v-model="verify.maxBodySize" :min="4096" :max="1048576" :step="4096" /> 字节
          </el-form-item>
          <el-form-item>
            <template #label><el-tooltip content="验证器对「回显请求头」站点尝试 HTTP/HTTPS 的总次数" placement="top"><span>回显尝试次数</span></el-tooltip></template>
            <el-input-number v-model="verify.maxHeaderTries" :min="1" :max="10" />
          </el-form-item>
          <el-form-item>
            <template #label><el-tooltip content="「仅回显IP」站点的尝试次数，用于兜底判定出口 IP" placement="top"><span>IP站点尝试</span></el-tooltip></template>
            <el-input-number v-model="verify.maxIpTries" :min="0" :max="10" />
          </el-form-item>
          <el-form-item>
            <template #label><el-tooltip content="CONNECT 目标（HTTPS 代理能力）的尝试次数" placement="top"><span>HTTPS尝试</span></el-tooltip></template>
            <el-input-number v-model="verify.maxHttpsTries" :min="0" :max="10" />
          </el-form-item>
          <el-form-item label="UA">
            <el-input v-model="verify.userAgent" />
          </el-form-item>
        </el-form>
      </div>

      <div class="panel mt">
        <div class="card-title"><span>本机公网 IP</span><el-button link type="primary" size="small" @click="detect">重新检测</el-button></div>
        <el-alert v-if="publicIp" :title="publicIp" type="success" show-icon :closable="false" description="用于识别透明代理（回显的 X-Forwarded-For 中包含该 IP 即判定为透明）" />
        <el-alert v-else type="warning" show-icon :closable="false" title="未能获取本机公网 IP（网络受限），透明代理将退化为「普通匿名」判定" />
      </div>

      <div class="btns">
        <el-button type="primary" size="large" @click="save">保存配置</el-button>
        <el-button size="large" plain @click="load">重新载入</el-button>
      </div>
    </el-col>
  </el-row>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { detectPublicIP, getConfig, saveConfig } from '../api'

const defaultEcho = [
  { url: 'http://192.187.105.21:8849/get', kind: 'headers', note: '自建回显（同端口支持 HTTP+HTTPS，自动判定匿名等级）' },
  { url: 'http://api.ipify.org?format=json', kind: 'ip', note: '仅回显出口 IP（连通兜底）' },
  { url: 'https://api.ipify.org?format=json', kind: 'ip', note: 'HTTPS 出口 IP（连通兜底）' },
  { url: 'http://ip-api.com/json/', kind: 'ip', note: '出口 IP 与归属地' },
  { url: 'http://myip.ipip.net', kind: 'ip', note: '文本出口 IP' },
  { url: 'https://www.taobao.com/help/getip.php', kind: 'ip', note: '文本出口 IP' },
  { url: 'http://www.baidu.com', kind: 'connect', note: '连通性兜底' },
  { url: 'https://www.baidu.com', kind: 'connect', note: 'HTTPS 连通性兜底' }
]

const defaultTargets = [
  'https://api.ipify.org?format=json',
  'https://www.baidu.com',
  'https://www.qq.com'
]

const verify = reactive({
  dialTimeout: 4000,
  totalTimeout: 8000,
  maxBodySize: 65536,
  userAgent: '',
  publicIp: '',
  echoServers: JSON.parse(JSON.stringify(defaultEcho)),
  httpsTargets: [...defaultTargets],
  maxHeaderTries: 3,
  maxIpTries: 2,
  maxHttpsTries: 2
})

const publicIp = ref('')

function addEcho() {
  verify.echoServers.push({ url: '', kind: 'headers', note: '' })
}

function resetEcho() {
  verify.echoServers = JSON.parse(JSON.stringify(defaultEcho))
  verify.httpsTargets = [...defaultTargets]
}

async function load() {
  try {
    const cfg = await getConfig()
    if (cfg?.verify) {
      const v = cfg.verify
      verify.dialTimeout = num(v.dialTimeout, verify.dialTimeout)
      verify.totalTimeout = num(v.totalTimeout, verify.totalTimeout)
      verify.maxBodySize = v.maxBodySize || verify.maxBodySize
      verify.userAgent = v.userAgent || verify.userAgent
      verify.maxHeaderTries = v.maxHeaderTries || verify.maxHeaderTries
      verify.maxIpTries = v.maxIpTries ?? verify.maxIpTries
      verify.maxHttpsTries = v.maxHttpsTries ?? verify.maxHttpsTries
      verify.echoServers = v.echoServers?.length ? v.echoServers : JSON.parse(JSON.stringify(defaultEcho))
      verify.httpsTargets = v.httpsTargets?.length ? v.httpsTargets : [...defaultTargets]
      verify.publicIp = v.publicIp || ''
    }
  } catch (e) {
    ElMessage.error(e.message)
  }
  publicIp.value = verify.publicIp || ''
  if (!publicIp.value) {
    try {
      publicIp.value = (await detectPublicIP()) || ''
      verify.publicIp = publicIp.value
    } catch (e) {
      /* 检测失败时保持空，用户可手动重新检测 */
    }
  }
}

function num(v, def) {
  const n = Number(v)
  if (!v) return def
  // 后端 JSON 里 time.Duration 是纳秒
  return Math.round(n > 1000000 ? n / 1e6 : n)
}

async function save() {
  try {
    verify.publicIp = publicIp.value || verify.publicIp || ''
    await saveConfig({ verify: verify })
    ElMessage.success('配置已保存并即时生效')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function detect() {
  try {
    publicIp.value = (await detectPublicIP()) || ''
    verify.publicIp = publicIp.value
    ElMessage.success(publicIp.value ? '检测成功' : '未能检测到公网 IP')
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

.mt {
  margin-top: 14px;
}

.tip {
  margin-top: 8px;
  font-size: 12px;
  color: #8a94a6;
  line-height: 1.6;
}

.btns {
  margin-top: 14px;
  display: flex;
  gap: 10px;
}
</style>

import axios from 'axios'

const http = axios.create({
  baseURL: '/api',
  timeout: 30000,
  // 数组参数用重复键（country=中国&province=四川）。axios 默认序列化成 country[]=中国，
  // Go 后端读不到，会导致「选了省却按全国/全球扫」。
  paramsSerializer: {
    serialize: (params) => {
      const sp = new URLSearchParams()
      Object.entries(params || {}).forEach(([k, val]) => {
        if (val === undefined || val === null || val === '') return
        if (Array.isArray(val)) {
          val.forEach((v) => {
            if (v !== undefined && v !== null && v !== '') sp.append(k, v)
          })
        } else {
          sp.append(k, val)
        }
      })
      return sp.toString()
    }
  }
})

// 请求拦截：自动携带登录令牌
http.interceptors.request.use((config) => {
  const t = localStorage.getItem('ps.token')
  if (t) config.headers.Authorization = `Bearer ${t}`
  return config
})

// 未授权事件名（App.vue 监听后跳转登录）
export const UNAUTHORIZED_EVENT = 'ps:unauthorized'

http.interceptors.response.use(
  (res) => {
    const data = res.data
    if (data && typeof data === 'object' && 'code' in data) {
      if (data.code === 0) return data.data
      return Promise.reject(new Error(data.message || '请求失败'))
    }
    return data
  },
  (err) => {
    const status = err?.response?.status
    const msg = err?.response?.data?.message || err.message || '网络异常'
    if (status === 401) {
      // 清除本地凭据并通知前端跳转登录（登录页自身的 401 忽略即可）
      localStorage.removeItem('ps.token')
      if (location.hash !== '#/login') {
        window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT))
      }
    }
    return Promise.reject(new Error(msg))
  }
)

export default http

// ---------- 鉴权 ----------

export const loginUser = (data) => http.post('/login', data)
export const logoutUser = () => http.post('/logout')
export const getMe = () => http.get('/me')
export const changePassword = (data) => http.post('/admin/password', data)

// ---------- 接口封装 ----------

export const getHealth = () => http.get('/health')

export const getStats = () => http.get('/stats')

export const getRegions = () => http.get('/regions')

export const getConfig = () => http.get('/config')

export const saveConfig = (data) => http.post('/config', data)

export const startScan = (cfg) => http.post('/scan/start', cfg)
export const enqueueScan = (cfg) => http.post('/scan/enqueue', cfg)
export const stopScan = () => http.post('/scan/stop')
export const getScanQueue = () => http.get('/scan/queue')
export const removeScanTask = (id) => http.delete(`/scan/queue/${id}`)
export const deleteTask = (id) => http.delete(`/tasks/${id}`)

export const getProgress = () => http.get('/progress')

export const estimateSegments = (params) =>
  http.get('/scan/estimate', { params: { ...params, _: Date.now() } })

export const listTasks = () => http.get('/tasks')

export const clearTasks = () => http.delete('/tasks')

export const getProxies = (params) => http.get('/proxies', { params })

export const deleteProxy = (id) => http.delete(`/proxies/${id}`)

export const deleteProxies = (ids) => http.post('/proxies/delete', { ids })

export const clearProxies = (country) => http.delete('/proxies', { data: { country } })

export const verifyProxies = (ids) => http.post('/proxies/verify', { ids })

export const verifyProxy = (id) => http.post(`/proxies/verify/${id}`)

export const detectPublicIP = () => http.get('/public-ip')

// ---------- 定时任务 ----------

export const listSchedules = () => http.get('/schedules')

export const saveSchedule = (data) => http.post('/schedules', data)

export const deleteSchedule = (id) => http.delete(`/schedules/${id}`)

export const runSchedule = (id) => http.post(`/schedules/${id}/run`)

export const toggleSchedule = (id, enabled) => http.post(`/schedules/${id}/toggle`, { enabled })

export const exportURL = (params) => {
  const qs = new URLSearchParams()
  Object.keys(params || {}).forEach((k) => {
    if (params[k] !== '' && params[k] !== undefined && params[k] !== null) qs.append(k, params[k])
  })
  return `/api/proxies/export?${qs.toString()}`
}

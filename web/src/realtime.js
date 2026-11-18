import { reactive } from 'vue'

// 全局实时状态：由 SSE(/api/events) 驱动
export const rt = reactive({
  connected: false,
  progress: {
    running: false,
    type: '',
    name: '',
    taskId: 0,
    total: 0,
    scanned: 0,
    found: 0,
    failed: 0,
    deleted: 0,
    elapsedMs: 0,
    ratePerSec: 0,
    message: ''
  },
  logs: [],
  latest: [], // 最近入库的代理
  removedIds: [],
  queue: [] // 排队中的扫描任务
})

const listeners = { progress: [], found: [], removed: [], updated: [], done: [], log: [], queue: [] }

function emit(type, payload) {
  ;(listeners[type] || []).forEach((fn) => {
    try {
      fn(payload)
    } catch (e) {
      console.error(e)
    }
  })
}

export function on(type, fn) {
  if (!listeners[type]) listeners[type] = []
  listeners[type].push(fn)
  return () => {
    listeners[type] = listeners[type].filter((f) => f !== fn)
  }
}

let es = null

export function connect() {
  if (es) return es
  let url = '/api/events'
  const t = localStorage.getItem('ps.token')
  if (t) url += '?token=' + encodeURIComponent(t)
  es = new EventSource(url)
  es.onopen = () => {
    rt.connected = true
  }
  es.onerror = () => {
    rt.connected = false
  }
  const types = ['hello', 'progress', 'log', 'found', 'updated', 'removed', 'done', 'queue']
  types.forEach((type) => {
    es.addEventListener(type, (ev) => {
      rt.connected = true
      let data = null
      try {
        data = JSON.parse(ev.data)
      } catch (e) {
        data = null
      }
      if (type === 'hello') {
        if (data?.progress) applyProgress(data.progress)
        return
      }
      if (type === 'progress') {
        applyProgress(data)
        return
      }
      if (type === 'log') {
        rt.logs.unshift({ time: new Date(), ...data })
        if (rt.logs.length > 200) rt.logs.pop()
        emit('log', data)
        return
      }
      if (type === 'found') {
        rt.latest.unshift(data)
        if (rt.latest.length > 60) rt.latest.pop()
        emit('found', data)
        return
      }
      if (type === 'updated') {
        emit('updated', data)
        return
      }
      if (type === 'removed') {
      	rt.removedIds.push(data?.id)
      	if (rt.removedIds.length > 500) rt.removedIds.shift()
      	emit('removed', data)
      	return
      }
      if (type === 'queue') {
      	if (Array.isArray(data)) rt.queue = data
      	emit('queue', data)
      	return
      }
      if (type === 'done') {
        // 任务结束立即清空进度，避免上次任务的数据残留在进度条上
        Object.assign(rt.progress, {
          running: false,
          type: '',
          name: '',
          taskId: 0,
          total: 0,
          scanned: 0,
          found: 0,
          failed: 0,
          deleted: 0,
          elapsedMs: 0,
          ratePerSec: 0,
          message: '',
          verified: 0,
          rejectAnon: 0,
          rejectUnknown: 0,
          rejectDedup: 0,
          rejectLatency: 0,
          rejectHttps: 0
        })
        emit('done', data)
      }
    })
  })
  return es
}

function applyProgress(p) {
  Object.assign(rt.progress, p || {})
  emit('progress', rt.progress)
}

export function disconnect() {
  if (es) {
    es.close()
    es = null
  }
}

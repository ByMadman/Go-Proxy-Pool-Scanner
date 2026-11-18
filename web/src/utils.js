export const LEVEL_TEXT = ['未知', '透明', '普通匿名', '高匿名']
export const LEVEL_TYPE = ['info', 'danger', 'warning', 'success']

export function levelText(level) {
  return LEVEL_TEXT[level] || '未知'
}

export function levelType(level) {
  return LEVEL_TYPE[level] || 'info'
}

export function protocolOf(row) {
  if (row.httpOk && row.httpsOk) return 'HTTP/HTTPS'
  if (row.httpsOk) return 'HTTPS'
  return 'HTTP'
}

export function fmtDateTime(v) {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return String(v)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

// 亿 / 万 为单位的可读数字
export function humanCount(n) {
  const v = Number(n || 0)
  if (v >= 1e8) return (v / 1e8).toFixed(2) + ' 亿'
  if (v >= 1e4) return (v / 1e4).toFixed(2) + ' 万'
  return String(v)
}

export const COMMON_PORTS = [
  80, 81, 808, 8080, 8081, 8088, 8888, 3128, 8000, 8001, 8880,
  1080, 1081, 10809, 20171, 53281, 7890, 7891, 2080, 10800,
  9090, 9797, 10000, 65501
]

export const PORT_PRESETS = [
  { label: '常用 HTTP 代理端口', ports: [80, 8080, 8081, 3128, 8888, 8000, 9797] },
  { label: '常用 SOCKS/混合端口', ports: [1080, 1081, 10809, 20171, 7890, 7891, 2080] },
  { label: '全端口快扫 24 个', ports: COMMON_PORTS }
]

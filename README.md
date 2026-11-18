# ProxyScanner

带 Web 控制台的 HTTP/HTTPS 高匿名代理扫描器。按国家/地区自动提取 IP 段 → 连通性探测 → 匿名度验证（透明/匿名/高匿）→ 地理归属（ip2region 离线库），并对外提供**鉴权保护的代理池提取 API**。

---

## 1. 功能特性

- 代理扫描：按 CIDR / 国家 / 端口范围批量扫描并验证
- 匿名度识别：透明、匿名、高匿（基于回显 IP 与 `X-Forwarded-For` 头）
- 地理归属：ip2region 离线库，按国家/省份统计
- Web 控制台：仪表盘、扫描任务、代理池、任务记录、定时任务、参数配置
- **后台登录鉴权**：所有管理操作需登录（默认账号 `admin / admin123`）
- **提取令牌（Token）**：管理员可创建带「过期时间 + 单次提取数量 + 累计额度」的令牌，外部凭令牌提取代理，过期或额度耗尽即拒绝

---

## 2. 编译与运行

### 2.1 编译

```bash
# 后端
go build -o proxyscanner.exe .

# 前端（可选，已构建产物在 web/dist）
cd web && npm install && npm run build
```

### 2.2 运行

```bash
proxyscanner.exe -addr :8848 -db proxy.db -web web/dist
```

启动后访问 `http://<host>:8848` 打开 Web 控制台。

### 2.3 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-addr` | `:8848` | Web 控制台监听地址 |
| `-db` | `proxy.db` | SQLite 数据库文件路径 |
| `-xdb` | `data/ip2region.xdb` | ip2region xdb 数据文件路径（缺失则启动失败） |
| `-web` | `web/dist` | 前端静态资源目录 |
| `-publicip` | `true` | 启动时检测本机公网 IP（用于识别透明代理） |
| `-admin` | `admin` | 默认管理员用户名（仅当库中无账号时用于初始化） |
| `-admin-pass` | `admin123` | 默认管理员口令（仅当库中无账号时用于初始化） |
| `-extract-key` | 空 | 代理池提取接口密钥；设置后外部可用 `?apikey=` 提取，否则需登录令牌 |

> **安全提示**：首次启动会自动播种默认管理员 `admin / admin123`，请登录后在「右上角 → 修改密码」立即修改，或通过 `-admin` / `-admin-pass` 指定强口令启动。

---

## 3. 鉴权模型

系统区分两类凭据：

| 凭据 | 用途 | 生命周期 |
|------|------|----------|
| **会话令牌（Session）** | 管理员登录后操作 Web 控制台 | 30 天 |
| **提取令牌（Token）** | 外部程序调用提取 API 拉取代理 | 由管理员设定过期时间 |

除 `/api/health`、登录接口、提取接口外，**所有 `/api/*` 均要求登录**，未携带有效会话令牌返回 `401`。

### 3.1 登录

```bash
curl -X POST http://<host>:8848/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
```

响应：

```json
{ "code": 0, "data": { "token": "<session_token>", "username": "admin", "expiresAt": "2026-11-20T10:00:00Z" } }
```

后续请求在 `Authorization` 头携带（Cookie `session` 也会自动下发）：

```bash
curl http://<host>:8848/api/proxies -H 'Authorization: Bearer <session_token>'
```

### 3.2 当前用户 / 登出 / 改密

```bash
GET  /api/me                  # 当前登录用户 { username }
POST /api/logout              # 注销当前会话
POST /api/admin/password      # 修改密码 { oldPassword, newPassword }
```

---

## 4. 提取令牌管理

令牌用于给**外部调用方**发放「可按量提取代理」的凭证，由管理员在 Web 控制台「提取令牌」页面或 API 创建。

### 4.1 令牌字段

| 字段 | 说明 |
|------|------|
| `name` | 备注名（如「给客户A」） |
| `expiresAt` | 过期时间，过期后提取被拒 |
| `count` | **单次提取数量**：每次调用最多返回的代理条数 |
| `maxTotal` | **累计额度**：令牌生命周期内最多可提取的代理总数（`0` = 不限） |
| `used` | 已累计提取数量（只读） |

### 4.2 创建令牌

```bash
curl -X POST http://<host>:8848/api/tokens \
  -H 'Authorization: Bearer <session_token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"客户A","expiresAt":"2026-12-31 23:59:59","count":200,"maxTotal":1000}'
```

响应（令牌值**仅此一次**完整返回，请妥善保存）：

```json
{ "code": 0, "data": { "token": "px_xxx...", "expiresAt": "2026-12-31T23:59:59Z", "count": 200, "maxTotal": 1000 } }
```

### 4.3 令牌管理接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/tokens` | 列出全部令牌（含 `used` / `enabled`） |
| `POST` | `/api/tokens` | 创建令牌（见上） |
| `DELETE` | `/api/tokens/{id}` | 删除（吊销）令牌 |
| `POST` | `/api/tokens/{id}/toggle` | 启停令牌 `{ enabled: true\|false }` |

---

## 5. 代理提取 API

### 5.1 令牌提取（对外，推荐）

```bash
GET /api/proxies/extract?token=<提取令牌>&format=txt&https=1&country=CN&anon=3
```

**参数**

| 参数 | 说明 |
|------|------|
| `token` | 提取令牌（必填） |
| `format` | `txt`（默认，每行 `ip:port`）或 `json`（代理对象数组） |
| `https` | `1` 仅返回 HTTPS 代理 |
| `country` | 国家过滤，如 `CN`（与 `countryCode` 兼容） |
| `province` | 省过滤（如 `广东省`）；**为空则不做区分** |
| `city` | 市过滤（如 `深圳市`）；**为空则不做区分** |
| `district` | 区过滤（如 `南山区`）；**为空则不做区分** |
| `protocol` | 协议过滤 `http` / `https` |
| `anon` / `minLevel` | 最低匿名等级（1 匿名 / 2 高匿 / 3 高匿及以上） |
| `maxLatency` | 最大延迟（毫秒） |
| `size` | 本次上限（取小：令牌 `count` / `size` / 剩余累计额度） |

> **地理精度说明**：内置 ip2region 库仅解析到「市」级，因此 `district`（区）列已建好并支持过滤，但本地库数据通常为空——过滤 `district` 在有区数据的地理源下才生效；`country`/`province`/`city` 可正常过滤。所有地理参数留空即表示「不区分，直接按数量提取」。

导出接口（`/api/proxies/export`）同样支持 `country` / `province` / `city` / `district` 过滤参数。

**返回规则**

- 返回数量 = `min(令牌单次数量 count, 请求 size, 剩余累计额度)`
- 每成功提取一次，`used` 累加；耗尽后返回 `401 令牌提取额度已用尽`
- 令牌过期 / 停用 / 无效 → `401`
- `txt` 在响应头 `X-Proxy-Count` 返回本次条数

**示例**

```bash
# 文本格式（每行 ip:port）
curl "http://<host>:8848/api/proxies/extract?token=px_xxx&format=txt&https=1"

# JSON 格式
curl "http://<host>:8848/api/proxies/extract?token=px_xxx&format=json&country=CN&minLevel=2"
```

### 5.2 管理员导出（会话令牌 / 提取密钥）

```bash
GET /api/proxies/export?format=txt|json|csv&country=&protocol=&https=1&anon=&minLevel=&maxLatency=
```

- 需登录会话令牌，或启动时配置了 `-extract-key` 并携带 `?apikey=<key>`
- 返回代理池全量（按延迟升序），无单次/额度限制

---

## 6. 其他主要接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 健康检查（无需鉴权） |
| `GET` | `/api/stats` | 运行概览统计 |
| `GET` | `/api/regions` | 国家/地区代理分布 |
| `GET` | `/api/proxies` | 分页查询代理池 `{ page, size, country, protocol, minLevel, ... }` |
| `POST` | `/api/scan/start` | 启动扫描任务 |
| `POST` | `/api/scan/stop` | 停止扫描 |
| `GET` | `/api/tasks` | 任务记录 |
| `POST` | `/api/proxies/verify` | 触发代理验证 |
| `GET` | `/api/schedules` | 定时任务列表 |
| `POST` | `/api/config` | 保存验证/扫描参数 |
| `GET` | `/api/events` | SSE 实时事件流（带 `?token=` 可鉴权） |

---

## 7. 目录结构

```
.
├── main.go                 # 入口、命令行参数、初始化
├── internal/
│   ├── store/              # SQLite 存储（users/sessions/tokens/proxies/...）
│   ├── api/                # HTTP 接口与鉴权中间件
│   ├── scanner/            # 扫描与验证核心
│   ├── proxy/              # 代理验证器（匿名度识别）
│   ├── ip2region/          # 地理归属
│   ├── scheduler/          # 定时任务
│   └── event/              # SSE 实时事件
├── cmd/selftest/           # 本地联调回显/代理服务（-serve）
└── web/                    # Vue3 + Element Plus 前端
```

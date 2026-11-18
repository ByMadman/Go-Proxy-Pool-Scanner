// Package store 负责 SQLite 持久化：代理池、扫描任务、运行期配置。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// 匿名等级。
const (
	AnonymityUnknown     = 0 // 未判定（回显服务不可用）
	AnonymityTransparent = 1 // 透明：泄露真实 IP
	AnonymityAnonymous   = 2 // 普通匿名：带 Via/Proxy 头
	AnonymityElite       = 3 // 高匿名：无任何代理痕迹
)

// AnonymityText 返回匿名等级的可读名称。
func AnonymityText(level int) string {
	switch level {
	case AnonymityTransparent:
		return "透明"
	case AnonymityAnonymous:
		return "普通匿名"
	case AnonymityElite:
		return "高匿名"
	default:
		return "未知"
	}
}

// Proxy 代理池中的一条记录。
type Proxy struct {
	ID           int64     `json:"id"`
	IP           string    `json:"ip"`
	Port         int       `json:"port"`
	HTTPOK       bool      `json:"httpOk"`
	HTTPSOK      bool      `json:"httpsOk"`
	Anonymity    int       `json:"anonymity"`
	Latency      int       `json:"latency"`
	ExitIP       string    `json:"exitIp"`
	Country      string    `json:"country"`
	CountryCode  string    `json:"countryCode"`
	Province     string    `json:"province"`
	City         string    `json:"city"`
	District     string    `json:"district"`
	ISP          string    `json:"isp"`
	Region       string    `json:"region"`
	Source       string    `json:"source"`
	SuccessCount int       `json:"successCount"`
	FailCount    int       `json:"failCount"`
	CreatedAt    time.Time `json:"createdAt"`
	VerifiedAt   time.Time `json:"verifiedAt"`
}

// Addr 返回 ip:port。
func (p Proxy) Addr() string { return fmt.Sprintf("%s:%d", p.IP, p.Port) }

// Protocol 返回支持的协议描述。
func (p Proxy) Protocol() string {
	switch {
	case p.HTTPOK && p.HTTPSOK:
		return "HTTP/HTTPS"
	case p.HTTPSOK:
		return "HTTPS"
	default:
		return "HTTP"
	}
}

// AnonymityName 匿名等级名称。
func (p Proxy) AnonymityName() string { return AnonymityText(p.Anonymity) }

// Task 一次扫描/验证任务。
type Task struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"` // scan / verify
	Status     string    `json:"status"`
	Params     string    `json:"params"`
	Total      int64     `json:"total"`
	Scanned    int64     `json:"scanned"`
	Found      int64     `json:"found"`
	Success    int64     `json:"success"`
	Failed     int64     `json:"failed"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Message    string    `json:"message"`
}

// Store 数据库句柄。
type Store struct {
	db  *sql.DB
	mu  sync.Mutex
	dsn string
}

// Open 打开（必要时初始化）SQLite 数据库。
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, dsn: dsn}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

// migrate 为已存在的旧库补充新增列（district），新建库由 initSchema 建表已含。
func (s *Store) migrate() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM pragma_table_info('proxies') WHERE name='district'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.db.Exec(`ALTER TABLE proxies ADD COLUMN district TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	// 历史数据曾把 time.Time 原样写库（"2026-10-21 10:23:54.9 +0800 CST m=+..."），
	// 带单调时钟后缀，SQLite 的 date() 无法解析，导致「今日新增」恒为 0。
	// 这里统一裁剪成 "YYYY-MM-DD HH:MM:SS"，反复执行也安全。
	if _, err := s.db.Exec(`UPDATE proxies
		SET created_at = substr(created_at,1,19)
		WHERE created_at LIKE '%m=+%'`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE proxies
		SET verified_at = substr(verified_at,1,19)
		WHERE verified_at LIKE '%m=+%'`); err != nil {
		return err
	}
	return nil
}

// DB 返回原始句柄（仅供内部使用）。
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) initSchema() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS proxies (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			ip            TEXT    NOT NULL,
			port          INTEGER NOT NULL,
			http_ok       INTEGER NOT NULL DEFAULT 0,
			https_ok      INTEGER NOT NULL DEFAULT 0,
			anonymity     INTEGER NOT NULL DEFAULT 0,
			latency       INTEGER NOT NULL DEFAULT 0,
			exit_ip       TEXT    NOT NULL DEFAULT '',
			country       TEXT    NOT NULL DEFAULT '',
			country_code  TEXT    NOT NULL DEFAULT '',
			province      TEXT    NOT NULL DEFAULT '',
			city          TEXT    NOT NULL DEFAULT '',
			isp           TEXT    NOT NULL DEFAULT '',
			region        TEXT    NOT NULL DEFAULT '',
			source        TEXT    NOT NULL DEFAULT '',
			success_count INTEGER NOT NULL DEFAULT 1,
			fail_count    INTEGER NOT NULL DEFAULT 0,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			verified_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_addr ON proxies(ip, port)`,
		`CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies(latency)`,
		`CREATE INDEX IF NOT EXISTS idx_proxies_verified ON proxies(verified_at)`,
		`CREATE INDEX IF NOT EXISTS idx_proxies_country ON proxies(country)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT NOT NULL DEFAULT '',
			type        TEXT NOT NULL DEFAULT 'scan',
			status      TEXT NOT NULL DEFAULT 'running',
			params      TEXT NOT NULL DEFAULT '',
			total       INTEGER NOT NULL DEFAULT 0,
			scanned     INTEGER NOT NULL DEFAULT 0,
			found       INTEGER NOT NULL DEFAULT 0,
			success     INTEGER NOT NULL DEFAULT 0,
			failed      INTEGER NOT NULL DEFAULT 0,
			started_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			finished_at DATETIME,
			message     TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS schedules (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			name         TEXT    NOT NULL DEFAULT '',
			enabled      INTEGER NOT NULL DEFAULT 1,
			kind         TEXT    NOT NULL DEFAULT 'scan',
			repeat       TEXT    NOT NULL DEFAULT 'daily',
			run_time     TEXT    NOT NULL DEFAULT '03:00',
			interval_min INTEGER NOT NULL DEFAULT 60,
			weekday      INTEGER NOT NULL DEFAULT 1,
			params       TEXT    NOT NULL DEFAULT '',
			last_run_at  DATETIME,
			next_run_at  DATETIME,
			run_count    INTEGER NOT NULL DEFAULT 0,
			last_result  TEXT    NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			username      TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token      TEXT PRIMARY KEY,
			username   TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       TEXT NOT NULL DEFAULT '',
			token      TEXT NOT NULL UNIQUE,
			creator    TEXT NOT NULL DEFAULT '',
			expires_at DATETIME NOT NULL,
			count      INTEGER NOT NULL DEFAULT 100,
			max_total  INTEGER NOT NULL DEFAULT 0,
			used       INTEGER NOT NULL DEFAULT 0,
			enabled    INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, sql_ := range stmts {
		if _, err := s.db.Exec(sql_); err != nil {
			return fmt.Errorf("初始化表结构失败: %w", err)
		}
	}
	if err := s.migrate(); err != nil {
		return err
	}
	return nil
}

// sqlTimeLayout 是写入 SQLite 的时间格式，须与 SQLite 内建时间函数兼容（本地时间）。
const sqlTimeLayout = "2006-01-02 15:04:05"

// SaveProxy 写入或更新一条代理记录（按 ip:port 唯一）。
func (s *Store) SaveProxy(p *Proxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	const q = `INSERT INTO proxies
		(ip,port,http_ok,https_ok,anonymity,latency,exit_ip,country,country_code,province,city,district,isp,region,source,success_count,fail_count,created_at,verified_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip,port) DO UPDATE SET
			http_ok=excluded.http_ok,
			https_ok=excluded.https_ok,
			anonymity=excluded.anonymity,
			latency=excluded.latency,
			exit_ip=excluded.exit_ip,
			country=excluded.country,
			country_code=excluded.country_code,
			province=excluded.province,
			city=excluded.city,
			district=excluded.district,
			isp=excluded.isp,
			region=excluded.region,
			source=excluded.source,
			success_count=proxies.success_count+1,
			fail_count=0,
			verified_at=excluded.verified_at`
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.VerifiedAt.IsZero() {
		p.VerifiedAt = now
	}
	if p.SuccessCount == 0 {
		p.SuccessCount = 1
	}
	// 统一以 "YYYY-MM-DD HH:MM:SS"（本地时间）写库：既能被 SQLite 的 date() 解析，
	// 也避免驱动把 time.Time 转成带单调时钟后缀的字符串。
	res, err := s.db.Exec(q, p.IP, p.Port, boolInt(p.HTTPOK), boolInt(p.HTTPSOK), p.Anonymity, p.Latency,
		p.ExitIP, p.Country, p.CountryCode, p.Province, p.City, p.District, p.ISP, p.Region, p.Source,
		p.SuccessCount, p.FailCount, p.CreatedAt.Format(sqlTimeLayout), p.VerifiedAt.Format(sqlTimeLayout))
	if err != nil {
		return err
	}
	if p.ID == 0 {
		if id, err := res.LastInsertId(); err == nil {
			p.ID = id
		}
	}
	return nil
}

// DeleteProxy 删除指定代理（验证失败时调用）。
func (s *Store) DeleteProxy(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM proxies WHERE id=?`, id)
	return err
}

// DeleteProxies 批量删除。
func (s *Store) DeleteProxies(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	res, err := s.db.Exec(`DELETE FROM proxies WHERE id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ClearProxies 清空代理池（可按国家过滤，空表示全部）。
func (s *Store) ClearProxies(country string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var (
		res sql.Result
		err error
	)
	if country == "" {
		res, err = s.db.Exec(`DELETE FROM proxies`)
	} else {
		res, err = s.db.Exec(`DELETE FROM proxies WHERE country=? OR country_code=?`, country, country)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ProxyQuery 列表查询条件。
type ProxyQuery struct {
	Page      int
	Size      int
	Keyword   string // ip / 归属地 / 出口 IP 模糊匹配
	Country   string
	Countries []string // 非空时按别名集合过滤（country / country_code 任一命中）
	Province  string   // 省
	Provinces []string // 非空时按省份别名集合过滤
	City      string // 市
	District  string // 区
	Protocol  string // http / https
	MinLevel  int    // 匿名等级下限（0 不限制）
	Level     int    // 精确匿名等级（0=未知）
	LevelSet  bool   // 是否启用精确匹配；为 true 时 Level 即使是 0 也生效
	MaxLevel  int
	MaxLatency int   // 毫秒上限，0 不限
	SortBy    string // latency / verified_at / id
	Order     string // asc / desc
}

// proxyCols 代理表查询列清单。
const proxyCols = `SELECT id,ip,port,http_ok,https_ok,anonymity,latency,exit_ip,country,country_code,province,city,district,isp,region,source,success_count,fail_count,created_at,verified_at `

// proxyOrder 由查询条件生成排序子句。
func proxyOrder(q ProxyQuery) string {
	sortBy := map[string]string{
		"latency":     "latency",
		"verified_at": "verified_at",
		"created_at":  "created_at",
		"id":          "id",
	}[strings.ToLower(q.SortBy)]
	if sortBy == "" {
		sortBy = "verified_at"
	}
	order := "DESC"
	if strings.EqualFold(q.Order, "asc") {
		order = "ASC"
	}
	// 追加 id 作为稳定 tiebreaker：延迟/验证时间大量并列时，若排序不确定，
	// LIMIT/OFFSET 翻页会出现重复行或漏行。
	return sortBy + " " + order + ", id DESC"
}

// proxyWhere 由查询条件拼装 WHERE 子句与参数。
func proxyWhere(q ProxyQuery) (string, []any) {
	where := []string{"1=1"}
	args := []any{}
	if k := strings.TrimSpace(q.Keyword); k != "" {
		where = append(where, `(ip LIKE ? OR exit_ip LIKE ? OR region LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ? OR district LIKE ?)`)
		for i := 0; i < 7; i++ {
			args = append(args, "%"+k+"%")
		}
	}
	if len(q.Countries) > 0 {
		// 库里存的是 ip2region 英文原文（如 United States），而界面传的是中文名，
		// 因此用别名集合做 IN 匹配，避免「选了国家却没结果」。
		ph := strings.TrimSuffix(strings.Repeat("?,", len(q.Countries)), ",")
		where = append(where, `(country IN (`+ph+`) OR country_code IN (`+ph+`))`)
		for _, v := range q.Countries {
			args = append(args, v)
		}
		for _, v := range q.Countries {
			args = append(args, v)
		}
	} else if c := strings.TrimSpace(q.Country); c != "" {
		where = append(where, `(country=? OR country_code=?)`)
		args = append(args, c, c)
	}
	if len(q.Provinces) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(q.Provinces)), ",")
		where = append(where, `province IN (`+ph+`)`)
		for _, v := range q.Provinces {
			args = append(args, v)
		}
	} else if c := strings.TrimSpace(q.Province); c != "" {
		where = append(where, `province=?`)
		args = append(args, c)
	}
	if c := strings.TrimSpace(q.City); c != "" {
		where = append(where, `city=?`)
		args = append(args, c)
	}
	if c := strings.TrimSpace(q.District); c != "" {
		where = append(where, `district=?`)
		args = append(args, c)
	}
	switch strings.ToLower(q.Protocol) {
	case "http":
		where = append(where, `http_ok=1`)
	case "https":
		where = append(where, `https_ok=1`)
	}
	if q.LevelSet {
		// 精确匹配：选「未知」(0) 时也要真正过滤，而不是当成"不限制"。
		where = append(where, `anonymity=?`)
		args = append(args, q.Level)
	} else if q.MinLevel > 0 {
		where = append(where, `anonymity>=?`)
		args = append(args, q.MinLevel)
	}
	if q.MaxLevel > 0 {
		where = append(where, `anonymity<=?`)
		args = append(args, q.MaxLevel)
	}
	if q.MaxLatency > 0 {
		where = append(where, `latency>0 AND latency<=?`)
		args = append(args, q.MaxLatency)
	}
	return strings.Join(where, " AND "), args
}

// ListProxies 分页查询代理池。
func (s *Store) ListProxies(q ProxyQuery) ([]Proxy, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cond, args := proxyWhere(q)

	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM proxies WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if q.Page < 1 {
		q.Page = 1
	}
	if q.Size <= 0 || q.Size > 500 {
		q.Size = 20
	}
	offset := (q.Page - 1) * q.Size

	rows, err := s.db.Query(proxyCols+`
		FROM proxies WHERE `+cond+` ORDER BY `+proxyOrder(q)+` LIMIT ? OFFSET ?`, append(args, q.Size, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list, _, err := scanProxies(rows)
	// 注意：total 必须用前面的 COUNT(1) 结果，scanProxies 返回的是「本页行数」，
	// 直接把它当总数会导致分页永远只显示一页（共 20 条 / 1 页）。
	return list, total, err
}

// ListProxiesAll 不分页返回符合条件的所有代理（供导出与「单次不限量」的令牌提取使用）。
// limit<=0 时按 100000 兜底，避免误传导致超大结果。
func (s *Store) ListProxiesAll(q ProxyQuery, limit int) ([]Proxy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 1000000 {
		limit = 100000
	}
	cond, args := proxyWhere(q)
	rows, err := s.db.Query(proxyCols+`
		FROM proxies WHERE `+cond+` ORDER BY `+proxyOrder(q)+` LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, _, err := scanProxies(rows)
	return list, err
}

// AllProxies 返回全部代理（用于一键验证、导出）。
func (s *Store) AllProxies() ([]Proxy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id,ip,port,http_ok,https_ok,anonymity,latency,exit_ip,country,country_code,province,city,district,isp,region,source,success_count,fail_count,created_at,verified_at FROM proxies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, _, err := scanProxies(rows)
	return list, err
}

// ProxyByID 按主键查询。
func (s *Store) ProxyByID(id int64) (*Proxy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`SELECT id,ip,port,http_ok,https_ok,anonymity,latency,exit_ip,country,country_code,province,city,district,isp,region,source,success_count,fail_count,created_at,verified_at FROM proxies WHERE id=?`, id)
	p, err := scanProxy(row)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Stats 首页统计。
type Stats struct {
	Total      int64            `json:"total"`
	Elite      int64            `json:"elite"`
	Anonymous  int64            `json:"anonymous"`
	HTTPSOK    int64            `json:"httpsOk"`
	TodayAdded int64            `json:"todayAdded"`
	AvgLatency int64            `json:"avgLatency"`
	Countries  []CountryCounter `json:"countries"`
}

// CountryCounter 国家维度的代理数量。
type CountryCounter struct {
	Name  string `json:"name"`
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

// GetStats 汇总统计。
func (s *Store) GetStats() (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st Stats
	row := s.db.QueryRow(`SELECT
		COUNT(1),
		COALESCE(SUM(anonymity=3),0),
		COALESCE(SUM(anonymity=2),0),
		COALESCE(SUM(https_ok=1),0),
		COALESCE(SUM(substr(created_at,1,10)=date('now','localtime')),0),
		COALESCE(CAST(AVG(CASE WHEN latency>0 THEN latency END) AS INTEGER),0)
		FROM proxies`)
	if err := row.Scan(&st.Total, &st.Elite, &st.Anonymous, &st.HTTPSOK, &st.TodayAdded, &st.AvgLatency); err != nil {
		return st, err
	}
	rows, err := s.db.Query(`SELECT country, country_code, COUNT(1) c FROM proxies GROUP BY country, country_code ORDER BY c DESC LIMIT 20`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var c CountryCounter
		if err := rows.Scan(&c.Name, &c.Code, &c.Count); err != nil {
			return st, err
		}
		st.Countries = append(st.Countries, c)
	}
	return st, rows.Err()
}

// CreateTask 创建任务记录，返回 ID。
func (s *Store) CreateTask(t *Task) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`INSERT INTO tasks (name,type,status,params,total) VALUES (?,?,?,?,?)`,
		t.Name, t.Type, t.Status, t.Params, t.Total)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	t.ID = id
	return id, nil
}

// UpdateTaskProgress 更新任务进度。
func (s *Store) UpdateTaskProgress(id int64, scanned, found, success, failed int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE tasks SET scanned=?, found=?, success=?, failed=? WHERE id=?`, scanned, found, success, failed, id)
	return err
}

// FinishTask 结束任务。
func (s *Store) FinishTask(id int64, status, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE tasks SET status=?, message=?, finished_at=CURRENT_TIMESTAMP WHERE id=?`, status, message, id)
	return err
}

// UpdateTaskStatus 仅更新任务状态（任务开始运行时由排队态改为运行中）。
func (s *Store) UpdateTaskStatus(id int64, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE tasks SET status=? WHERE id=?`, status, id)
	return err
}

// DeleteTask 删除单条任务记录。
func (s *Store) DeleteTask(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM tasks WHERE id=?`, id); err != nil {
		return err
	}
	return nil
}

// ListTasks 返回最近任务列表。
func (s *Store) ListTasks(limit int) ([]Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT id,name,type,status,params,total,scanned,found,success,failed,started_at,COALESCE(finished_at,''),message FROM tasks ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Task
	for rows.Next() {
		var t Task
		var finished string
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Status, &t.Params, &t.Total, &t.Scanned, &t.Found, &t.Success, &t.Failed, &t.StartedAt, &finished, &t.Message); err != nil {
			return nil, err
		}
		if finished != "" {
			if v, err := time.Parse("2006-01-02 15:04:05", finished); err == nil {
				t.FinishedAt = v
			}
		}
		list = append(list, t)
	}
	return list, rows.Err()
}

// ClearTasks 清空全部历史任务记录。
func (s *Store) ClearTasks() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`DELETE FROM tasks`); err != nil {
		return err
	}
	return nil
}

// Schedule 定时任务。
type Schedule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	Kind        string    `json:"kind"`        // scan=扫描 / verify=代理池验证
	Repeat      string    `json:"repeat"`      // once / daily / weekly / interval
	RunTime     string    `json:"runTime"`     // HH:MM（daily/weekly/once 使用）
	OnceAt      string    `json:"onceAt"`      // YYYY-MM-DD HH:MM（once 使用）
	IntervalMin int       `json:"intervalMin"` // interval 使用的分钟数
	Weekday     int       `json:"weekday"`     // weekly: 0=周日 .. 6=周六
	Params      string    `json:"params"`      // kind=scan 时的扫描配置 JSON
	LastRunAt   time.Time `json:"lastRunAt"`
	NextRunAt   time.Time `json:"nextRunAt"`
	RunCount    int       `json:"runCount"`
	LastResult  string    `json:"lastResult"`
	CreatedAt   time.Time `json:"createdAt"`
}

// ListSchedules 返回全部定时任务。
func (s *Store) ListSchedules() ([]Schedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id,name,enabled,kind,repeat,run_time,interval_min,weekday,params,
		COALESCE(last_run_at,''),COALESCE(next_run_at,''),run_count,last_result,created_at FROM schedules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Schedule
	for rows.Next() {
		var (
			x          Schedule
			enabled    int
			lastRun    string
			nextRun    string
		)
		if err := rows.Scan(&x.ID, &x.Name, &enabled, &x.Kind, &x.Repeat, &x.RunTime, &x.IntervalMin,
			&x.Weekday, &x.Params, &lastRun, &nextRun, &x.RunCount, &x.LastResult, timeScan{&x.CreatedAt}); err != nil {
			return nil, err
		}
		x.Enabled = enabled == 1
		x.LastRunAt = parseTime(lastRun)
		x.NextRunAt = parseTime(nextRun)
		list = append(list, x)
	}
	return list, rows.Err()
}

// SaveSchedule 新建或更新定时任务。
func (s *Store) SaveSchedule(x *Schedule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x.ID > 0 {
		_, err := s.db.Exec(`UPDATE schedules SET name=?,enabled=?,kind=?,repeat=?,run_time=?,interval_min=?,weekday=?,params=?,next_run_at=?,last_result=? WHERE id=?`,
			x.Name, boolInt(x.Enabled), x.Kind, x.Repeat, x.RunTime, x.IntervalMin, x.Weekday, x.Params, x.NextRunAt, x.LastResult, x.ID)
		return err
	}
	res, err := s.db.Exec(`INSERT INTO schedules (name,enabled,kind,repeat,run_time,interval_min,weekday,params,next_run_at,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`,
		x.Name, boolInt(x.Enabled), x.Kind, x.Repeat, x.RunTime, x.IntervalMin, x.Weekday, x.Params, x.NextRunAt)
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	x.ID = id
	return nil
}

// DeleteSchedule 删除定时任务。
func (s *Store) DeleteSchedule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM schedules WHERE id=?`, id)
	return err
}

// MarkScheduleRun 记录一次执行结果并推进下次执行时间。
func (s *Store) MarkScheduleRun(id int64, at, next time.Time, result string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE schedules SET last_run_at=?, next_run_at=?, run_count=run_count+1, last_result=? WHERE id=?`,
		at, next, result, id)
	return err
}

// SetScheduleScheduler fields 仅更新下一次触发时间与启用状态。
func (s *Store) SetScheduleNext(id int64, next time.Time, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE schedules SET next_run_at=?, enabled=? WHERE id=?`, next, boolInt(enabled), id)
	return err
}

// Setting / GetSetting 读写运行期配置。
func (s *Store) Setting(key string, out any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), out)
}

// SaveSetting 保存运行期配置。
func (s *Store) SaveSetting(key string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(raw))
	return err
}

func scanProxies(rows *sql.Rows) ([]Proxy, int64, error) {
	var list []Proxy
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, 0, err
		}
		list = append(list, p)
	}
	return list, int64(len(list)), rows.Err()
}

type scannable interface {
	Scan(dest ...any) error
}

func scanProxy(row scannable) (Proxy, error) {
	var (
		p       Proxy
		httpOK  int
		httpsOK int
	)
	err := row.Scan(&p.ID, &p.IP, &p.Port, &httpOK, &httpsOK, &p.Anonymity, &p.Latency, &p.ExitIP,
		&p.Country, &p.CountryCode, &p.Province, &p.City, &p.District, &p.ISP, &p.Region, &p.Source,
		&p.SuccessCount, &p.FailCount, timeScan{&p.CreatedAt}, timeScan{&p.VerifiedAt})
	if err != nil {
		return p, err
	}
	p.HTTPOK = httpOK == 1
	p.HTTPSOK = httpsOK == 1
	return p, nil
}

// timeScan 兼容驱动返回 string / []byte / time.Time / int64 的时间值。
type timeScan struct{ t *time.Time }

func (s timeScan) Scan(v any) error {
	switch x := v.(type) {
	case nil:
		return nil
	case time.Time:
		*s.t = x
	case []byte:
		*s.t = parseTime(string(x))
	case string:
		*s.t = parseTime(x)
	case int64:
		*s.t = time.Unix(x, 0)
	case float64:
		*s.t = time.Unix(int64(x), 0)
	}
	return nil
}

func parseTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05.999999999-07:00",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, v, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

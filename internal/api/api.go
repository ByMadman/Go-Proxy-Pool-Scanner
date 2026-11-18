// Package api 提供 Web 控制台所需的 HTTP 接口与静态资源服务。
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxyscanner/internal/event"
	"proxyscanner/internal/ip2region"
	px "proxyscanner/internal/proxy"
	"proxyscanner/internal/scanner"
	"proxyscanner/internal/scheduler"
	"proxyscanner/internal/store"
)

// Server Web 服务。
type Server struct {
	store     *store.Store
	xdb       *ip2region.Searcher
	mgr       *scanner.Manager
	hub       *event.Hub
	sched     *scheduler.Scheduler
	staticDir string
	extractKey string
	mu        sync.Mutex
	scanCfg   scanner.Config
	vfOpt     px.Option
	publicIP  string
}

// New 创建 Web 服务实例。
func New(st *store.Store, xdb *ip2region.Searcher, mgr *scanner.Manager, vf *px.Verifier, hub *event.Hub, sched *scheduler.Scheduler, staticDir, extractKey string) *Server {
	s := &Server{
		store:     st,
		xdb:       xdb,
		mgr:       mgr,
		hub:       hub,
		sched:     sched,
		staticDir: staticDir,
		extractKey: extractKey,
		scanCfg:   scanner.DefaultConfig(),
		vfOpt:     px.DefaultOption(),
	}
	// 读取已保存的配置
	_ = st.Setting("scan", &s.scanCfg)
	_ = st.Setting("verify", &s.vfOpt)
	s.applyVerifyOption()
	return s
}

// Handler 返回路由（含静态资源）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/regions", s.handleRegions)
	mux.HandleFunc("GET /api/proxies", s.handleListProxies)
	mux.HandleFunc("DELETE /api/proxies/{id}", s.handleDeleteProxy)
	mux.HandleFunc("POST /api/proxies/delete", s.handleDeleteProxies)
	mux.HandleFunc("DELETE /api/proxies", s.handleClearProxies)
	mux.HandleFunc("GET /api/proxies/export", s.handleExport)
	mux.HandleFunc("GET /api/proxies/extract", s.handleExtract)
	mux.HandleFunc("POST /api/proxies/verify", s.handleVerifyProxies)
	mux.HandleFunc("POST /api/proxies/verify/{id}", s.handleVerifyOne)

	mux.HandleFunc("GET /api/config", s.handleGetConfig)
	mux.HandleFunc("POST /api/config", s.handleSaveConfig)
	mux.HandleFunc("GET /api/progress", s.handleProgress)
	mux.HandleFunc("POST /api/scan/start", s.handleScanStart)
	mux.HandleFunc("POST /api/scan/enqueue", s.handleScanEnqueue)
	mux.HandleFunc("GET /api/scan/queue", s.handleScanQueue)
	mux.HandleFunc("DELETE /api/scan/queue/{id}", s.handleScanQueueRemove)
	mux.HandleFunc("POST /api/scan/stop", s.handleScanStop)
	mux.HandleFunc("GET /api/scan/estimate", s.handleEstimate)
	mux.HandleFunc("GET /api/tasks", s.handleTasks)
	mux.HandleFunc("DELETE /api/tasks", s.handleClearTasks)
	mux.HandleFunc("DELETE /api/tasks/{id}", s.handleDeleteTask)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/public-ip", s.handlePublicIP)
	mux.HandleFunc("GET /api/logs", s.handleLogs)

	// 鉴权
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("POST /api/admin/password", s.handleChangePassword)

	// 提取令牌管理（需管理员登录）
	mux.HandleFunc("GET /api/tokens", s.handleListTokens)
	mux.HandleFunc("POST /api/tokens", s.handleCreateToken)
	mux.HandleFunc("DELETE /api/tokens/{id}", s.handleDeleteToken)
	mux.HandleFunc("POST /api/tokens/{id}/toggle", s.handleToggleToken)

	// 定时任务
	mux.HandleFunc("GET /api/schedules", s.handleListSchedules)
	mux.HandleFunc("POST /api/schedules", s.handleSaveSchedule)
	mux.HandleFunc("DELETE /api/schedules/{id}", s.handleDeleteSchedule)
	mux.HandleFunc("POST /api/schedules/{id}/run", s.handleRunSchedule)
	mux.HandleFunc("POST /api/schedules/{id}/toggle", s.handleToggleSchedule)
	mux.HandleFunc("GET /api/health", s.handleHealth)

	// GET /echo 自建回显端点（免鉴权，必须在静态兜底之前）：把收到的请求头原样返回，
	// 供代理验证器判定匿名等级。相比 httpbin.org，国内出口的代理也能稳定访问。
	mux.HandleFunc("GET /echo", s.handleEcho)

	mux.Handle("/", s.staticHandler())
	return cors(s.authMiddleware(mux))
}

// handleEcho 回显请求头与来源 IP。
func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string, len(r.Header))
	for k, vs := range r.Header {
		headers[k] = strings.Join(vs, ",")
	}
	origin := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		origin = host
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"headers": headers,
		"origin":  origin,
		"url":     r.URL.String(),
	})
}

// ---------- 基础工具 ----------

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, map[string]any{"code": 0, "data": data})
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"code": code, "message": msg})
}

func readJSONBody(r *http.Request, out any) error {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("请求体为空")
	}
	return json.Unmarshal(data, out)
}

func (s *Server) applyVerifyOption() {
	vf := px.NewVerifier(s.vfOpt)
	s.mgr.UpdateVerifier(vf)
}

// ---------- 接口实现 ----------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"time":      time.Now().Format("2006-01-02 15:04:05"),
		"xdbFile":   s.xdb.Path(),
		"xdbSizeMB": fmt.Sprintf("%.2f", float64(s.xdb.FileSize())/1024/1024),
	})
}

// GET /api/stats
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.GetStats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, map[string]any{
		"stats":    st,
		"progress": s.mgr.Progress(),
		"publicIp": s.publicIP,
	})
}

// GET /api/regions  返回国家/地区及其省份
func (s *Server) handleRegions(w http.ResponseWriter, r *http.Request) {
	// 直接返回聚合结果：里面带 aliases（原始中/英文写法），
	// 前端用它把历史配置里的英文名换算成当前的中文显示名。
	writeOK(w, s.xdb.Countries())
}

// GET /api/proxies
func (s *Server) handleListProxies(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	maxLatency, _ := strconv.Atoi(q.Get("maxLatency"))
	minLevel, _ := strconv.Atoi(q.Get("minLevel"))
	// 代理池里 country/province 存的是 ip2region 英文原文（如 United States），
	// 界面传的是中文名，这里展开成别名集合再查询，否则筛选会「没反应」。
	var cs, ps []string
	if v := strings.TrimSpace(q.Get("country")); v != "" {
		cs = append(cs, v)
	}
	if v := strings.TrimSpace(q.Get("province")); v != "" {
		ps = append(ps, v)
	}
	countryIn := s.xdb.ExpandCountryFilter(cs)
	provIn := s.xdb.ExpandProvinceFilter(countryIn, ps)
	// 只有真正传了非空 level 才启用精确匹配；空参数（level=）视为「不限」，
	// 否则会被误当成「只看未知(0)」。
	levelStr := strings.TrimSpace(q.Get("level"))
	list, total, err := s.store.ListProxies(store.ProxyQuery{
		Page:       page,
		Size:       size,
		Keyword:    q.Get("keyword"),
		Country:    q.Get("country"),
		Countries:  countryIn,
		Province:   q.Get("province"),
		Provinces:  provIn,
		City:       q.Get("city"),
		District:   q.Get("district"),
		Protocol:   q.Get("protocol"),
		Level:      atoiDef(levelStr, 0),
		LevelSet:   levelStr != "",
		MinLevel:   minLevel,
		MaxLatency: maxLatency,
		SortBy:     q.Get("sortBy"),
		Order:      q.Get("order"),
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if page < 1 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	var bigTotal int64
	if st, err := s.store.GetStats(); err == nil {
		bigTotal = st.Total
	}
	writeOK(w, map[string]any{
		"list":     list,
		"total":    total,
		"page":     page,
		"size":     size,
		"allTotal": bigTotal,
	})
}

// DELETE /api/proxies/{id}
func (s *Server) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	if err := s.store.DeleteProxy(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, true)
}

// POST /api/proxies/delete  {ids:[1,2,3]}
func (s *Server) handleDeleteProxies(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	n, err := s.store.DeleteProxies(req.IDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, n)
}

// DELETE /api/proxies  {country:""} 清空代理池
func (s *Server) handleClearProxies(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Country string `json:"country"`
	}
	_ = readJSONBody(r, &req)
	n, err := s.store.ClearProxies(req.Country)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, n)
}

// GET /api/proxies/export?format=txt|json|csv&country=&protocol=&https=1&anon=elite&minLevel=2&maxLatency=2000&apikey=
// 提取接口：需登录令牌（Authorization 头/Cookie）或配置的提取密钥（apikey）。
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if !s.extractAllowed(r) {
		writeErr(w, 401, "未授权：请提供登录令牌，或配置提取密钥后携带 apikey")
		return
	}
	q := r.URL.Query()
	format := strings.ToLower(q.Get("format"))
	if format == "" {
		format = "txt"
	}
	var cs, ps []string
	if v := strings.TrimSpace(q.Get("country")); v != "" {
		cs = append(cs, v)
	}
	if v := strings.TrimSpace(q.Get("province")); v != "" {
		ps = append(ps, v)
	}
	countryIn := s.xdb.ExpandCountryFilter(cs)
	provIn := s.xdb.ExpandProvinceFilter(countryIn, ps)
	levelStr := strings.TrimSpace(q.Get("level"))
	qy := store.ProxyQuery{
		Country:    q.Get("country"),
		Countries:  countryIn,
		Province:   q.Get("province"),
		Provinces:  provIn,
		City:       q.Get("city"),
		District:   q.Get("district"),
		Keyword:    q.Get("keyword"),
		Protocol:   q.Get("protocol"),
		Level:      atoiDef(levelStr, 0),
		LevelSet:   levelStr != "",
		MinLevel:   atoiDef(q.Get("minLevel"), 0),
		MaxLatency: atoiDef(q.Get("maxLatency"), 0),
		SortBy:     "latency",
		Order:      "asc",
	}
	if lv := atoiDef(q.Get("anon"), 0); lv > 0 {
		qy.MinLevel = lv
	}
	if q.Get("https") == "1" || strings.EqualFold(q.Get("https"), "true") {
		qy.Protocol = "https"
	}
	list, err := s.store.ListProxiesAll(qy, 0)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxies.%s"`, format))
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(list)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		fmt.Fprintln(w, "ip,port,protocol,anonymity,latency,exit_ip,region")
		for _, p := range list {
			fmt.Fprintf(w, "%s,%d,%s,%s,%d,%s,%q\n", p.IP, p.Port, p.Protocol(), store.AnonymityText(p.Anonymity), p.Latency, p.ExitIP, p.Region)
		}
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, p := range list {
			fmt.Fprintf(w, "%s:%d\n", p.IP, p.Port)
		}
	}
}

// POST /api/proxies/verify {ids:[]}  空数组表示验证全部
func (s *Server) handleVerifyProxies(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	_ = readJSONBody(r, &req)
	if err := s.mgr.VerifyAll(req.IDs); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeOK(w, true)
}

// POST /api/proxies/verify/{id}
func (s *Server) handleVerifyOne(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	if err := s.mgr.VerifyAll([]int64{id}); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeOK(w, true)
}

// GET /api/config
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeOK(w, map[string]any{
		"scan":   s.scanCfg,
		"verify": s.vfOpt,
	})
}

// POST /api/config
func (s *Server) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Scan   *scanner.Config `json:"scan"`
		Verify *px.Option      `json:"verify"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.mu.Lock()
	if req.Scan != nil {
		s.scanCfg = *req.Scan
		if err := s.store.SaveSetting("scan", s.scanCfg); err != nil {
			s.mu.Unlock()
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.Verify != nil {
		s.vfOpt = *req.Verify
		if err := s.store.SaveSetting("verify", s.vfOpt); err != nil {
			s.mu.Unlock()
			writeErr(w, 500, err.Error())
			return
		}
		s.applyVerifyOption()
	}
	s.mu.Unlock()
	writeOK(w, true)
}

// GET /api/progress
func (s *Server) handleProgress(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.mgr.Progress())
}

// POST /api/scan/start
func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cfg := s.scanCfg
	s.mu.Unlock()
	if err := readJSONBody(r, &cfg); err != nil && err.Error() != "请求体为空" {
		writeErr(w, 400, err.Error())
		return
	}
	pos, err := s.mgr.Enqueue(cfg)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !cfg.PreserveDefaults {
		s.mu.Lock()
		s.scanCfg = scanner.Config{
			Countries: cfg.Countries, Provinces: cfg.Provinces, Keyword: cfg.Keyword,
			Ports: cfg.Ports, Concurrency: cfg.Concurrency, TimeoutMs: cfg.TimeoutMs,
			MaxCandidates: cfg.MaxCandidates, PerSegment: cfg.PerSegment,
			FullCover: cfg.FullCover, FullCoverMaxIPs: cfg.FullCoverMaxIPs,
			MinAnonymity: cfg.MinAnonymity, AllowUnknown: cfg.AllowUnknown,
			RequireHTTPS: cfg.RequireHTTPS, DedupExitIP: cfg.DedupExitIP,
			MaxLatency: cfg.MaxLatency,
		}
		_ = s.store.SaveSetting("scan", s.scanCfg)
		s.mu.Unlock()
	}
	writeOK(w, map[string]any{"position": pos})
}

// POST /api/scan/enqueue 将一次扫描加入队列（跑完自动接着跑下一个）。
func (s *Server) handleScanEnqueue(w http.ResponseWriter, r *http.Request) {
	s.handleScanStart(w, r)
}

// GET /api/scan/queue 返回当前排队中的任务（不含正在运行的）。
func (s *Server) handleScanQueue(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.mgr.Queue())
}

// DELETE /api/scan/queue/{id} 取消一个排队/运行中的任务。
func (s *Server) handleScanQueueRemove(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	s.mgr.RemoveTask(id)
	writeOK(w, true)
}

// POST /api/scan/stop
func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if !s.mgr.Stop() {
		writeErr(w, 400, "当前没有正在运行的任务")
		return
	}
	writeOK(w, true)
}

// GET /api/scan/estimate?country=中国（可重复）
func (s *Server) handleEstimate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cfg := scanner.Config{
		Countries: q["country"],
		Provinces: q["province"],
		Keyword:   q.Get("keyword"),
		Ranges:    q["range"],
	}
	if v, err := strconv.Atoi(q.Get("perSegment")); err == nil {
		cfg.PerSegment = v
	}
	if v, err := strconv.Atoi(q.Get("maxCandidates")); err == nil {
		cfg.MaxCandidates = v
	}
	if v, err := strconv.Atoi(q.Get("portCount")); err == nil {
		cfg.PortCount = v
	}
	if q.Get("fullCover") == "1" || q.Get("fullCover") == "true" {
		cfg.FullCover = true
	}
	if v, err := strconv.Atoi(q.Get("fullCoverMaxIPs")); err == nil {
		cfg.FullCoverMaxIPs = v
	}
	st := s.mgr.EstimateSegments(cfg)
	writeOK(w, st)
}

// GET /api/tasks
func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListTasks(20)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, list)
}

// DELETE /api/tasks  清空历史任务记录（需管理员登录）。
func (s *Server) handleClearTasks(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearTasks(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, true)
}

// DELETE /api/tasks/{id}  删除单条历史任务记录。
func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	if err := s.store.DeleteTask(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, true)
}

// GET /api/public-ip
func (s *Server) handlePublicIP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.publicIP = px.PublicIP(6 * time.Second)
	ip := s.publicIP
	s.mu.Unlock()
	if s.mgr != nil {
		opt := s.mgr.Verifier().Option()
		opt.PublicIP = ip
		s.mgr.Verifier().SetOption(opt)
	}
	writeOK(w, ip)
}

// GET /api/events  SSE 实时事件
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "当前连接不支持流式输出")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(ch)

	// 立即推送当前进度
	fmt.Fprintf(w, "event: hello\ndata: %s\n\n", mustJSON(map[string]any{
		"progress": s.mgr.Progress(),
	}))
	flusher.Flush()

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, mustJSON(ev.Data))
			flusher.Flush()
		case <-tick.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func atoiDef(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

// ---------- 定时任务 ----------

// GET /api/schedules
func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListSchedules()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]store.Schedule, 0, len(list))
	for _, x := range list {
		if x.Repeat == "once" {
			x.OnceAt = x.RunTime
		}
		if x.Enabled && x.NextRunAt.IsZero() {
			x.NextRunAt = scheduler.ComputeNextRun(&x, time.Now())
		}
		out = append(out, x)
	}
	writeOK(w, out)
}

// POST /api/schedules  新增或更新（id>0 视为更新）
func (s *Server) handleSaveSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Enabled     bool   `json:"enabled"`
		Kind        string `json:"kind"`
		Repeat      string `json:"repeat"`
		RunTime     string `json:"runTime"`
		OnceAt      string `json:"onceAt"`
		IntervalMin int    `json:"intervalMin"`
		Weekday     int    `json:"weekday"`
		Params      string `json:"params"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, 400, "请填写任务名称")
		return
	}
	kind := req.Kind
	if kind != "scan" && kind != "verify" {
		kind = "scan"
	}
	runTime := strings.TrimSpace(req.RunTime)
	if req.Repeat == "once" {
		runTime = strings.TrimSpace(req.OnceAt)
		if _, ok := parseOnce(runTime); !ok {
			writeErr(w, 400, "一次性任务的时间格式应为 YYYY-MM-DD HH:MM")
			return
		}
	} else if req.Repeat != "interval" {
		if _, _, ok := parseHHMMText(runTime); !ok {
			writeErr(w, 400, "时间格式应为 HH:MM")
			return
		}
	}
	if req.Repeat == "interval" && req.IntervalMin < 1 {
		writeErr(w, 400, "间隔分钟数需大于 0")
		return
	}
	if req.Repeat == "" {
		req.Repeat = "daily"
	}

	x := store.Schedule{
		ID:          req.ID,
		Name:        strings.TrimSpace(req.Name),
		Enabled:     req.Enabled,
		Kind:        kind,
		Repeat:      req.Repeat,
		RunTime:     runTime,
		IntervalMin: req.IntervalMin,
		Weekday:     req.Weekday,
		Params:      req.Params,
	}
	next := scheduler.ComputeNextRun(&x, time.Now())
	if next.IsZero() && x.Repeat == "once" {
		writeErr(w, 400, "该一次性任务的时间已过期，请重新设置")
		return
	}
	x.NextRunAt = next
	if err := s.store.SaveSchedule(&x); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.sched.Reload()
	s.hub.Publish("log", map[string]any{
		"level": "info",
		"msg":   fmt.Sprintf("定时任务「%s」已保存，下次触发：%s", x.Name, next.Format("2006-01-02 15:04:05")),
	})
	writeOK(w, x.ID)
}

// DELETE /api/schedules/{id}
func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	if err := s.store.DeleteSchedule(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.sched.Reload()
	writeOK(w, true)
}

// POST /api/schedules/{id}/run  立即执行一次
func (s *Server) handleRunSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	if err := s.sched.RunNow(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeOK(w, true)
}

// POST /api/schedules/{id}/toggle  {enabled:true}
func (s *Server) handleToggleSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	_ = readJSONBody(r, &req)
	list, err := s.store.ListSchedules()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, x := range list {
		if x.ID != id {
			continue
		}
		x.Enabled = req.Enabled
		x.NextRunAt = scheduler.ComputeNextRun(&x, time.Now())
		if err := s.store.SaveSchedule(&x); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		s.sched.Reload()
		writeOK(w, true)
		return
	}
	writeErr(w, 404, "任务不存在")
}

func parseHHMMText(v string) (int, int, bool) {
	if t, err := time.ParseInLocation("15:04", strings.TrimSpace(v), time.Local); err == nil {
		return t.Hour(), t.Minute(), true
	}
	if t, err := time.ParseInLocation("15:04:05", strings.TrimSpace(v), time.Local); err == nil {
		return t.Hour(), t.Minute(), true
	}
	return 0, 0, false
}

func parseOnce(v string) (time.Time, bool) {
	layouts := []string{"2006-01-02 15:04", "2006-01-02 15:04:05"}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, strings.TrimSpace(v), time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// GET /api/logs?n=50  返回最近的历史日志。
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 500 {
		n = 100
	}
	writeOK(w, s.hub.RecentLogs(n))
}

// ---------- 静态资源 ----------

func (s *Server) staticHandler() http.Handler {
	dir := s.staticDir
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			if ok := serveSPAIndex(w, r, dir); ok {
				return
			}
			http.NotFound(w, r)
			return
		}
		// 已存在的文件直接交给 FileServer
		clean := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
		full := filepath.Join(dir, clean)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		// 前端路由 fallback
		if ok := serveSPAIndex(w, r, dir); !ok {
			http.NotFound(w, r)
		}
	})
}

func serveSPAIndex(w http.ResponseWriter, r *http.Request, dir string) bool {
	index := filepath.Join(dir, "index.html")
	data, err := os.ReadFile(index)
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return true
}

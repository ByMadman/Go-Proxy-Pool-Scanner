// Package scanner 负责从 ip2region 网段生成候选、调度验证并把结果落库。
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxyscanner/internal/event"
	"proxyscanner/internal/ip2region"
	px "proxyscanner/internal/proxy"
	"proxyscanner/internal/store"
)

// Config 一次扫描任务的配置。
type Config struct {
	TaskName      string   `json:"taskName"`
	Countries     []string `json:"countries"`     // 国家/地区（名字或代码），为空表示全部
	Provinces     []string `json:"provinces"`     // 省份/区域
	Keyword       string   `json:"keyword"`       // 归属地模糊关键字（省/市/运营商）
	Ranges        []string `json:"ranges"`        // 自定义 IP 段（CIDR 或 起-止），优先于国家筛选
	Ports         []int    `json:"ports"`         // 端口列表
	Concurrency   int      `json:"concurrency"`   // 并发数
	TimeoutMs     int      `json:"timeoutMs"`     // 单次验证超时(毫秒)
	MaxCandidates int      `json:"maxCandidates"` // 随机抽样 IP 总数
	PerSegment    int      `json:"perSegment"`    // 单个网段最多抽样数
	// FullCover 为 true 时启用「网段全覆盖」模式：跳过随机抽样，改为把筛出的
	// 网段按 /24 切成小块、逐个块整段扫描（块内每个 IP 都试），命中率远高于随机 IP。
	// 适合只选单省/单州的精扫；覆盖范围很大时由 FullCoverMaxIPs 限流，避免任务失控。
	FullCover       bool `json:"fullCover"`
	FullCoverMaxIPs int  `json:"fullCoverMaxIPs"` // 全覆盖模式最多扫多少 IP（默认 100 万）
	MinAnonymity  int      `json:"minAnonymity"`  // 入库匿名等级下限 0/1/2/3
	AllowUnknown  bool     `json:"allowUnknown"`  // 是否允许「未判定」匿名等级入库
	RequireHTTPS  bool     `json:"requireHttps"`  // 是否必须支持 HTTPS
	DedupExitIP   bool     `json:"dedupExitIp"`   // 同一出口 IP 只保留一条
	MaxLatency    int      `json:"maxLatency"`    // 延迟上限(毫秒)，0 不限
	// PortCount 仅用于「覆盖范围/候选数预估」：前端传入端口数量，避免真的构造端口列表。
	// 实际执行时以 Ports 为准。
	PortCount int `json:"portCount,omitempty"`
	// PreserveDefaults 为 true 时（如定时任务、内部调用）不把本次配置写回「用户默认配置」，
	// 避免把用户表单里保存的偏好覆盖掉。
	PreserveDefaults bool `json:"-"`
}

// DefaultConfig 返回默认扫描配置。
func DefaultConfig() Config {
	return Config{
		Countries:     []string{"中国"},
		Ports:         []int{80, 8080, 8081, 3128, 8888, 1080, 10809, 20171, 7890, 7891, 10809, 2080, 8000, 9797, 53281},
		Concurrency:   300,
		TimeoutMs:     6000,
		MaxCandidates: 20000,
		PerSegment:    4,
		FullCoverMaxIPs: 0, // 0 = 不限：全覆盖时扫描所选范围的全部 IP
		MinAnonymity:  px.AnonymityAnonymous,
		AllowUnknown:  true,
		RequireHTTPS:  false,
		DedupExitIP:   false,
	}
}

// Progress 任务进度快照。
type Progress struct {
	Running    bool   `json:"running"`
	Type       string `json:"type"` // scan / verify
	Name       string `json:"name"`
	TaskID     int64  `json:"taskId"`
	Total      int64  `json:"total"`
	Scanned    int64  `json:"scanned"`
	Found      int64  `json:"found"`
	Failed     int64  `json:"failed"`
	Deleted    int64  `json:"deleted"`
	StartedAt  int64  `json:"startedAt"`
	ElapsedMs  int64  `json:"elapsedMs"`
	RatePerSec int    `json:"ratePerSec"`
	Message    string `json:"message"`

	// 验证通过但被入库条件过滤的明细，用于解释「为什么 0 入库」。
	Verified      int64 `json:"verified"`      // 通过可用性验证（代理确实能用）
	RejectLatency int64 `json:"rejectLatency"` // 延迟超过上限
	RejectAnon    int64 `json:"rejectAnon"`    // 匿名等级不达标
	RejectUnknown int64 `json:"rejectUnknown"` // 匿名等级未知且不允许入库
	RejectHTTPS   int64 `json:"rejectHttps"`   // 要求 HTTPS 但代理不支持
	RejectDedup   int64 `json:"rejectDedup"`   // 出口 IP 重复去重
}

// rejectStats 记录"验证通过却被过滤"的分类计数（并发安全用原子操作）。
type rejectStats struct {
	verified int64
	latency  int64
	anon     int64
	unknown  int64
	https    int64
	dedup    int64
}

// QueueItem 队列中待执行任务的快照（供前端展示）。
type QueueItem struct {
	ID       int64   `json:"id"`
	Name     string  `json:"name"`
	Position int     `json:"position"` // 在队列中的序号（1 起）
	Total    int64   `json:"total"`    // 预估候选数
	Cfg      Config  `json:"cfg"`
}

// queueItem 队列内部项（含完整配置，运行时再展开为作业）。
type queueItem struct {
	id    int64
	name  string
	cfg   Config
	total int64
}

// SegmentStat 网段统计，用于前端展示任务覆盖范围。
type SegmentStat struct {
	Segments int    `json:"segments"`
	IPs      uint64 `json:"ips"`
	// 以下为「按当前抽样配置实际会扫描的规模」，用于消除「覆盖 42 亿却 3 秒结束」的误解。
	MaxIPs      int     `json:"maxIps"`      // 实际抽样/扫描的 IP 数
	Ports       int     `json:"ports"`       // 端口数
	Candidates  int64   `json:"candidates"`  // 候选探测数 = IP 数 × 端口数
	Full        bool    `json:"full"`        // 是否网段全覆盖模式
	Blocks      int     `json:"blocks"`      // 全覆盖模式下将扫描的 /24 块数
	CoveragePct float64 `json:"coveragePct"` // 本次实际扫描 IP 占地址池 IP 的百分比
}

type job struct {
	ip   uint32
	port int
}

// Manager 扫描/验证任务管理器。
type Manager struct {
	store *store.Store
	xdb   *ip2region.Searcher
	vf    *px.Verifier
	hub   *event.Hub

	mu       sync.Mutex
	cancel   context.CancelFunc
	progress Progress
	queue    []queueItem // 等待执行的扫描任务（不含正在运行的）
}

// NewManager 创建管理器。
func NewManager(st *store.Store, xdb *ip2region.Searcher, vf *px.Verifier, hub *event.Hub) *Manager {
	return &Manager{store: st, xdb: xdb, vf: vf, hub: hub}
}

// ErrBusy 已有任务在运行。
var ErrBusy = errors.New("已有任务正在运行，请先停止或等待其结束")

// Verifier 返回验证器。
func (m *Manager) Verifier() *px.Verifier { return m.vf }

// UpdateVerifier 替换验证器（例如用户修改了回显站点配置）。
func (m *Manager) UpdateVerifier(vf *px.Verifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vf = vf
}

// Progress 返回当前进度快照。
func (m *Manager) Progress() Progress {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.progress
	if p.Running {
		p.ElapsedMs = time.Now().UnixMilli() - p.StartedAt
		if sec := p.ElapsedMs / 1000; sec > 0 {
			p.RatePerSec = int(p.Scanned / sec)
		}
	}
	return p
}

// IsRunning 是否有任务在运行。
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.progress.Running
}

// Stop 请求停止当前任务。
func (m *Manager) Stop() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.progress.Running || m.cancel == nil {
		return false
	}
	m.cancel()
	return true
}

func (m *Manager) begin(typ, name string, total int64, taskID int64) (context.Context, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.progress.Running {
		return nil, ErrBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.progress = Progress{
		Running:   true,
		Type:      typ,
		Name:      name,
		TaskID:    taskID,
		Total:     total,
		StartedAt: time.Now().UnixMilli(),
	}
	m.hub.Publish("progress", m.progress)
	return ctx, nil
}

func (m *Manager) finish(status, message string) {
	m.mu.Lock()
	p := m.progress
	p.Running = false
	p.Message = message
	p.ElapsedMs = time.Now().UnixMilli() - p.StartedAt
	m.progress = p
	m.cancel = nil
	m.mu.Unlock()
	if p.TaskID > 0 {
		_ = m.store.FinishTask(p.TaskID, status, message)
	}
	m.hub.Publish("progress", p)
	m.hub.Publish("done", map[string]any{"status": status, "message": message})
	// 当前任务结束后，自动启动队列中的下一个（若有）。
	m.runNext()
}

// scanPlan 一次扫描的作业流：total 用于进度条，produce 按需生成作业。
// 网段全覆盖时作业量可达数十亿，不能预生成 []job（会 OOM），必须流式生成。
type scanPlan struct {
	name    string
	total   int64
	produce func(ctx context.Context, ch chan<- job)
}

// prepareScan 校验配置并生成作业流，供 Enqueue（仅校验/计数）和 runItem（真正执行）复用。
func (m *Manager) prepareScan(cfg Config) (*scanPlan, error) {
	cfg = normalizeConfig(cfg)
	var (
		segs []ip2region.Segment
		err  error
	)
	if len(cfg.Ranges) > 0 {
		segs, err = parseRanges(cfg.Ranges)
		if err != nil {
			return nil, err
		}
	} else {
		if len(cfg.Countries) == 0 && strings.TrimSpace(cfg.Keyword) == "" && len(cfg.Provinces) == 0 {
			return nil, errors.New("请至少选择一个国家/地区，或填写归属地关键字")
		}
		segs = m.xdb.Segments(ip2region.Filter{
			Countries: cfg.Countries,
			Provinces: cfg.Provinces,
			Keyword:   cfg.Keyword,
		})
	}
	if len(segs) == 0 {
		return nil, errors.New("ip2region 中没有匹配的网段，请调整国家/地区或关键字")
	}

	// 任务名带上省份，避免「中国·四川」只显示成「中国」。
	name := cfg.TaskName
	if name == "" {
		label := strings.Join(cfg.Countries, ",")
		if label == "" {
			label = "自定义IP段"
		}
		if p := strings.Join(cfg.Provinces, "、"); p != "" {
			label += "·" + p
		}
		name = fmt.Sprintf("扫描 %s", label)
	}

	ports := len(cfg.Ports)
	if ports == 0 {
		ports = len(DefaultConfig().Ports)
	}

	// 网段全覆盖：逐 /24 块整段扫描，作业流式生成，不设 IP 上限。
	if cfg.FullCover {
		blocks := expandBlocks(segs)
		if len(blocks) == 0 {
			return nil, errors.New("未能展开可用网段，请调整扫描范围")
		}
		var totalIPs int64
		for _, b := range blocks {
			totalIPs += int64(b.end) - int64(b.start) + 1
		}
		produce := func(ctx context.Context, ch chan<- job) {
			for _, b := range blocks {
				for ip := b.start; ; ip++ {
					if ip != 0 {
						for _, port := range cfg.Ports {
							select {
							case <-ctx.Done():
								return
							case ch <- job{ip: ip, port: port}:
							}
						}
					}
					if ip == b.end || ip == 0xFFFFFFFF {
						break
					}
				}
			}
		}
		return &scanPlan{name: name, total: totalIPs * int64(ports), produce: produce}, nil
	}

	jobs := buildJobs(segs, cfg)
	if len(jobs) == 0 {
		return nil, errors.New("未能生成候选 IP，请放宽过滤条件")
	}
	produce := func(ctx context.Context, ch chan<- job) {
		for _, j := range jobs {
			select {
			case <-ctx.Done():
				return
			case ch <- j:
			}
		}
	}
	return &scanPlan{name: name, total: int64(len(jobs)), produce: produce}, nil
}

// Enqueue 将一个扫描配置加入队列：立即校验，写入「排队中」任务记录，
// 若当前空闲则自动开跑。返回在队列中的位置（1 起）。
func (m *Manager) Enqueue(cfg Config) (int, error) {
	cfg = normalizeConfig(cfg)
	plan, err := m.prepareScan(cfg)
	if err != nil {
		return 0, err
	}
	params, _ := json.Marshal(cfg)
	taskID, _ := m.store.CreateTask(&store.Task{
		Name:   plan.name,
		Type:   "scan",
		Status: "queued",
		Params: string(params),
		Total:  plan.total,
	})
	m.mu.Lock()
	m.queue = append(m.queue, queueItem{id: taskID, name: plan.name, cfg: cfg, total: plan.total})
	pos := len(m.queue)
	m.mu.Unlock()
	m.hub.Publish("log", map[string]any{
		"level": "info",
		"msg": fmt.Sprintf("已加入任务队列（第 %d 位）：%s，候选 %d 个", pos, plan.name, plan.total),
	})
	m.runNext()
	return pos, nil
}

// Queue 返回当前排队中的任务快照（不含正在运行的）。
func (m *Manager) Queue() []QueueItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]QueueItem, 0, len(m.queue))
	for i, q := range m.queue {
		out = append(out, QueueItem{ID: q.id, Name: q.name, Position: i + 1, Total: q.total, Cfg: q.cfg})
	}
	return out
}

// RemoveTask 移除一个任务：排队中则从队列删除；运行中则停止并删除记录。
func (m *Manager) RemoveTask(id int64) {
	m.mu.Lock()
	for i, q := range m.queue {
		if q.id == id {
			m.queue = append(m.queue[:i], m.queue[i+1:]...)
			m.mu.Unlock()
			_ = m.store.DeleteTask(id)
			m.hub.Publish("queue", m.Queue())
			m.hub.Publish("log", map[string]any{"level": "info", "msg": fmt.Sprintf("已取消排队任务：%s", q.name)})
			return
		}
	}
	running := m.progress.Running && m.progress.TaskID == id
	m.mu.Unlock()
	if running {
		m.Stop()
	}
	_ = m.store.DeleteTask(id)
	m.hub.Publish("queue", m.Queue())
}

// runNext 若空闲且队列非空，则取出队首任务开跑。
func (m *Manager) runNext() {
	m.mu.Lock()
	if m.progress.Running {
		m.mu.Unlock()
		return
	}
	if len(m.queue) == 0 {
		m.mu.Unlock()
		m.hub.Publish("queue", m.Queue())
		return
	}
	item := m.queue[0]
	m.queue = m.queue[1:]
	m.mu.Unlock()
	m.hub.Publish("queue", m.Queue())
	go m.runItem(item)
}

// runItem 展开队列项为作业并真正执行一次扫描。
func (m *Manager) runItem(item queueItem) {
	plan, err := m.prepareScan(item.cfg)
	if err != nil {
		_ = m.store.FinishTask(item.id, "failed", err.Error())
		m.hub.Publish("log", map[string]any{"level": "warn", "msg": fmt.Sprintf("任务「%s」启动失败：%s", item.name, err.Error())})
		m.runNext()
		return
	}
	// 扫描配置里的超时/并发即时作用于验证器
	opt := m.vf.Option()
	opt.TotalTimeout = px.DurationMs(item.cfg.TimeoutMs)
	opt.DialTimeout = px.DurationMs(item.cfg.TimeoutMs / 2)
	if opt.DialTimeout < 500 {
		opt.DialTimeout = 500
	}
	opt.ConcurrencyHint = item.cfg.Concurrency
	m.vf.SetOption(opt)

	ctx, err := m.begin("scan", plan.name, plan.total, item.id)
	if err != nil {
		_ = m.store.FinishTask(item.id, "failed", err.Error())
		m.runNext()
		return
	}
	_ = m.store.UpdateTaskStatus(item.id, "running")
	m.hub.Publish("log", map[string]any{
		"level": "info",
		"msg": fmt.Sprintf("任务启动：%s，候选 %d 个，并发 %d", plan.name, plan.total, item.cfg.Concurrency),
	})
	go m.runScan(ctx, item.cfg, plan)
}

func (m *Manager) runScan(ctx context.Context, cfg Config, plan *scanPlan) {
	var (
		scanned int64
		found   int64
		failed  int64
		wg      sync.WaitGroup
	)
	// 事件限流：防止海量日志事件经 SSE 冲垮前端主线程（表现为“点击扫描即卡死”）
	var logMu sync.Mutex
	var lastFail, lastDetail int64
	rs := &rejectStats{}
	ch := make(chan job, cfg.Concurrency*2)
	seenExit := map[string]struct{}{}
	var seenMu sync.Mutex

	// 投递任务：全覆盖模式下由 produce 流式生成，不再预先生成全部作业（避免 OOM）
	go func() {
		defer close(ch)
		plan.produce(ctx, ch)
	}()

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				select {
				case <-ctx.Done():
					return
				default:
				}
				ipStr := ip2region.Uint32ToIP(j.ip)
				curScanned := atomic.AddInt64(&scanned, 1)
				res := m.vf.Verify(ipStr, j.port)
				if curScanned%200 == 0 {
					m.tick(curScanned, atomic.LoadInt64(&found), atomic.LoadInt64(&failed), 0, rs)
				}
				if !res.OK {
					atomic.AddInt64(&failed, 1)
					// 失败日志限流：每 3s 最多 1 条，失败计数已在实时进度里显示
					now := time.Now().UnixMilli()
					logMu.Lock()
					if now-lastFail >= 3000 {
						lastFail = now
						m.hub.Publish("log", map[string]any{"level": "warn", "msg": fmt.Sprintf("验证失败中：已检查 %d，失败 %d（多数候选非可用代理）", curScanned, atomic.LoadInt64(&failed))})
					}
					logMu.Unlock()
					continue
				}
				atomic.AddInt64(&rs.verified, 1)
				if ok, reason := accept(res, cfg); !ok {
					switch reason {
					case "https":
						atomic.AddInt64(&rs.https, 1)
					case "latency":
						atomic.AddInt64(&rs.latency, 1)
					case "unknown":
						atomic.AddInt64(&rs.unknown, 1)
					default:
						atomic.AddInt64(&rs.anon, 1)
					}
					continue
				}
				if cfg.DedupExitIP && res.ExitIP != "" {
					seenMu.Lock()
					if _, dup := seenExit[res.ExitIP]; dup {
						seenMu.Unlock()
						atomic.AddInt64(&rs.dedup, 1)
						continue
					}
					seenExit[res.ExitIP] = struct{}{}
					seenMu.Unlock()
				}
				loc, _ := m.xdb.Search(ipStr)
				p := store.Proxy{
					IP:          ipStr,
					Port:        j.port,
					HTTPOK:      res.HTTPOK,
					HTTPSOK:     res.HTTPSOK,
					Anonymity:   res.Anonymity,
					Latency:     res.Latency,
					ExitIP:      res.ExitIP,
					Country:     loc.Country,
					CountryCode: loc.CountryCode,
					Province:    loc.Province,
					City:        loc.City,
					District:    loc.District,
					ISP:         loc.ISP,
					Region:      loc.Display(),
					Source:      "扫描",
				}
				if err := m.store.SaveProxy(&p); err != nil {
					m.hub.Publish("log", map[string]any{"level": "warn", "msg": "写入失败: " + err.Error()})
					continue
				}
				atomic.AddInt64(&found, 1)
				// 入库详情日志限流：仅前 200 条、且每秒最多 1 条，避免事件洪流打垮前端
				now := time.Now().UnixMilli()
				logMu.Lock()
				if atomic.LoadInt64(&found) <= 200 && now-lastDetail >= 1000 {
					lastDetail = now
					m.hub.Publish("log", map[string]any{"level": "info", "msg": fmt.Sprintf("入库 %s:%d 协议=%v/%v 匿名=%d 延迟=%dms 出口=%s",
						ipStr, j.port, res.HTTPOK, res.HTTPSOK, res.Anonymity, res.Latency, res.ExitIP)})
				}
				logMu.Unlock()
				m.hub.Publish("found", &p)
			}
		}()
	}

	// 进度上报（独立于 wg：避免 wg.Wait 与 stop 关闭相互等待造成死锁）
	stop := make(chan struct{})
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				m.tick(atomic.LoadInt64(&scanned), atomic.LoadInt64(&found), atomic.LoadInt64(&failed), 0, rs)
				return
			case <-t.C:
				m.tick(atomic.LoadInt64(&scanned), atomic.LoadInt64(&found), atomic.LoadInt64(&failed), 0, rs)
			}
		}
	}()

	wg.Wait()
	close(stop)
	<-progressDone

	status := "completed"
	stopped := ctx.Err() != nil
	if stopped {
		status = "stopped"
	}
	verified := atomic.LoadInt64(&rs.verified)
	detail := fmt.Sprintf("延迟超限 %d、匿名不足 %d、未知等级 %d、需HTTPS %d、出口重复 %d",
		rs.latency, rs.anon, rs.unknown, rs.https, rs.dedup)
	total := plan.total
	sampledIPs := int64(0)
	if len(cfg.Ports) > 0 {
		sampledIPs = total / int64(len(cfg.Ports))
	}
	budget := fmt.Sprintf("本次共 %d 个 IP × %d 端口 = %d 个候选", sampledIPs, len(cfg.Ports), total)
	var msg string
	if stopped {
		msg = fmt.Sprintf("任务已停止：已检查 %d/%d 个候选，入库 %d 条（%s）", scanned, total, found, budget)
	} else {
		msg = fmt.Sprintf("扫描结束：检查 %d/%d 个候选，入库 %d 条（%s，已全部检查完毕）", scanned, total, found, budget)
	}
	if rejected := verified - found; rejected > 0 {
		if found == 0 {
			msg += fmt.Sprintf("。注意：有 %d 个代理验证通过却全部被入库条件过滤（%s），建议调高「延迟上限」或允许「未知等级」入库。", verified, detail)
		} else {
			msg += fmt.Sprintf("；另有 %d 个验证通过但被过滤（%s）", rejected, detail)
		}
	}
	m.hub.Publish("log", map[string]any{"level": "info", "msg": msg})
	m.finish(status, msg)
}

// VerifyAll 一键验证：重新验证代理池中的记录，失败的自动删除。
// ids 为空表示验证全部。
func (m *Manager) VerifyAll(ids []int64) error {
	if len(ids) == 0 {
		list, err := m.store.AllProxies()
		if err != nil {
			return err
		}
		for _, p := range list {
			ids = append(ids, p.ID)
		}
	}
	if len(ids) == 0 {
		return errors.New("代理池为空，没有可验证的记录")
	}
	return m.startVerify(ids)
}

func (m *Manager) startVerify(ids []int64) error {
	name := fmt.Sprintf("验证 %d 条代理", len(ids))
	taskID, _ := m.store.CreateTask(&store.Task{
		Name:   name,
		Type:   "verify",
		Status: "running",
		Params: "",
		Total:  int64(len(ids)),
	})
	ctx, err := m.begin("verify", name, int64(len(ids)), taskID)
	if err != nil {
		_ = m.store.FinishTask(taskID, "failed", err.Error())
		return err
	}
	m.hub.Publish("log", map[string]any{"level": "info", "msg": name + "：开始验证，失败的将自动删除"})
	go m.runVerify(ctx, ids)
	return nil
}

func (m *Manager) runVerify(ctx context.Context, ids []int64) {
	var (
		scanned int64
		okCount int64
		deleted int64
		wg      sync.WaitGroup
	)
	conc := m.vf.Option().ConcurrencyHint
	if conc <= 0 {
		conc = 100
	}
	ch := make(chan int64, conc*2)
	go func() {
		defer close(ch)
		for _, id := range ids {
			select {
			case <-ctx.Done():
				return
			case ch <- id:
			}
		}
	}()
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range ch {
				select {
				case <-ctx.Done():
					return
				default:
				}
				p, err := m.store.ProxyByID(id)
				if err != nil || p == nil {
					continue
				}
				cur := atomic.AddInt64(&scanned, 1)
				res := m.vf.Verify(p.IP, p.Port)
				if cur%100 == 0 {
					m.tick(cur, atomic.LoadInt64(&okCount), 0, atomic.LoadInt64(&deleted), nil)
				}
				if !res.OK {
					atomic.AddInt64(&deleted, 1)
					if err := m.store.DeleteProxy(p.ID); err == nil {
						m.hub.Publish("removed", map[string]any{"id": p.ID, "ip": p.IP, "port": p.Port})
					}
					continue
				}
				p.HTTPOK = res.HTTPOK
				p.HTTPSOK = res.HTTPSOK
				p.Latency = res.Latency
				p.Anonymity = res.Anonymity
				p.ExitIP = res.ExitIP
				p.VerifiedAt = time.Now()
				p.FailCount = 0
				p.SuccessCount++
				if err := m.store.SaveProxy(p); err != nil {
					m.hub.Publish("log", map[string]any{"level": "warn", "msg": "更新失败: " + err.Error()})
					continue
				}
				atomic.AddInt64(&okCount, 1)
				m.hub.Publish("updated", p)
			}
		}()
	}
	wg.Wait()

	status := "completed"
	msg := fmt.Sprintf("验证结束：有效 %d 条，失效删除 %d 条", okCount, deleted)
	if ctx.Err() != nil {
		status = "stopped"
		msg = fmt.Sprintf("验证已停止：有效 %d 条，失效删除 %d 条", okCount, deleted)
	}
	m.hub.Publish("log", map[string]any{"level": "info", "msg": msg})
	m.finish(status, msg)
}

func (m *Manager) tick(scanned, found, failed, deleted int64, rs *rejectStats) {
	m.mu.Lock()
	p := m.progress
	p.Scanned = scanned
	p.Found = found
	p.Failed = failed
	p.Deleted = deleted
	if rs != nil {
		p.Verified = atomic.LoadInt64(&rs.verified)
		p.RejectLatency = atomic.LoadInt64(&rs.latency)
		p.RejectAnon = atomic.LoadInt64(&rs.anon)
		p.RejectUnknown = atomic.LoadInt64(&rs.unknown)
		p.RejectHTTPS = atomic.LoadInt64(&rs.https)
		p.RejectDedup = atomic.LoadInt64(&rs.dedup)
	}
	p.ElapsedMs = time.Now().UnixMilli() - p.StartedAt
	if sec := p.ElapsedMs / 1000; sec > 0 {
		p.RatePerSec = int(scanned / sec)
	}
	m.progress = p
	m.mu.Unlock()
	if p.TaskID > 0 {
		_ = m.store.UpdateTaskProgress(p.TaskID, scanned, found, found, deleted)
	}
	m.hub.Publish("progress", p)
}

// EstimateSegments 估算某个过滤条件下的网段与 IP 覆盖，用于启动前确认。
func (m *Manager) EstimateSegments(cfg Config) SegmentStat {
	var segs []ip2region.Segment
	if len(cfg.Ranges) > 0 {
		rs, err := parseRanges(cfg.Ranges)
		if err == nil {
			segs = rs
		}
	} else {
		segs = m.xdb.Segments(ip2region.Filter{
			Countries: cfg.Countries,
			Provinces: cfg.Provinces,
			Keyword:   cfg.Keyword,
		})
	}
	var st SegmentStat
	st.Segments = len(segs)
	for _, s := range segs {
		st.IPs += s.Size()
	}
	// 端口数：优先用真实端口列表，其次用前端传的数量，最后取默认。
	ports := len(cfg.Ports)
	if ports == 0 {
		ports = cfg.PortCount
	}
	if ports == 0 {
		ports = len(DefaultConfig().Ports)
	}
	nc := normalizeConfig(cfg)
	// 网段全覆盖模式：逐 /24 块整段扫描所选范围的全部 IP，不再按 IP 上限截断。
	if nc.FullCover {
		blocks := expandBlocks(segs)
		st.Full = true
		st.MaxIPs = int(st.IPs)
		st.Blocks = len(blocks)
		st.Ports = ports
		st.Candidates = int64(st.IPs) * int64(ports)
		st.CoveragePct = 100
		return st
	}
	// 抽样模式：按网段大小比例抽若干个随机 IP。
	shares := samplePlan(segs, nc)
	ips := 0
	for _, n := range shares {
		ips += n
	}
	st.MaxIPs = ips
	st.Ports = ports
	st.Candidates = int64(ips) * int64(ports)
	if st.IPs > 0 {
		st.CoveragePct = float64(ips) / float64(st.IPs) * 100
	}
	return st
}

// accept 判断验证结果是否满足入库条件。
// accept 判断验证通过的代理是否满足入库条件，返回 (是否入库, 被拒原因)。
func accept(res px.Result, cfg Config) (bool, string) {
	// 双协议验证已能自动识别 HTTP/HTTPS 代理，不再按「必须 HTTPS」过滤；
	// 「延迟上限」也取消，入库只看匿名等级 / 未知策略 / 出口去重。
	if res.Anonymity == px.AnonymityUnknown {
		if !cfg.AllowUnknown {
			return false, "unknown"
		}
		return true, ""
	}
	if res.Anonymity < cfg.MinAnonymity {
		return false, "anon"
	}
	return true, ""
}

func normalizeConfig(c Config) Config {
	d := DefaultConfig()
	if len(c.Ports) == 0 {
		c.Ports = d.Ports
	}
	if c.Concurrency <= 0 {
		c.Concurrency = d.Concurrency
	}
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = d.TimeoutMs
	}
	if c.MaxCandidates <= 0 {
		c.MaxCandidates = d.MaxCandidates
	}
	if c.PerSegment <= 0 {
		c.PerSegment = d.PerSegment
	}
	// 端口去重
	seen := map[int]bool{}
	ports := make([]int, 0, len(c.Ports))
	for _, p := range c.Ports {
		if p > 0 && p < 65536 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	c.Ports = ports
	if c.MaxCandidates > 5_000_000 {
		c.MaxCandidates = 5_000_000
	}
	// 网段全覆盖不再按 IP 上限截断：FullCoverMaxIPs 仅为兼容旧配置保留，0 表示不限。
	if c.FullCover && c.FullCoverMaxIPs < 0 {
		c.FullCoverMaxIPs = 0
	}
	return c
}

// samplePlan 计算「每个网段抽样多少个 IP」，返回与 segs 等长的份额数组。
//
// 旧实现按网段顺序依次分配，预算一用完就 break，导致「抽样 100 个 IP」时只覆盖
// 地址空间最前面的 100 个网段（通常全是基础设/保留段），大区域几乎扫不到真实 ISP，
// 而且看起来像「刚开始就结束了」。这里改为：
//  1. 先按网段大小比例算出理想份额（单项限制在 [1, PerSegment]）；
//  2. 按「随机网段顺序」分配预算，使抽样均匀散布在整个区域；
//  3. 总量不超过 MaxCandidates（抽样 IP 数）。
func samplePlan(segs []ip2region.Segment, cfg Config) []int {
	shares := make([]int, len(segs))
	if len(segs) == 0 {
		return shares
	}
	var totalIPs uint64
	for _, s := range segs {
		totalIPs += s.Size()
	}
	if totalIPs == 0 {
		return shares
	}
	budget := cfg.MaxCandidates
	perSeg := cfg.PerSegment
	if perSeg < 1 {
		perSeg = 1
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	assigned := 0
	for _, idx := range rnd.Perm(len(segs)) {
		if assigned >= budget {
			break
		}
		share := int(float64(segs[idx].Size()) / float64(totalIPs) * float64(budget))
		if share < 1 {
			share = 1
		}
		if share > perSeg {
			share = perSeg
		}
		if share > budget-assigned {
			share = budget - assigned
		}
		shares[idx] = share
		assigned += share
	}
	return shares
}

// ipBlock 是一个对齐到 /24 的连续 IP 块（不足 /24 的网段整段作为一块）。
type ipBlock struct {
	start, end uint32
}

// expandBlocks 把网段按 /24 切成小块：每个块最多 256 个 IP 且起始地址对齐 /24
// 边界。小于 /24 的小网段（如 /29）保持原样作为一块。这种切块方式让「网段全覆盖」
// 模式下探测在段内均匀分布，命中率远高于在几十亿地址里随机抽单个 IP。
func expandBlocks(segs []ip2region.Segment) []ipBlock {
	blocks := make([]ipBlock, 0, len(segs))
	for _, s := range segs {
		st, en := s.Start, s.End
		for st <= en {
			bEnd := (st | 0x000000ff) // 本 /24 块末尾
			if bEnd > en || bEnd < st {
				bEnd = en
			}
			if bEnd >= st {
				blocks = append(blocks, ipBlock{start: st, end: bEnd})
			}
			if bEnd == en {
				break
			}
			st = bEnd + 1
		}
	}
	return blocks
}

// buildJobs 根据配置生成候选任务。
//   - 抽样模式（默认）：按 samplePlan 的比例在每个网段抽若干个随机 IP。
//   - 网段全覆盖模式（FullCover）：把网段拆成 /24 块，逐块整段扫描（块内每个 IP 都试），
//     直到达到 FullCoverMaxIPs 上限。这样每块内命中率接近 100%。
func buildJobs(segs []ip2region.Segment, cfg Config) []job {
	if cfg.FullCover {
		return buildFullCoverJobs(segs, cfg)
	}
	shares := samplePlan(segs, cfg)
	total := 0
	for _, n := range shares {
		total += n
	}
	if total == 0 {
		return nil
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	capacity := total * len(cfg.Ports)
	if capacity > 4_000_000 {
		capacity = 4_000_000
	}
	jobs := make([]job, 0, capacity)
	for i, s := range segs {
		n := shares[i]
		if n == 0 {
			continue
		}
		for k := 0; k < n; k++ {
			ip := randUint32In(rnd, s.Start, s.End)
			if ip == 0 {
				continue
			}
			for _, port := range cfg.Ports {
				jobs = append(jobs, job{ip: ip, port: port})
			}
		}
	}
	// 打散，避免并发 workers 长时间集中在同一小段
	rnd.Shuffle(len(jobs), func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })
	return jobs
}

// buildFullCoverJobs 网段全覆盖模式：逐 /24 块整段扫描，受 IP 总数上限约束。
func buildFullCoverJobs(segs []ip2region.Segment, cfg Config) []job {
	blocks := expandBlocks(segs)
	if len(blocks) == 0 {
		return nil
	}
	ipMax := cfg.FullCoverMaxIPs
	if ipMax <= 0 {
		ipMax = 1_000_000
	}
	// 候选 job 上限保护内存：最多约 800 万 job（≈ 33 万 IP × 24 端口）。
	maxJobs := ipMax * len(cfg.Ports)
	const jobCap = 8_000_000
	if maxJobs > jobCap {
		maxJobs = jobCap
	}
	jobs := make([]job, 0, maxJobs)
	for _, b := range blocks {
		if len(jobs) >= maxJobs {
			break
		}
		// 逐 IP 扫描；用「到末尾或回绕到 0」判定结束，避免 end==0xFFFFFFFF 时 uint32 自增溢出成死循环。
		for ip := b.start; ; ip++ {
			if ip != 0 {
				for _, port := range cfg.Ports {
					jobs = append(jobs, job{ip: ip, port: port})
				}
			}
			if ip == b.end || ip == 0xFFFFFFFF {
				break
			}
			if len(jobs) >= maxJobs {
				break
			}
		}
	}
	return jobs
}

// parseRanges 解析自定义 IP 段，支持 CIDR（如 1.2.3.0/24）与区间（如 1.2.3.1-1.2.3.254），
// 也支持单个 IP（自动取整段内的一个 /32）。
func parseRanges(list []string) ([]ip2region.Segment, error) {
	out := make([]ip2region.Segment, 0, len(list))
	for _, raw := range list {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		switch {
		case strings.Contains(item, "/"):
			_, n, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("无效的 CIDR: %s", item)
			}
			if n.IP.To4() == nil {
				return nil, fmt.Errorf("暂不支持 IPv6 段: %s", item)
			}
			start, err1 := ip2region.IPToUint32(n.IP.String())
			if err1 != nil {
				return nil, fmt.Errorf("无效的 CIDR: %s", item)
			}
			ones, _ := n.Mask.Size()
			end := start | ^(^uint32(0) << (32 - ones))
			out = append(out, ip2region.Segment{Start: start, End: end})
		case strings.Contains(item, "-"):
			parts := strings.SplitN(item, "-", 2)
			start, err1 := ip2region.IPToUint32(strings.TrimSpace(parts[0]))
			end, err2 := ip2region.IPToUint32(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || end < start {
				return nil, fmt.Errorf("无效的 IP 区间: %s", item)
			}
			out = append(out, ip2region.Segment{Start: start, End: end})
		default:
			v, err := ip2region.IPToUint32(item)
			if err != nil {
				return nil, fmt.Errorf("无效的 IP: %s", item)
			}
			out = append(out, ip2region.Segment{Start: v, End: v})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("自定义 IP 段为空")
	}
	return out, nil
}

func randUint32In(rnd *rand.Rand, start, end uint32) uint32 {
	span := uint64(end) - uint64(start) + 1
	if span <= 1 {
		return start
	}
	return uint32(uint64(start) + uint64(rnd.Int63n(int64(span))))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

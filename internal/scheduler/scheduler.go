// Package scheduler 负责定时任务的调度：到点自动触发扫描或代理池验证任务。
package scheduler

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"proxyscanner/internal/event"
	"proxyscanner/internal/scanner"
	"proxyscanner/internal/store"
)

// Scheduler 定时器，内部使用 10 秒轮询判断触发时机。
type Scheduler struct {
	store *store.Store
	mgr   *scanner.Manager
	hub   *event.Hub

	mu     sync.Mutex
	stopCh chan struct{}
	running bool
}

// New 创建调度器。
func New(st *store.Store, mgr *scanner.Manager, hub *event.Hub) *Scheduler {
	return &Scheduler{store: st, mgr: mgr, hub: hub, stopCh: make(chan struct{})}
}

// Start 启动调度协程。
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.resync()
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-t.C:
				s.check()
			}
		}
	}()
}

// Stop 停止调度协程。
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false
	close(s.stopCh)
}

// resync 重新计算所有任务的下次触发时间（进程启动或配置变更后调用）。
//
// 核心原则：绝不在同步阶段把已启用任务的下次时间清零后保留启用状态（否则 check 会跳过它，
// 任务既不触发也无记录）。once 类型过期时显式保留 enabled=true 与 zero 时间，交由 check 立即触发。
func (s *Scheduler) resync() {
	list, err := s.store.ListSchedules()
	if err != nil {
		return
	}
	now := time.Now()
	for i := range list {
		x := list[i]
		if !x.Enabled {
			continue
		}
		if !x.NextRunAt.IsZero() {
			// 已有有效的下次时间：仅修正 interval 类型中已过期的情况（基于上次运行顺延）
			if x.Repeat == "interval" && now.After(x.NextRunAt) {
				base := x.LastRunAt
				if base.IsZero() {
					base = now
				}
				_ = s.store.SetScheduleNext(x.ID, ComputeNextRun(&x, base), true)
			}
			continue
		}
		// 未设置下次时间：新任务或 once 已过期
		next := ComputeNextRun(&x, now)
		if x.Repeat == "once" && next.IsZero() {
			// 一次性任务时间已过：保留启用并清零，check 会立即触发，触发后自动停用
			_ = s.store.SetScheduleNext(x.ID, time.Time{}, true)
			continue
		}
		_ = s.store.SetScheduleNext(x.ID, next, true)
	}
}

// Reload 外部变更任务后调用，重新同步。
func (s *Scheduler) Reload() { s.resync() }

// check 检查是否到点执行。
func (s *Scheduler) check() {
	list, err := s.store.ListSchedules()
	if err != nil {
		return
	}
	now := time.Now()
	for i := range list {
		x := list[i]
		if !x.Enabled {
			continue
		}
		due := false
		switch {
		case !x.NextRunAt.IsZero():
			due = !now.Before(x.NextRunAt)
		case x.Repeat == "once":
			// 一次性任务且时间已过期（next 被 resync 清零）：立即触发
			due = true
		default:
			// 其他类型但 next 为零：重新计算，本轮先跳过
			s.resync()
		}
		if due {
			s.trigger(x)
		}
	}
}

// trigger 触发一次任务。
func (s *Scheduler) trigger(x store.Schedule) {
	now := time.Now()
	switch x.Kind {
	case "verify":
		// 验证与扫描共用 begin，互斥，运行时稍后重试
		if s.mgr.IsRunning() {
			_ = s.store.SetScheduleNext(x.ID, now.Add(time.Minute), true)
			s.hub.Publish("log", map[string]any{
				"level": "warn",
				"msg":   fmt.Sprintf("定时任务「%s」到点但已有任务在运行，1 分钟后重试", x.Name),
			})
			return
		}
		if err := s.mgr.VerifyAll(nil); err != nil {
			s.hub.Publish("log", map[string]any{"level": "warn", "msg": fmt.Sprintf("定时任务「%s」触发失败: %v", x.Name, err)})
		} else {
			s.hub.Publish("log", map[string]any{"level": "info", "msg": fmt.Sprintf("定时任务「%s」触发代理池验证任务", x.Name)})
		}
	default:
		cfg := scanner.DefaultConfig()
		if strings.TrimSpace(x.Params) != "" {
			if err := json.Unmarshal([]byte(x.Params), &cfg); err != nil {
				s.hub.Publish("log", map[string]any{"level": "warn", "msg": fmt.Sprintf("定时任务「%s」扫描配置解析失败: %v", x.Name, err)})
				return
			}
		}
		cfg.TaskName = fmt.Sprintf("定时·%s", x.Name)
		cfg.PreserveDefaults = true // 定时任务不覆盖用户在界面上保存的默认配置
		if _, err := s.mgr.Enqueue(cfg); err != nil {
			s.hub.Publish("log", map[string]any{"level": "warn", "msg": fmt.Sprintf("定时任务「%s」入队失败: %v", x.Name, err)})
		} else {
			s.hub.Publish("log", map[string]any{"level": "info", "msg": fmt.Sprintf("定时任务「%s」已加入扫描队列", x.Name)})
		}
	}
	next := ComputeNextRun(&x, now)
	enabled := true
	if next.IsZero() {
		enabled = false // once 类型执行后自动停用
	}
	if err := s.store.MarkScheduleRun(x.ID, now, next, ""); err == nil && !enabled {
		_ = s.store.SetScheduleNext(x.ID, time.Time{}, false)
	}
	s.hub.Publish("schedule", map[string]any{"id": x.ID, "next": next})
}

// RunNow 立即执行一次（忽略下次触发时间）。
func (s *Scheduler) RunNow(id int64) error {
	list, err := s.store.ListSchedules()
	if err != nil {
		return err
	}
	for _, x := range list {
		if x.ID == id {
			s.trigger(x)
			return nil
		}
	}
	return fmt.Errorf("定时任务 %d 不存在", id)
}

// ComputeNextRun 依据重复规则计算下一次触发时间；返回零值表示不再执行。
func ComputeNextRun(x *store.Schedule, from time.Time) time.Time {
	switch x.Repeat {
	case "interval":
		min := x.IntervalMin
		if min < 1 {
			min = 60
		}
		return from.Add(time.Duration(min) * time.Minute)

	case "daily":
		h, m, ok := parseHHMM(x.RunTime)
		if !ok {
			return time.Time{}
		}
		n := time.Date(from.Year(), from.Month(), from.Day(), h, m, 0, 0, from.Location())
		if !n.After(from) {
			n = n.AddDate(0, 0, 1)
		}
		return n

	case "weekly":
		h, m, ok := parseHHMM(x.RunTime)
		if !ok {
			return time.Time{}
		}
		wd := int(x.Weekday)
		if wd < 0 || wd > 6 {
			wd = 1
		}
		n := time.Date(from.Year(), from.Month(), from.Day(), h, m, 0, 0, from.Location())
		delta := (wd - int(n.Weekday()) + 7) % 7
		if delta == 0 && !n.After(from) {
			delta = 7
		}
		return n.AddDate(0, 0, delta)

	case "once":
		t, ok := parseDateTime(x.RunTime)
		if !ok {
			return time.Time{}
		}
		if t.After(from) {
			return t
		}
		return time.Time{}

	default:
		return time.Time{}
	}
}

func parseHHMM(v string) (int, int, bool) {
	v = strings.TrimSpace(v)
	t, err := time.ParseInLocation("15:04", v, time.Local)
	if err != nil {
		// 兼容 HH:MM:SS
		if t2, err2 := time.ParseInLocation("15:04:05", v, time.Local); err2 == nil {
			return t2.Hour(), t2.Minute(), true
		}
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

func parseDateTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	layouts := []string{"2006-01-02 15:04", "2006-01-02 15:04:05", time.RFC3339}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, v, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

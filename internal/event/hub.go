// Package event 提供简单的发布订阅总线，用于向 Web 控制台推送实时事件(SSE)。
package event

import (
	"sync"
	"time"
)

// Event 一次推送。
type Event struct {
	Type string `json:"type"`
	Time int64  `json:"time"`
	Data any    `json:"data"`
}

// Hub 事件总线。
type Hub struct {
	mu    sync.Mutex
	subs  map[chan Event]struct{}
	seq   int
	recent []Event // 最近日志的环形缓冲，供 /api/logs 拉取
}

// NewHub 创建事件总线。
func NewHub() *Hub {
	return &Hub{subs: map[chan Event]struct{}{}, recent: make([]Event, 0, 256)}
}

// Subscribe 订阅事件（返回缓冲为 64 的通道）。
func (h *Hub) Subscribe() chan Event {
	ch := make(chan Event, 128)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.seq++
	h.mu.Unlock()
	return ch
}

// Unsubscribe 取消订阅。
func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
}

// Publish 广播事件，不阻塞。
func (h *Hub) Publish(typ string, data any) {
	ev := Event{Type: typ, Time: time.Now().UnixMilli(), Data: data}
	h.mu.Lock()
	defer h.mu.Unlock()
	// 仅保留 log/scan 类事件到历史缓冲，避免无限增长
	if typ == "log" || typ == "found" || typ == "schedule" || typ == "done" {
		h.recent = append(h.recent, ev)
		if len(h.recent) > 256 {
			h.recent = h.recent[len(h.recent)-256:]
		}
	}
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
			// 订阅者消费过慢时丢弃，避免阻塞扫描线程
		}
	}
}

// RecentLogs 返回最近的历史日志（最多 n 条，n<=0 表示全部）。
func (h *Hub) RecentLogs(n int) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Event, len(h.recent))
	copy(out, h.recent)
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// Subscribers 当前订阅数量。
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

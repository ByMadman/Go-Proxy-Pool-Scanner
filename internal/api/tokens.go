package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxyscanner/internal/store"
)

// parseExpiry 解析令牌过期时间，支持多种常见格式。
func parseExpiry(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
		time.RFC3339,
		"2006/01/02 15:04:05",
		"2006/01/02 15:04",
	}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// GET /api/tokens  列出全部提取令牌（需管理员登录）。
func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListTokens()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, list)
}

// POST /api/tokens  {name, expiresAt, count, maxTotal}  新建提取令牌。
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	username, _ := s.authUser(r)
	var req struct {
		Name      string `json:"name"`
		ExpiresAt string `json:"expiresAt"`
		Count     int    `json:"count"`
		MaxTotal  int    `json:"maxTotal"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	exp, ok := parseExpiry(req.ExpiresAt)
	if !ok {
		writeErr(w, 400, "过期时间格式无效，示例：2026-12-31 23:59:59")
		return
	}
	if req.Count < 0 {
		req.Count = 0
	}
	if req.MaxTotal < 0 {
		req.MaxTotal = 0
	}
	val, err := s.store.CreateToken(req.Name, username, exp, req.Count, req.MaxTotal)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, map[string]any{"token": val, "expiresAt": exp.Format(time.RFC3339), "count": req.Count, "maxTotal": req.MaxTotal})
}

// DELETE /api/tokens/{id}  删除（吊销）令牌。
func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	if err := s.store.DeleteToken(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, true)
}

// POST /api/tokens/{id}/toggle  {enabled}  启停令牌。
func (s *Server) handleToggleToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "无效 ID")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.store.SetTokenEnabled(id, req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeOK(w, true)
}

// GET /api/proxies/extract?token=px_xxx&format=txt|json&https=1&anon=&country=&protocol=&minLevel=&maxLatency=
// 凭提取令牌返回代理：返回数量受令牌「单次数量」限制（count<=0 表示单次不限），且受累计额度与过期时间约束。
func (s *Server) handleExtract(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		writeErr(w, 401, "缺少提取令牌（?token=）")
		return
	}
	tk, ok, err := s.store.GetTokenByValue(raw)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !ok {
		writeErr(w, 401, "令牌无效")
		return
	}
	if tk.Enabled != 1 {
		writeErr(w, 401, "令牌已被停用")
		return
	}
	if time.Now().After(tk.ExpiresAt) {
		writeErr(w, 401, "令牌已过期")
		return
	}
	if tk.MaxTotal > 0 && tk.Used >= tk.MaxTotal {
		writeErr(w, 401, "令牌提取额度已用尽")
		return
	}

	q := r.URL.Query()
	format := strings.ToLower(q.Get("format"))
	if format == "" {
		format = "txt"
	}

	// 本次返回数量：令牌单次上限（count<=0 表示单次不限）与客户端 size 取小，再受累计额度约束
	unlimited := tk.Count <= 0
	capN := tk.Count
	if sz := atoiDef(q.Get("size"), 0); sz > 0 && (unlimited || sz < capN) {
		capN = sz
	}
	if tk.MaxTotal > 0 {
		if remain := tk.MaxTotal - tk.Used; unlimited || remain < capN {
			capN = remain
			unlimited = false
		}
	}
	if capN < 0 {
		capN = 0
	}

	// 与列表/导出接口一致：把中文国家/省份名展开成库里的英文原文别名。
	var cs, ps []string
	if v := strings.TrimSpace(q.Get("country")); v != "" {
		cs = append(cs, v)
	}
	if v := strings.TrimSpace(q.Get("province")); v != "" {
		ps = append(ps, v)
	}
	countryIn := s.xdb.ExpandCountryFilter(cs)
	provIn := s.xdb.ExpandProvinceFilter(countryIn, ps)
	qy := store.ProxyQuery{
		Page:       1,
		Size:       capN,
		Country:    q.Get("country"),
		Countries:  countryIn,
		Province:   q.Get("province"),
		Provinces:  provIn,
		City:       q.Get("city"),
		District:   q.Get("district"),
		Keyword:    q.Get("keyword"),
		Protocol:   q.Get("protocol"),
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

	var list []store.Proxy
	if unlimited {
		list, err = s.store.ListProxiesAll(qy, 0)
	} else {
		var all []store.Proxy
		all, _, err = s.store.ListProxies(qy)
		list = all
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 累计额度扣减
	if len(list) > 0 {
		_ = s.store.AddTokenUsed(tk.ID, len(list))
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(list)
	default: // txt: 每行 ip:port
		var b strings.Builder
		for _, p := range list {
			b.WriteString(p.IP)
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(p.Port))
			b.WriteByte('\n')
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Proxy-Count", strconv.Itoa(len(list)))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(b.String()))
	}
}

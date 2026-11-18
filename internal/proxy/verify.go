// Package proxy 实现代理可用性验证与匿名等级判定。
//
// 判定原理：
//  1. 通过代理向「回显站点」发起 HTTP 请求，回显站点会把服务端收到的请求头原样返回；
//  2. 若回显里出现 X-Forwarded-For / X-Real-IP 且包含本机公网 IP -> 透明代理；
//  3. 若出现 Via / Proxy-Connection / Forwarded 等代理痕迹但未泄露真实 IP -> 普通匿名；
//  4. 完全没有代理痕迹 -> 高匿名（Elite）；
//  5. 再通过 CONNECT 隧道握手验证代理是否支持 HTTPS。
package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 匿名等级常量（与 store 包保持一致）。
const (
	AnonymityUnknown     = 0 // 未判定（回显站点未提供请求头）
	AnonymityTransparent = 1 // 透明：泄露真实 IP
	AnonymityAnonymous   = 2 // 普通匿名：带 Via/Proxy 头
	AnonymityElite       = 3 // 高匿名：无任何代理痕迹
)

// AnonymityText 返回匿名等级名称。
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

// EchoServer 回显目标站点。
//   - headers: 服务端回显接收到的请求头（如 httpbin/get），据此判定匿名等级
//   - ip:      只回显出口 IP（如 ipify），只能验证可用性
//   - connect: 任意可访问站点，仅做连通性测试
type EchoServer struct {
	URL  string `json:"url"`
	Kind string `json:"kind"`
	Note string `json:"note"`
}

// DefaultEchoServers 默认回显站点。
func DefaultEchoServers() []EchoServer {
	return []EchoServer{
		{URL: "http://httpbin.org/get", Kind: "headers", Note: "回显请求头，可判定匿名等级"},
		{URL: "https://httpbin.org/get", Kind: "headers", Note: "HTTPS 回显，同时验证 CONNECT"},
		{URL: "http://postman-echo.com/get", Kind: "headers", Note: "备用回显"},
		{URL: "https://postman-echo.com/get", Kind: "headers", Note: "HTTPS 备用回显"},
		{URL: "http://api.ipify.org?format=json", Kind: "ip", Note: "仅回显出口 IP"},
		{URL: "https://api.ipify.org?format=json", Kind: "ip", Note: "仅回显出口 IP"},
		{URL: "http://ip-api.com/json/", Kind: "ip", Note: "回显出口 IP 与归属地"},
		{URL: "http://myip.ipip.net", Kind: "ip", Note: "文本出口 IP"},
		{URL: "https://www.taobao.com/help/getip.php", Kind: "ip", Note: "文本出口 IP"},
		{URL: "http://www.baidu.com", Kind: "connect", Note: "连通性兜底"},
		{URL: "https://www.baidu.com", Kind: "connect", Note: "HTTPS 连通性兜底"},
	}
}

// DefaultHTTPSTargets 用于验证 CONNECT 隧道的目标站点。
func DefaultHTTPSTargets() []string {
	return []string{
		"https://httpbin.org/get",
		"https://api.ipify.org?format=json",
		"https://www.baidu.com",
		"https://www.qq.com",
	}
}

// DurationMs 以「毫秒」为单位与外部交互的时长类型，避免 time.Duration 序列化为纳秒造成单位错乱。
type DurationMs int64

// Duration 转成 time.Duration。
func (d DurationMs) Duration() time.Duration { return time.Duration(d) * time.Millisecond }

// msOr 保证至少为 minimum 毫秒。
func msOr(v DurationMs, minimum DurationMs) DurationMs {
	if v <= 0 {
		return minimum
	}
	return v
}

// Option 验证参数。
type Option struct {
	DialTimeout    DurationMs   `json:"dialTimeout"`
	TotalTimeout   DurationMs   `json:"totalTimeout"`
	MaxBodySize    int64        `json:"maxBodySize"`
	UserAgent      string       `json:"userAgent"`
	EchoServers    []EchoServer `json:"echoServers"`
	HTTPSTargets   []string     `json:"httpsTargets"`
	PublicIP       string       `json:"publicIp"`
	MaxHeaderTries int          `json:"maxHeaderTries"`
	MaxIPTries     int          `json:"maxIpTries"`
	MaxHTTPSTries  int          `json:"maxHttpsTries"`
	// ConcurrencyHint 仅用于「一键验证」时的并发参考值，由扫描配置写入。
	ConcurrencyHint int `json:"concurrencyHint"`
}

// DefaultOption 返回默认验证参数。
func DefaultOption() Option {
	return Option{
		DialTimeout:    4000,
		TotalTimeout:   8000,
		MaxBodySize:    64 * 1024,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
		EchoServers:    DefaultEchoServers(),
		HTTPSTargets:   DefaultHTTPSTargets(),
		MaxHeaderTries: 3,
		MaxIPTries:     2,
		MaxHTTPSTries:  2,
	}
}

// Result 一次验证的结果。
type Result struct {
	OK        bool   `json:"ok"`
	HTTPOK    bool   `json:"httpOk"`
	HTTPSOK   bool   `json:"httpsOk"`
	Anonymity int    `json:"anonymity"`
	Latency   int    `json:"latency"`
	ExitIP    string `json:"exitIp"`
	Detail    string `json:"detail"`
	Error     string `json:"error"`
}

// 可能导致代理身份泄露的请求头。
var leakHeaders = map[string]bool{
	"x-forwarded-for":     true,
	"x-real-ip":           true,
	"x-forwarded":         true,
	"forwarded":           true,
	"client-ip":           true,
	"x-client-ip":         true,
	"x-originating-ip":    true,
	"x-remote-ip":         true,
	"x-remote-addr":       true,
	"proxy-connection":    true,
	"proxy-authorization": true,
	"proxy-authenticate":  true,
	"proxy-agent":         true,
	"via":                 true,
	"x-proxy-id":          true,
	"x-proxy-user-ip":     true,
	"x-via":               true,
}

// realIPHeaders 若其中出现本机真实 IP，则判定为透明代理。
var realIPHeaders = []string{
	"x-forwarded-for", "x-real-ip", "forwarded", "client-ip", "x-client-ip",
	"x-originating-ip", "x-remote-ip", "x-remote-addr", "x-proxy-user-ip",
}

var ipv4Re = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)

// Verifier 验证器，内部维护「最近可用回显站点」热度表以加快验证。
type Verifier struct {
	mu   sync.RWMutex
	opt  Option
	good map[string]time.Time
}

// NewVerifier 创建验证器。
func NewVerifier(opt Option) *Verifier {
	o := normalize(opt)
	return &Verifier{opt: o, good: map[string]time.Time{}}
}

func normalize(o Option) Option {
	if o.MaxBodySize <= 0 {
		o.MaxBodySize = 64 * 1024
	}
	if o.MaxHeaderTries <= 0 {
		o.MaxHeaderTries = 3
	}
	if o.MaxIPTries <= 0 {
		o.MaxIPTries = 2
	}
	if o.MaxHTTPSTries <= 0 {
		o.MaxHTTPSTries = 2
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 4000
	}
	if o.TotalTimeout <= 0 {
		o.TotalTimeout = 8000
	}
	if len(o.EchoServers) == 0 {
		o.EchoServers = DefaultEchoServers()
	}
	if len(o.HTTPSTargets) == 0 {
		o.HTTPSTargets = DefaultHTTPSTargets()
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultOption().UserAgent
	}
	return o
}

// Option 返回当前参数副本。
func (v *Verifier) Option() Option {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.opt
}

// SetOption 更新参数。
func (v *Verifier) SetOption(o Option) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.opt = normalize(o)
}

func (v *Verifier) markGood(u string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.good[u] = time.Now()
}

// ordered 按热度排序候选站点。
func (v *Verifier) ordered(wantKind string) []EchoServer {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []EchoServer
	for _, e := range v.opt.EchoServers {
		if strings.EqualFold(e.Kind, wantKind) {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, oki := v.good[out[i].URL]
		tj, okj := v.good[out[j].URL]
		if oki && okj {
			return ti.After(tj)
		}
		return oki && !okj
	})
	return out
}

// httpHTTPSVariants 返回原 URL 与「另一协议」版本（http<->https，同 host:port），
// 让一个回显站点同时覆盖明文代理与只支持 CONNECT 隧道的代理。
func httpHTTPSVariants(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return []string{raw}
	}
	alt := *u
	if alt.Scheme == "https" {
		alt.Scheme = "http"
	} else {
		alt.Scheme = "https"
	}
	altStr := alt.String()
	if altStr == raw {
		return []string{raw}
	}
	return []string{raw, altStr}
}

// Verify 完整验证一个 ip:port。
func (v *Verifier) Verify(ip string, port int) Result {
	opt := v.Option()
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	var res Result
	var httpsProven bool

	// 0. TCP 预检：端口不通就直接失败，避免对不可达目标反复尝试多个回显站点。
	// 随机扫描时绝大多数候选端口是关闭/被丢弃的，此步可把单候选耗时从 ~10s 降到 ~1.5s。
	if c, err := dial(addr, opt); err != nil {
		res.Error = trimError(err)
		return res
	} else {
		_ = c.Close()
	}

	// 1. 优先使用可回显请求头的站点，籍此判定匿名等级
	tries := 0
	for _, e := range v.ordered("headers") {
		for _, u := range httpHTTPSVariants(e.URL) {
			if tries >= opt.MaxHeaderTries {
				break
			}
			tries++
			r := v.request(addr, u, opt)
			if !r.ok || !r.verified {
				if res.Error == "" {
					if r.ok {
						res.Error = "响应不含回显内容（疑似非代理）"
					} else {
						res.Error = r.err
					}
				}
				continue
			}
			v.markGood(u)
			res.OK, res.HTTPOK = true, true
			res.Latency, res.ExitIP, res.Anonymity = r.ms, r.exitIP, r.level
			res.Detail = strings.Join(r.reasons, "; ")
			res.Error = ""
			if r.isHTTPS {
				res.HTTPSOK = true
				httpsProven = true
			}
			break
		}
		if res.OK {
			break
		}
	}

	// 2. 退化为 IP 回显站点（匿名等级未知）
	if !res.OK {
		tries = 0
		for _, e := range v.ordered("ip") {
			if tries >= opt.MaxIPTries {
				break
			}
			tries++
			r := v.request(addr, e.URL, opt)
			if !r.ok || r.exitIP == "" {
				if res.Error == "" {
					if r.ok {
						res.Error = "响应不含出口 IP（疑似非代理）"
					} else {
						res.Error = r.err
					}
				}
				continue
			}
			v.markGood(e.URL)
			res.OK, res.HTTPOK = true, true
			res.Latency, res.ExitIP, res.Anonymity = r.ms, r.exitIP, AnonymityUnknown
			res.Detail = "回显站点未提供请求头，匿名等级未知"
			res.Error = ""
			if r.isHTTPS {
				res.HTTPSOK = true
				httpsProven = true
			}
			break
		}
	}

	// 3. 不再使用「仅连通性」兜底：普通 Web 服务对任意绝对 URI 都回 200，
	// 仅凭状态码无法区分真假代理，会把大量 Akamai/CDN 端口误判为可用代理
	// （表现为匿名未知、出口 IP 为空、延迟整齐）。只有 headers 或 IP 回显站点
	// 真正返回了内容，才算验证通过。

	if !res.OK {
		if res.Error == "" {
			res.Error = "连接失败或超时"
		}
		return res
	}

	// 4. HTTPS(CONNECT) 能力验证
	if !httpsProven {
		for i, target := range opt.HTTPSTargets {
			if i >= opt.MaxHTTPSTries {
				break
			}
			if err := v.connectTunnel(addr, target, opt); err == nil {
				res.HTTPSOK = true
				break
			}
		}
	}
	return res
}

type rawResponse struct {
	ok       bool
	verified bool // 响应体里确实回显了请求头或出口 IP，说明真的经过代理
	ms       int
	exitIP   string
	level    int
	reasons  []string
	isHTTPS  bool
	err      string
}

// request 通过代理访问目标 URL（HTTP 走绝对 URI，HTTPS 走 CONNECT 隧道）。
func (v *Verifier) request(proxyAddr, target string, opt Option) rawResponse {
	var out rawResponse
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		out.err = "目标地址非法"
		return out
	}
	if strings.EqualFold(u.Scheme, "https") {
		out.isHTTPS = true
		ms, body, err := v.tunnelGet(proxyAddr, u, opt)
		if err != nil {
			out.err = trimError(err)
			return out
		}
		out.ok = true
		out.ms = ms
		finish(&out, string(body), opt)
		return out
	}

	start := time.Now()
	conn, err := dial(proxyAddr, opt)
	if err != nil {
		out.err = trimError(err)
		return out
	}
	defer conn.Close()
	req := buildProxyGET(u, opt)
	if _, err := conn.Write([]byte(req)); err != nil {
		out.err = "写入请求失败"
		return out
	}
	status, _, body, err := readResponse(conn, opt.TotalTimeout.Duration(), opt.MaxBodySize)
	if err != nil {
		out.err = trimError(err)
		return out
	}
	out.ms = int(time.Since(start).Milliseconds())
	if status >= 400 {
		out.err = fmt.Sprintf("目标返回 %d", status)
		return out
	}
	out.ok = true
	finish(&out, string(body), opt)
	return out
}

func finish(out *rawResponse, body string, opt Option) {
	if ip, ok := extractIPFromJSON(body); ok {
		out.exitIP = ip
	} else if m := ipv4Re.FindString(body); m != "" && isPublicIPv4(m) {
		out.exitIP = m
	}
	if headers, ok := extractHeadersFromJSON(body); ok {
		out.level, out.reasons = judge(mapToHeader(headers), opt.PublicIP)
		out.verified = true
	} else if h := extractHeadersFromText(body); len(h) > 0 {
		out.level, out.reasons = judge(h, opt.PublicIP)
		out.verified = true
	} else {
		out.level = AnonymityUnknown
	}
	if out.exitIP != "" {
		out.verified = true
	}
}

// tunnelGet 通过 CONNECT 隧道完成 TLS 握手并取回响应体。
func (v *Verifier) tunnelGet(proxyAddr string, u *url.URL, opt Option) (int, []byte, error) {
	total := opt.TotalTimeout.Duration()
	conn, err := dial(proxyAddr, opt)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	connReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: close\r\n\r\n", host, host)
	if err := writeAll(conn, connReq, total); err != nil {
		return 0, nil, fmt.Errorf("CONNECT 写入失败")
	}
	status, _, _, err := readResponseHeader(conn, total)
	if err != nil {
		return 0, nil, fmt.Errorf("CONNECT 失败")
	}
	if status != 200 {
		return 0, nil, fmt.Errorf("CONNECT 返回 %d", status)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	tlsConn.SetDeadline(time.Now().Add(total))
	if err := tlsConn.Handshake(); err != nil {
		return 0, nil, fmt.Errorf("TLS 握手失败")
	}
	start := time.Now()
	if err := writeAll(tlsConn, buildOriginGET(u, opt), total); err != nil {
		return 0, nil, fmt.Errorf("HTTPS 请求写入失败")
	}
	st, _, body, err := readResponse(tlsConn, total, opt.MaxBodySize)
	if err != nil {
		return 0, nil, fmt.Errorf("HTTPS 响应读取失败")
	}
	ms := int(time.Since(start).Milliseconds())
	if st >= 400 {
		return ms, nil, fmt.Errorf("目标返回 %d", st)
	}
	return ms, body, nil
}

// connectTunnel 仅做 CONNECT + TLS 握手，用于验证 HTTPS 支持能力。
func (v *Verifier) connectTunnel(proxyAddr, target string, opt Option) error {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return fmt.Errorf("目标地址非法")
	}
	conn, err := dial(proxyAddr, opt)
	if err != nil {
		return err
	}
	defer conn.Close()
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: close\r\n\r\n", host, host)
	if err := writeAll(conn, req, opt.DialTimeout.Duration()); err != nil {
		return err
	}
	status, _, _, err := readResponseHeader(conn, opt.TotalTimeout.Duration())
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("CONNECT 返回 %d", status)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	tlsConn.SetDeadline(time.Now().Add(opt.TotalTimeout.Duration()))
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS 握手失败")
	}
	return nil
}

func dial(addr string, opt Option) (net.Conn, error) {
	d := net.Dialer{Timeout: opt.DialTimeout.Duration()}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	c.SetDeadline(time.Now().Add(opt.TotalTimeout.Duration()))
	return c, nil
}

func writeAll(c net.Conn, s string, timeout time.Duration) error {
	c.SetDeadline(time.Now().Add(timeout))
	_, err := c.Write([]byte(s))
	return err
}

func buildProxyGET(u *url.URL, opt Option) string {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("GET %s://%s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
		u.Scheme, u.Host, path, u.Host, opt.UserAgent)
}

func buildOriginGET(u *url.URL, opt Option) string {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
		path, u.Host, opt.UserAgent)
}

// readResponse 读取完整响应（含 chunked 解码）。
func readResponse(r io.Reader, timeout time.Duration, maxBody int64) (int, http.Header, []byte, error) {
	reader := bufio.NewReaderSize(r, 8192)
	if deadline, ok := r.(net.Conn); ok {
		deadline.SetDeadline(time.Now().Add(timeout))
	}
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxBody)
	if err != nil && err != io.EOF {
		return resp.StatusCode, resp.Header, body, nil
	}
	return resp.StatusCode, resp.Header, body, nil
}

// readResponseHeader 只读取响应头（用于 CONNECT）。
func readResponseHeader(r io.Reader, timeout time.Duration) (int, http.Header, []byte, error) {
	if c, ok := r.(net.Conn); ok {
		c.SetDeadline(time.Now().Add(timeout))
	}
	reader := bufio.NewReaderSize(r, 4096)
	tp := textproto.NewReader(reader)
	line, err := tp.ReadLine()
	if err != nil {
		return 0, nil, nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	status := 0
	if len(parts) >= 2 {
		status, _ = strconv.Atoi(parts[1])
	}
	// 跳过头部
	for {
		l, err := tp.ReadLine()
		if err != nil {
			return status, nil, nil, nil
		}
		if l == "" {
			break
		}
	}
	return status, nil, nil, nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		max = 64 * 1024
	}
	var buf []byte
	tmp := make([]byte, 4096)
	var total int64
	for total < max {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			total += int64(n)
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, io.EOF
}

// judge 依据回显请求头判定匿名等级。
func judge(headers http.Header, publicIP string) (int, []string) {
	reasons := make([]string, 0, 4)
	level := AnonymityElite
	lower := http.Header{}
	for k, vs := range headers {
		lower[strings.ToLower(k)] = vs
	}
	for _, name := range realIPHeaders {
		vals, ok := lower[name]
		if !ok {
			continue
		}
		joined := strings.Join(vals, ",")
		reasons = append(reasons, fmt.Sprintf("%s=%s", name, joined))
		if publicIP != "" && strings.Contains(joined, publicIP) {
			level = AnonymityTransparent
		} else if level > AnonymityAnonymous {
			level = AnonymityAnonymous
		}
	}
	for name, vals := range lower {
		if !leakHeaders[name] || alreadyContains(reasons, name) {
			continue
		}
		reasons = append(reasons, fmt.Sprintf("%s=%s", name, strings.Join(vals, ",")))
		if level > AnonymityAnonymous {
			level = AnonymityAnonymous
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "未泄露 X-Forwarded-For / Via 等代理头")
	}
	return level, reasons
}

func alreadyContains(reasons []string, name string) bool {
	for _, r := range reasons {
		if strings.Contains(strings.ToLower(r), strings.ToLower(name)) {
			return true
		}
	}
	return false
}

func mapToHeader(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

// extractHeadersFromJSON 递归查找 JSON 中的 headers 对象。
func extractHeadersFromJSON(text string) (map[string]string, bool) {
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return nil, false
	}
	m := findHeaders(v)
	return m, m != nil
}

func findHeaders(v any) map[string]string {
	switch node := v.(type) {
	case map[string]any:
		if h, ok := node["headers"]; ok {
			if m, ok := toStringMap(h); ok && len(m) > 0 {
				return m
			}
		}
		for _, child := range node {
			if m := findHeaders(child); m != nil {
				return m
			}
		}
	case []any:
		for _, child := range node {
			if m := findHeaders(child); m != nil {
				return m
			}
		}
	}
	return nil
}

func toStringMap(v any) (map[string]string, bool) {
	switch node := v.(type) {
	case map[string]any:
		out := make(map[string]string, len(node))
		for k, val := range node {
			out[k] = fmt.Sprint(val)
		}
		return out, true
	case []any:
		out := map[string]string{}
		for _, item := range node {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			value, _ := m["value"].(string)
			if name == "" {
				name, _ = m["key"].(string)
			}
			if name != "" {
				out[name] = value
			}
		}
		if len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// extractIPFromJSON 从 JSON 中提取出口 IP（origin/ip/query 等字段）。
func extractIPFromJSON(text string) (string, bool) {
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		return "", false
	}
	keys := []string{"origin", "ip", "query", "ipaddress", "client_ip", "remote_addr", "cip"}
	found := ""
	walk(v, func(key string, val any) {
		if found != "" {
			return
		}
		for _, k := range keys {
			if !strings.EqualFold(key, k) {
				continue
			}
			if s, ok := val.(string); ok {
				if m := ipv4Re.FindString(s); m != "" && isPublicIPv4(m) {
					found = m
					return
				}
			}
		}
	})
	return found, found != ""
}

func walk(v any, fn func(key string, val any)) {
	switch node := v.(type) {
	case map[string]any:
		for k, val := range node {
			fn(k, val)
			walk(val, fn)
		}
	case []any:
		for _, val := range node {
			walk(val, fn)
		}
	}
}

var headerLineRe = regexp.MustCompile(`(?i)^"?([a-z0-9\-]+)"?\s*[:=]\s*(.+)$`)

// extractHeadersFromText 从纯文本回显中提取疑似请求头。
func extractHeadersFromText(text string) http.Header {
	h := http.Header{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || len(line) > 300 {
			continue
		}
		m := headerLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		if name == "date" || name == "content-type" || name == "content-length" || name == "server" {
			continue
		}
		if leakHeaders[name] {
			h.Add(m[1], strings.TrimSpace(strings.Trim(m[2], `",'`)))
		}
	}
	return h
}

func isPublicIPv4(ip string) bool {
	v := net.ParseIP(ip)
	if v == nil || v.To4() == nil {
		return false
	}
	if v.IsLoopback() || v.IsPrivate() || v.IsLinkLocalUnicast() || v.IsLinkLocalMulticast() ||
		v.IsMulticast() || v.IsUnspecified() {
		return false
	}
	if strings.HasPrefix(ip, "0.") {
		return false
	}
	return true
}

func trimError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

// PublicIP 直连检测本机真实出口 IP（用于识别透明代理）。
func PublicIP(timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	targets := []string{
		"https://api.ipify.org?format=json",
		"http://api.ipify.org?format=json",
		"http://ip-api.com/json/",
		"http://myip.ipip.net",
		"https://www.taobao.com/help/getip.php",
	}
	client := &http.Client{Timeout: timeout}
	for _, t := range targets {
		req, err := http.NewRequest(http.MethodGet, t, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", DefaultOption().UserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		text := string(body)
		if ip, ok := extractIPFromJSON(text); ok {
			return ip
		}
		if m := ipv4Re.FindString(text); m != "" && isPublicIPv4(m) {
			return m
		}
	}
	return ""
}

// selftest 在本地起一个回显服务与三种不同匿名度的代理，
// 用来验证 proxy 包的可用性验证与匿名等级判定是否符合预期（无需外网）。
//
// 用法: go run ./cmd/selftest
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	px "proxyscanner/internal/proxy"
)

const fakePublicIP = "203.0.113.9"

// serve 模式：只启动本地服务与代理，便于手工调试（代理 19101 高匿 / 19102 普通匿名 / 19103 透明）。
var serveMode bool

func main() {
	flagServe := os.Getenv("SELFSERVE") != "" || len(os.Args) > 1 && os.Args[1] == "-serve"
	serveMode = flagServe
	echoPort, tlsPort, proxyPorts := 19111, 19112, []int{19101, 19102, 19103}

	// 1. 回显服务
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := map[string]string{}
		for k, v := range r.Header {
			headers[k] = strings.Join(v, ",")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"headers": headers,
			"origin":  r.RemoteAddr,
			"url":     r.URL.String(),
		})
	})
	httpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		fatal(err)
	}
	go func() { _ = http.Serve(httpLn, mux) }()

	// HTTPS 回显（自签证书）
	cert := issueCert()
	tlsLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort))
	if err != nil {
		fatal(err)
	}
	tlsLn = tls.NewListener(tlsLn, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() { _ = http.Serve(tlsLn, mux) }()

	// 2. 三种代理
	modes := map[int]string{19101: "elite", 19102: "anonymous", 19103: "transparent"}
	for port, mode := range modes {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			fatal(err)
		}
		m := mode
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go handleProxy(c, m)
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)

	if serveMode {
		fmt.Println("本地回显 http://127.0.0.1:19111/get  https://127.0.0.1:19112/get")
		fmt.Println("代理: 19101=高匿名 19102=普通匿名(Via) 19103=透明(X-Forwarded-For)")
		fmt.Println("按 Ctrl+C 退出")
		select {}
	}

	// 3. 验证
	opt := px.DefaultOption()
	opt.DialTimeout = 3000
	opt.TotalTimeout = 5000
	opt.PublicIP = fakePublicIP
	opt.EchoServers = []px.EchoServer{
		{URL: fmt.Sprintf("http://127.0.0.1:%d/get", echoPort), Kind: "headers"},
		{URL: fmt.Sprintf("https://127.0.0.1:%d/get", tlsPort), Kind: "headers"},
	}
	opt.HTTPSTargets = []string{fmt.Sprintf("https://127.0.0.1:%d/get", tlsPort)}
	vf := px.NewVerifier(opt)

	fmt.Println("本地验证（越接近实际情况越可信）:")
	fmt.Printf("%-16s %-14s %-6s %-8s %-10s %s\n", "代理", "期望", "可用", "HTTPS", "延迟", "判定明细")
	expects := map[int]string{19101: "高匿名(3)", 19102: "普通匿名(2)", 19103: "透明(1)"}
	pass := true
	for _, port := range proxyPorts {
		res := vf.Verify("127.0.0.1", port)
		ok := "是"
		if !res.OK {
			ok = "否"
		}
		httpsOK := "否"
		if res.HTTPSOK {
			httpsOK = "是"
		}
		got := px.AnonymityText(res.Anonymity)
		want := map[int]int{19101: px.AnonymityElite, 19102: px.AnonymityAnonymous, 19103: px.AnonymityTransparent}[port]
		if res.Anonymity != want || !res.OK || !res.HTTPSOK {
			pass = false
		}
		fmt.Printf("%-16s %-14s %-6s %-8s %-10s %s (等级=%d, 出口=%s)\n",
			fmt.Sprintf("127.0.0.1:%d", port), expects[port], ok, httpsOK, fmt.Sprintf("%dms", res.Latency), res.Detail, res.Anonymity, res.ExitIP)
		_ = got
	}

	// 4. 不存在的代理应当验证失败
	res := vf.Verify("127.0.0.1", 19999)
	fmt.Printf("\n无效代理 127.0.0.1:19999 => ok=%v err=%s\n", res.OK, res.Error)
	if res.OK {
		pass = false
	}

	if pass {
		fmt.Println("\n自检通过 ✓")
		return
	}
	fmt.Println("\n自检未通过 ✗")
	os.Exit(1)
}

// handleProxy 处理绝对 URI 的 GET 与 CONNECT 隧道。
func handleProxy(c net.Conn, mode string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	br := newBufReader(c)
	line, err := readLine(br)
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	method, target := parts[0], parts[1]

	// 读取剩余请求头
	headers := map[string][]string{}
	for {
		l, err := readLine(br)
		if err != nil {
			return
		}
		if l == "" {
			break
		}
		kv := strings.SplitN(l, ":", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		headers[name] = append(headers[name], strings.TrimSpace(kv[1]))
	}

	if strings.EqualFold(method, "CONNECT") {
		up, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer up.Close()
		up.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		go func() { _, _ = io.Copy(up, c); up.Close() }()
		_, _ = io.Copy(c, up)
		return
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	host := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
	host = strings.SplitN(host, "/", 2)[0]
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	path := "/"
	if idx := strings.Index(target[7:], "/"); idx >= 0 {
		path = target[7+idx:]
	}
	up, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()
	up.SetDeadline(time.Now().Add(8 * time.Second))

	out := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host)
	for k, vs := range headers {
		// Host / Connection 由本行下方统一生成，重复会导致目标站返回 400
		if strings.EqualFold(k, "Proxy-Connection") || strings.EqualFold(k, "Host") ||
			strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Proxy-Authenticate") {
			continue
		}
		for _, v := range vs {
			out += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	switch mode {
	case "transparent":
		out += "X-Forwarded-For: " + fakePublicIP + "\r\n"
	case "anonymous":
		out += "Via: 1.1 selftest-proxy\r\n"
	}
	out += "Connection: close\r\n\r\n"
	if os.Getenv("PROXYDBG") != "" {
		fmt.Printf("[proxy:%s] -> %s\n", mode, strings.ReplaceAll(out, "\r\n", "|"))
	}
	if _, err := up.Write([]byte(out)); err != nil {
		return
	}
	_, _ = io.Copy(c, up)
}

func newBufReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 8192) }

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func issueCert() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fatal(err)
	}
	return cert
}

func fatal(err error) {
	fmt.Println("启动失败:", err)
	os.Exit(1)
}

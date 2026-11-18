// echosrv 是 proxy 项目的独立「回显服务」，用于代理匿名等级判定。
//
// 它把收到的 HTTP 请求头、来源 IP、URL 以 JSON 原样返回，等价于 httpbin.org/get，
// 但部署在你自己的服务器上（最好在国内可达节点），出口代理能稳定访问，
// 从而避免默认 httpbin.org 等境外站点不可达导致大量代理被判为「未知」。
//
// 用法:
//   go run ./cmd/echosrv -addr :8849 -path /get
//   # 带 TLS（与明文同端口双协议；验证器 InsecureSkipVerify，自签证书即可）:
//   go run ./cmd/echosrv -addr :8849 -path /get -cert cert.pem -key key.pem
//
// 验证器配置（「参数配置 → 验证站点」）新增一行即可（http/https 验证器会自动双试）：
//   URL = http://你的IP:8849/get   类型 = headers
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	addr = flag.String("addr", ":8849", "监听地址，如 :8849 或 127.0.0.1:8849")
	cert = flag.String("cert", "", "TLS 证书路径（可选；提供则与 -key 一起启用 HTTP+HTTPS 同端口双协议）")
	key  = flag.String("key", "", "TLS 私钥路径（可选）")
	p    = flag.String("path", "/get", "回显路径；留空表示根路径 / 也响应")
)

// peekedConn 包装底层连接：先把「嗅探协议用的首字节」吐给上层，之后透明转发。
type peekedConn struct {
	conn net.Conn
	head byte
	used bool
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if !c.used {
		c.used = true
		if len(b) == 0 {
			return 0, nil
		}
		b[0] = c.head
		return 1, nil
	}
	return c.conn.Read(b)
}
func (c *peekedConn) Write(b []byte) (int, error)      { return c.conn.Write(b) }
func (c *peekedConn) Close() error                     { return c.conn.Close() }
func (c *peekedConn) LocalAddr() net.Addr              { return c.conn.LocalAddr() }
func (c *peekedConn) RemoteAddr() net.Addr             { return c.conn.RemoteAddr() }
func (c *peekedConn) SetDeadline(t time.Time) error     { return c.conn.SetDeadline(t) }
func (c *peekedConn) SetReadDeadline(t time.Time) error   { return c.conn.SetReadDeadline(t) }
func (c *peekedConn) SetWriteDeadline(t time.Time) error  { return c.conn.SetWriteDeadline(t) }

// singleConnListener 让 http.Server.Serve 复用单个已建立连接。
type singleConnListener struct {
	conn net.Conn
	once bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.once {
		return nil, io.EOF
	}
	l.once = true
	return l.conn, nil
}
func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func main() {
	flag.Parse()

	handler := func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string, len(r.Header))
		for k, vs := range r.Header {
			headers[k] = strings.Join(vs, ", ")
		}
		origin := r.RemoteAddr
		if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			origin = h
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"headers": headers,
			"origin":  origin,
			"url":     r.URL.String(),
			"method":  r.Method,
		})
	}

	mux := http.NewServeMux()
	if *p == "" {
		mux.HandleFunc("/", handler)
	} else {
		mux.HandleFunc(*p, handler)
		mux.HandleFunc("/", handler) // 同时响应根路径，方便健康检查
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	var tlsCfg *tls.Config
	if *cert != "" && *key != "" {
		cp, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatalf("load cert: %v", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cp}}
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	if tlsCfg != nil {
		log.Printf("echo server listening http+https %s path=%q", *addr, *p)
	} else {
		log.Printf("echo server listening http %s path=%q", *addr, *p)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			head := make([]byte, 1)
			if _, err := io.ReadFull(c, head); err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			pc := &peekedConn{conn: c, head: head[0]}
			if head[0] == 0x16 && tlsCfg != nil {
				tlsConn := tls.Server(pc, tlsCfg)
				_ = srv.Serve(&singleConnListener{conn: tlsConn})
				return
			}
			_ = srv.Serve(&singleConnListener{conn: pc})
		}(conn)
	}
}

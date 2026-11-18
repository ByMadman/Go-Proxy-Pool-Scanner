// ProxyScanner —— 带 Web 控制台的 HTTP/HTTPS 高匿名代理扫描器。
//
// 启动: proxyscanner.exe [-addr :8848] [-db proxy.db] [-xdb data/ip2region.xdb] [-web web/dist]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"proxyscanner/internal/api"
	"proxyscanner/internal/event"
	"proxyscanner/internal/ip2region"
	px "proxyscanner/internal/proxy"
	"proxyscanner/internal/scanner"
	"proxyscanner/internal/scheduler"
	"proxyscanner/internal/store"
)

func main() {
	addr := flag.String("addr", ":8848", "Web 控制台监听地址")
	dbPath := flag.String("db", "proxy.db", "SQLite 数据库文件路径")
	xdbPath := flag.String("xdb", "data/ip2region.xdb", "ip2region xdb 数据文件路径")
	webDir := flag.String("web", "web/dist", "前端静态资源目录")
	detectIP := flag.Bool("publicip", true, "启动时检测本机公网 IP（用于识别透明代理）")
	adminUser := flag.String("admin", "admin", "默认管理员用户名（仅当库中无账号时用于初始化）")
	adminPass := flag.String("admin-pass", "admin123", "默认管理员口令（仅当库中无账号时用于初始化）")
	extractKey := flag.String("extract-key", "", "代理池提取接口密钥；设置后外部可用 ?apikey= 提取，否则需登录令牌")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	xdbFile := resolvePath(*xdbPath)
	if _, err := os.Stat(xdbFile); err != nil {
		log.Fatalf("未找到 ip2region 数据文件: %s\n请下载 ip2region_v4.xdb 后放到 data/ip2region.xdb", xdbFile)
	}
	xdb, err := ip2region.New(xdbFile)
	if err != nil {
		log.Fatalf("加载 ip2region 数据失败: %v", err)
	}
	log.Printf("ip2region 加载完成: %s (%.2f MB)", xdb.Path(), float64(xdb.FileSize())/1024/1024)

	dbFile := *dbPath
	if dbFile != "" {
		_ = os.MkdirAll(filepath.Dir(resolvePath(dbFile)), 0o755)
	}
	st, err := store.Open(dbFile)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	if err := st.EnsureDefaultAdmin(*adminUser, *adminPass); err != nil {
		log.Fatalf("初始化管理员账号失败: %v", err)
	}

	hub := event.NewHub()
	vfOpt := px.DefaultOption()
	_ = st.Setting("verify", &vfOpt)
	vf := px.NewVerifier(vfOpt)

	mgr := scanner.NewManager(st, xdb, vf, hub)
	sched := scheduler.New(st, mgr, hub)
	sched.Start()
	defer sched.Stop()

	srv := api.New(st, xdb, mgr, vf, hub, sched, resolveDir(*webDir), *extractKey)

	if *detectIP {
		go func() {
			if ip := px.PublicIP(8 * time.Second); ip != "" {
				opt := mgr.Verifier().Option()
				opt.PublicIP = ip
				mgr.Verifier().SetOption(opt)
				log.Printf("本机公网 IP: %s（用于识别透明代理）", ip)
			} else {
				log.Printf("未能获取本机公网 IP，透明代理识别将退化为「出现 X-Forwarded-For 即判定为普通匿名」")
			}
		}()
	}

	handler := srv.Handler()
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 30 * time.Second}

	go func() {
		printBanner(*addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Web 服务启动失败: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("正在停止...")
	mgr.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	_ = st.Close()
	log.Println("已退出")
}

func printBanner(addr string) {
	host := addr
	if h, port, err := net.SplitHostPort(addr); err == nil {
		if h == "" || h == "0.0.0.0" {
			host = "127.0.0.1:" + port
		} else {
			host = net.JoinHostPort(h, port)
		}
	} else {
		host = addr
	}
	fmt.Println()
	fmt.Println("  ProxyScanner 已启动")
	fmt.Printf("  Web 控制台: http://%s\n", host)
	fmt.Println("  接口文档  : /api/health /api/regions /api/proxies /api/scan/start")
	fmt.Println("  按 Ctrl+C 停止服务")
	fmt.Println()
}

func resolvePath(p string) string {
	if filepath.IsAbs(p) || p == "" {
		return p
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return p
	}
	alt := filepath.Join(filepath.Dir(exe), p)
	if _, err := os.Stat(alt); err == nil {
		return alt
	}
	return p
}

func resolveDir(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if info, err := os.Stat(p); err == nil && info.IsDir() {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return p
	}
	alt := filepath.Join(filepath.Dir(exe), p)
	if info, err := os.Stat(alt); err == nil && info.IsDir() {
		return alt
	}
	return p
}

// xdbtool 用于验证 ip2region 数据文件是否可用，并输出国家/地区与网段统计。
//
// 用法:
//
//	xdbtool -xdb data/ip2region.xdb [-search 8.8.8.8] [-country 中国] [-top 20]
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"proxyscanner/internal/ip2region"
)

func main() {
	xdbPath := flag.String("xdb", "data/ip2region.xdb", "ip2region v4 xdb 文件路径")
	search := flag.String("search", "", "查询某个 IP 的归属地")
	country := flag.String("country", "", "列出该国家/地区下的网段（限制前 -limit 条）")
	province := flag.String("province", "", "省份/一级行政区（中文或英文，配合 -country 使用）")
	top := flag.Int("top", 30, "打印国家/地区排行的数量")
	limit := flag.Int("limit", 20, "打印网段的最大条数")
	flag.Parse()

	s, err := ip2region.New(*xdbPath)
	if err != nil {
		fmt.Println("加载失败:", err)
		os.Exit(1)
	}
	fmt.Printf("数据文件: %s (%.2f MB) IPv4=%v 结构版本=%v 索引策略=%v\n",
		s.Path(), float64(s.FileSize())/1024/1024, true, s.Version(), s.IndexPolicy())

	if *search != "" {
		loc, ok := s.Search(*search)
		if !ok {
			fmt.Println("未查询到归属地")
		} else {
			fmt.Printf("%s => %s (国家=%s 省=%s 市=%s ISP=%s)\n", *search, loc.Display(), loc.Country, loc.Province, loc.City, loc.ISP)
		}
		return
	}

	if *country != "" || *province != "" {
		f := ip2region.Filter{}
		if *country != "" {
			f.Countries = []string{*country}
		}
		if *province != "" {
			f.Provinces = []string{*province}
		}
		segs := s.Segments(f)
		sort.Slice(segs, func(i, j int) bool { return segs[i].Size() > segs[j].Size() })
		var total uint64
		for _, g := range segs {
			total += g.Size()
		}
		fmt.Printf("%s: 网段 %d 个, 覆盖 IP %.2f 亿\n", *country, len(segs), float64(total)/1e8)
		for i, g := range segs {
			if i >= *limit {
				break
			}
			fmt.Printf("  %-20s %-20s %-28s %s\n", g.StartIP(), g.EndIP(), g.Loc.Display(), g.CIDRs()[0])
		}
		return
	}

	cs := s.Countries()
	fmt.Printf("国家/地区数量: %d\n", len(cs))
	for i, c := range cs {
		if i >= *top {
			break
		}
		fmt.Printf("  %-16s %-4s 网段=%-8d IP=%.3f 亿  省份=%d\n", c.Name, c.Code, c.Segments, float64(c.IPs)/1e8, len(c.Provinces))
	}
}

// Package ip2region 实现了 ip2region xdb 文件的查询与网段枚举能力。
//
// xdb 二进制布局（已按实机文件校验）：
//
//	[0, 256)                         文件头 256 字节（小端）
//	    u16 version        @0
//	    u16 indexPolicy    @2
//	    u32 createdAt      @4
//	    u32 startIndexPtr  @8
//	    u32 endIndexPtr    @12
//	    u16 ipVersion      @16     4=IPv4 6=IPv6
//	    u16 runtimePtrBytes@18
//	[256, 256+524288)                一级向量索引，65536 项，每项 8 字节: startPtr(4) endPtr(4)
//	[startIdx, endIdx)               段索引区，IPv4 每条 14 字节:
//	    u32 startIP(小端) u32 endIP(小端) u16 dataLen u32 dataPtr
//	数据区                            归属地字符串（UTF-8），多条记录可复用同一 dataPtr
//
// 归属地字符串格式：国家|省份/区域|城市|ISP|国家代码，例如
// "中国|江苏省|南京市|0|CN" / "United States|Georgia|Atlanta|Google LLC|US"
package ip2region

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	// HeaderInfoLength 文件头长度。
	HeaderInfoLength = 256
	// VectorIndexRows / Cols 一级索引维度。
	VectorIndexRows = 256
	VectorIndexCols = 256
	// VectorIndexSize 一级索引每项字节数。
	VectorIndexSize = 8
	// VectorIndexLength 一级索引总长度 256*256*8 = 524288。
	VectorIndexLength = VectorIndexRows * VectorIndexCols * VectorIndexSize
	// IPv4IndexSize IPv4 段索引记录长度 4+4+2+4。
	IPv4IndexSize = 14
)

var (
	// ErrInvalidXdb xdb 文件非法。
	ErrInvalidXdb = errors.New("ip2region: 无效的 xdb 数据文件")
	// ErrIPv6Data 暂不支持 IPv6 数据文件。
	ErrIPv6Data = errors.New("ip2region: 仅支持 IPv4 数据文件(ip2region_v4.xdb)")
)

// Location 一条归属地的结构化结果。
type Location struct {
	Country     string `json:"country"`
	Province    string `json:"province"`
	City        string `json:"city"`
	District     string `json:"district"`
	ISP         string `json:"isp"`
	CountryCode string `json:"countryCode"`
	Raw         string `json:"raw"`
}

// Display 返回精简归属地，例如 "中国 江苏省 南京市 电信"。
func (l Location) Display() string {
	parts := make([]string, 0, 5)
	for _, v := range []string{l.Country, l.Province, l.City, l.ISP} {
		if v != "" && v != "0" {
			parts = append(parts, v)
		}
	}
	if len(parts) == 0 {
		if l.Raw != "" {
			return l.Raw
		}
		return "未知"
	}
	return strings.Join(parts, " ")
}

// ParseLocation 解析 "国家|省份|城市|ISP|代码" 格式的原始数据。
func ParseLocation(raw string) Location {
	l := Location{Raw: raw}
	fields := strings.Split(raw, "|")
	if len(fields) >= 1 {
		l.Country = cleanField(fields[0])
	}
	if len(fields) >= 2 {
		l.Province = cleanField(fields[1])
	}
	if len(fields) >= 3 {
		l.City = cleanField(fields[2])
	}
	if len(fields) >= 4 {
		// 5 段格式（国家|省|市|运营商|代码）时本段为运营商；
		// 更长格式（含区）时本段为区，运营商/代码顺延。
		if len(fields) >= 6 {
			l.District = cleanField(fields[3])
			l.ISP = cleanField(fields[4])
		} else {
			l.ISP = cleanField(fields[3])
		}
	}
	if len(fields) >= 5 {
		l.CountryCode = cleanField(fields[4])
	}
	return l
}

func cleanField(s string) string {
	s = strings.TrimSpace(s)
	if s == "0" || s == "" {
		return ""
	}
	return s
}

// Segment 一个连续 IP 网段及其归属地。
type Segment struct {
	Start uint32   `json:"start"`
	End   uint32   `json:"end"`
	Loc   Location `json:"loc"`
}

// StartIP 起始 IP 字符串。
func (s Segment) StartIP() string { return Uint32ToIP(s.Start) }

// EndIP 结束 IP 字符串。
func (s Segment) EndIP() string { return Uint32ToIP(s.End) }

// Size 网段包含的 IP 数量。
func (s Segment) Size() uint64 { return uint64(s.End) - uint64(s.Start) + 1 }

// CIDRs 把该网段转换为若干 CIDR 表示。
func (s Segment) CIDRs() []string { return RangeToCIDRs(s.Start, s.End) }

// rawSeg 内部紧凑存储（归属地通过 LocationID 引用共享表）。
type rawSeg struct {
	Start uint32
	End   uint32
	LocID uint32
}

// Filter 网段过滤条件，所有非空条件之间是「与」的关系。
type Filter struct {
	Countries []string // 国家名或国家代码，例如 "中国" / "CN"
	Provinces []string // 省份/区域，例如 "江苏省"
	Cities    []string // 城市
	ISPs      []string // 运营商，例如 "电信"
	Keyword   string   // 模糊关键字，匹配整条原始归属地串
}

// Empty 是否没有任何过滤条件。
func (f Filter) Empty() bool {
	return len(f.Countries) == 0 && len(f.Provinces) == 0 && len(f.Cities) == 0 &&
		len(f.ISPs) == 0 && strings.TrimSpace(f.Keyword) == ""
}

func (f Filter) match(loc Location) bool {
	if k := strings.TrimSpace(f.Keyword); k != "" && !strings.Contains(loc.Raw, k) {
		return false
	}
	if !matchAny(loc.Country, loc.CountryCode, f.Countries) {
		return false
	}
	if !matchAny(loc.Province, "", f.Provinces) {
		return false
	}
	if !matchAny(loc.City, "", f.Cities) {
		return false
	}
	if !matchAny(loc.ISP, "", f.ISPs) {
		return false
	}
	return true
}

func matchAny(a, b string, list []string) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" || v == "*" {
			return true
		}
		if strings.EqualFold(a, v) || (b != "" && strings.EqualFold(b, v)) {
			return true
		}
	}
	return false
}

// ProvinceStat 省份维度的统计。
type ProvinceStat struct {
	Name     string `json:"name"`
	Segments int    `json:"segments"`
	IPs      uint64 `json:"ips"`
	// Aliases 是该省份在 ip2region 里出现过的原始写法（一般是英文名，
	// 同一省份可能有多种拼写），按省份过滤时需要展开匹配。
	Aliases []string `json:"aliases,omitempty"`
}

// provinceGroup 归并后的省份（同一省份的不同英文拼写合并为一条）。
type provinceGroup struct {
	code    string
	name    string // 中文规范名
	aliases []string
}

// CountryStat 国家维度的统计。
type CountryStat struct {
	Name      string         `json:"name"`
	Code      string         `json:"code"`
	Segments  int            `json:"segments"`
	IPs       uint64         `json:"ips"`
	Provinces []ProvinceStat `json:"provinces"`
	// Aliases 是该国家/地区在 ip2region 里出现过的原始写法（中英混排），
	// 前端展示用不到，但按名称过滤时需要展开匹配。
	Aliases []string `json:"aliases,omitempty"`
}

// countryGroup 归并后的国家/地区（同一国家的中英文写法合并为一条）。
type countryGroup struct {
	code    string
	name    string   // 中文规范名
	aliases []string // 出现过的原始 Country 写法
}

// Searcher xdb 查询器，加载后全部内容驻留内存（约 11MB），线程安全。
type Searcher struct {
	path   string
	data   []byte
	fsize  int
	start  uint32 // 段索引区起始偏移
	end    uint32 // 段索引区结束偏移（不含）
	ipVer  uint16 // 4=IPv4
	policy uint16
	// version / createdAt 来自文件头，仅用于诊断展示
	version   uint16
	createdAt uint32

	once    sync.Once
	segs    []rawSeg
	locs    []Location
	locByID map[uint32]Location

	countryOnce  sync.Once
	countryStats []CountryStat
	countryIndex map[string]*countryGroup // 键：小写的 中文名/英文别名/国家代码
	provinceIndex map[string][]*provinceGroup // 键：小写的 省份中文名/英文别名
}

// New 加载指定路径的 xdb 文件。
func New(path string) (*Searcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Searcher{path: path, data: data, fsize: len(data)}
	if err := s.parseHeader(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path 返回数据文件路径。
func (s *Searcher) Path() string { return s.path }

// FileSize 数据文件字节数。
func (s *Searcher) FileSize() int { return s.fsize }

// Version 返回 xdb 结构版本。
func (s *Searcher) Version() uint16 { return s.version }

// IndexPolicy 返回 xdb 索引策略。
func (s *Searcher) IndexPolicy() uint16 { return s.policy }

// CreatedAt 返回数据文件的生成时间戳（Unix 秒）。
func (s *Searcher) CreatedAt() uint32 { return s.createdAt }

func (s *Searcher) parseHeader() error {
	if s.fsize < HeaderInfoLength+VectorIndexLength {
		return ErrInvalidXdb
	}
	hdr := s.data
	version := binary.LittleEndian.Uint16(hdr[0:2])
	s.policy = binary.LittleEndian.Uint16(hdr[2:4])
	createdAt := binary.LittleEndian.Uint32(hdr[4:8])
	ipVer := binary.LittleEndian.Uint16(hdr[16:18])
	if version < 3 {
		ipVer = 4 // 老版本结构只支持 IPv4
	}
	if ipVer != 4 {
		return ErrIPv6Data
	}
	s.ipVer = 4
	s.createdAt = createdAt
	s.version = version

	// 通过一级索引扫描出真实的段索引区边界（比直接读头部指针更可靠）。
	minPtr, maxPtr := uint32(math.MaxUint32), uint32(0)
	for i := 0; i < VectorIndexRows*VectorIndexCols; i++ {
		off := HeaderInfoLength + i*VectorIndexSize
		sp := binary.LittleEndian.Uint32(s.data[off:])
		ep := binary.LittleEndian.Uint32(s.data[off+4:])
		if sp == 0 || ep == 0 {
			continue
		}
		if sp < minPtr {
			minPtr = sp
		}
		if ep > maxPtr {
			maxPtr = ep
		}
	}
	if minPtr == math.MaxUint32 || maxPtr <= minPtr || int(maxPtr) > s.fsize {
		return ErrInvalidXdb
	}
	if (maxPtr-minPtr)%IPv4IndexSize != 0 {
		return fmt.Errorf("%w: 段索引区长度非法(%d~%d)", ErrInvalidXdb, minPtr, maxPtr)
	}
	s.start, s.end = minPtr, maxPtr
	return nil
}

// recordCount 段索引记录数量。
func (s *Searcher) recordCount() int { return int(s.end-s.start) / IPv4IndexSize }

// region 按 dataPtr 读取并缓存归属地字符串。
func (s *Searcher) region(ptr, length uint32) Location {
	if length == 0 || int(ptr)+int(length) > s.fsize {
		return Location{Raw: "未知"}
	}
	raw := string(s.data[ptr : ptr+length])
	return ParseLocation(raw)
}

// SearchIP 查询 uint32 形式的 IPv4。
func (s *Searcher) SearchIP(ip uint32) (Location, bool) {
	i0 := int((ip >> 24) & 0xFF)
	i1 := int((ip >> 16) & 0xFF)
	off := HeaderInfoLength + (i0*VectorIndexCols+i1)*VectorIndexSize
	if off+VectorIndexSize > s.fsize {
		return Location{}, false
	}
	sp := binary.LittleEndian.Uint32(s.data[off:])
	ep := binary.LittleEndian.Uint32(s.data[off+4:])
	if sp == 0 || ep == 0 || int(sp) >= s.fsize || int(ep) > s.fsize {
		return Location{}, false
	}
	l, h := 0, int(ep-sp)/IPv4IndexSize
	for l <= h {
		m := (l + h) >> 1
		p := int(sp) + m*IPv4IndexSize
		if p+IPv4IndexSize > s.fsize {
			return Location{}, false
		}
		sip := binary.LittleEndian.Uint32(s.data[p:])
		if ip < sip {
			h = m - 1
			continue
		}
		eip := binary.LittleEndian.Uint32(s.data[p+4:])
		if ip > eip {
			l = m + 1
			continue
		}
		dLen := uint32(binary.LittleEndian.Uint16(s.data[p+8:]))
		dPtr := binary.LittleEndian.Uint32(s.data[p+10:])
		if dLen == 0 {
			return Location{}, false
		}
		return s.region(dPtr, dLen), true
	}
	return Location{}, false
}

// Search 查询点分十进制 IPv4 字符串。
func (s *Searcher) Search(ipStr string) (Location, bool) {
	ip, err := IPToUint32(ipStr)
	if err != nil {
		return Location{}, false
	}
	return s.SearchIP(ip)
}

// buildIndex 首次使用时构建全量段索引（约 55 万条，实测 200ms 左右）。
func (s *Searcher) buildIndex() error {
	s.once.Do(func() {
		n := s.recordCount()
		segs := make([]rawSeg, 0, n)
		s.locByID = make(map[uint32]Location, 8192)
		s.locs = make([]Location, 0, 8192)
		seen := make(map[uint32]uint32, 65536) // dataPtr -> locID
		for i := 0; i < n; i++ {
			p := int(s.start) + i*IPv4IndexSize
			if p+IPv4IndexSize > s.fsize {
				break
			}
			start := binary.LittleEndian.Uint32(s.data[p:])
			end := binary.LittleEndian.Uint32(s.data[p+4:])
			if end < start {
				continue
			}
			dLen := uint32(binary.LittleEndian.Uint16(s.data[p+8:]))
			dPtr := binary.LittleEndian.Uint32(s.data[p+10:])
			if dLen == 0 || int(dPtr)+int(dLen) > s.fsize {
				continue
			}
			id, ok := seen[dPtr]
			if !ok {
				id = uint32(len(s.locs))
				loc := s.region(dPtr, dLen)
				s.locByID[id] = loc
				s.locs = append(s.locs, loc)
				seen[dPtr] = id
			}
			segs = append(segs, rawSeg{Start: start, End: end, LocID: id})
		}
		s.segs = segs
	})
	return nil
}

// AllSegments 返回全部网段（数量较大，慎用）。
func (s *Searcher) AllSegments() []Segment {
	_ = s.buildIndex()
	return expand(s, s.segs)
}

// Segments 按条件过滤网段。
func (s *Searcher) Segments(f Filter) []Segment {
	_ = s.buildIndex()
	if f.Empty() {
		return expand(s, s.segs)
	}
	// 把国家名/代码展开为该国家的全部原始写法，避免中英文写法不一致导致漏掉网段。
	f.Countries = s.expandCountryFilter(f.Countries)
	// 省份同理：界面上显示中文名，数据里是英文名（且可能多种拼写）。
	f.Provinces = s.expandProvinceFilter(f.Countries, f.Provinces)
	out := make([]Segment, 0, 1024)
	for _, r := range s.segs {
		loc := s.locByID[r.LocID]
		if !f.match(loc) {
			continue
		}
		out = append(out, Segment{Start: r.Start, End: r.End, Loc: loc})
	}
	return out
}

func expand(s *Searcher, segs []rawSeg) []Segment {
	out := make([]Segment, 0, len(segs))
	for _, r := range segs {
		out = append(out, Segment{Start: r.Start, End: r.End, Loc: s.locByID[r.LocID]})
	}
	return out
}

// ensureCountries 构建国家/地区归并统计与国家名索引（只执行一次）。
//
// ip2region 的数据里同一个国家存在中英两种写法（例如 "United States" 与 "美国"，
// 前者 15.24 亿 IP / 196960 段，后者仅 78 段）。旧实现直接按 Country 字符串聚合，
// 界面上会同时出现 "United States" 和 "美国" 两条，用户选小的那条就只能扫到极少网段。
// 这里改为按国家代码归并，并把展示名统一成中文。
func (s *Searcher) ensureCountries() {
	s.countryOnce.Do(func() {
		_ = s.buildIndex()
		type provAgg struct {
			segments int
			ips      uint64
			aliases  map[string]struct{}
		}
		type agg struct {
			code      string
			segments  int
			ips       uint64
			aliasIP   map[string]uint64
			provinces map[string]*provAgg
		}
		m := make(map[string]*agg, 512)
		for _, r := range s.segs {
			loc := s.locByID[r.LocID]
			alias := loc.Country
			if alias == "" {
				alias = "未知"
			}
			key := loc.CountryCode
			if key == "" {
				key = "name:" + alias
			}
			a := m[key]
			if a == nil {
				a = &agg{code: loc.CountryCode, aliasIP: map[string]uint64{}, provinces: map[string]*provAgg{}}
				m[key] = a
			}
			size := uint64(r.End) - uint64(r.Start) + 1
			a.segments++
			a.ips += size
			a.aliasIP[alias] += size

			pk := loc.Province
			if pk == "" {
				pk = "未划分"
			}
			// 省份按「国家代码 + 中文名」归并：同一省份的不同英文拼写会合并成一条，
			// 例如 BR 的 "São Paulo"/"Sao Paulo" 都归一为「圣保罗州」。
			pn := cnProvinceName(loc.CountryCode, pk)
			pa := a.provinces[pn]
			if pa == nil {
				pa = &provAgg{aliases: map[string]struct{}{}}
				a.provinces[pn] = pa
			}
			pa.aliases[pk] = struct{}{}
			pa.segments++
			pa.ips += size
		}

		idx := make(map[string]*countryGroup, len(m)*3)
		pIdx := make(map[string][]*provinceGroup, 4096)
		addProv := func(g *provinceGroup, key string) {
			nk := normPlaceKey(key)
			if nk == "" {
				return
			}
			for _, old := range pIdx[nk] {
				if old == g {
					return
				}
			}
			pIdx[nk] = append(pIdx[nk], g)
		}
		list := make([]CountryStat, 0, len(m))
		for _, a := range m {
			// 以 IP 量最大的写法作为主名，再翻译成中文。
			base, best := "", uint64(0)
			aliases := make([]string, 0, len(a.aliasIP))
			for name, n := range a.aliasIP {
				aliases = append(aliases, name)
				if n >= best {
					base, best = name, n
				}
			}
			sort.Strings(aliases)
			name := cnCountryName(base)

			ps := make([]ProvinceStat, 0, len(a.provinces))
			for pname, pa := range a.provinces {
				paliases := make([]string, 0, len(pa.aliases))
				for al := range pa.aliases {
					paliases = append(paliases, al)
				}
				sort.Strings(paliases)
				ps = append(ps, ProvinceStat{
					Name:     pname,
					Segments: pa.segments,
					IPs:      pa.ips,
					Aliases:  paliases,
				})
				pg := &provinceGroup{code: a.code, name: pname, aliases: paliases}
				addProv(pg, pname)
				for _, al := range paliases {
					addProv(pg, al)
				}
			}
			sort.Slice(ps, func(i, j int) bool { return ps[i].IPs > ps[j].IPs })
			list = append(list, CountryStat{
				Name:      name,
				Code:      a.code,
				Segments:  a.segments,
				IPs:       a.ips,
				Provinces: ps,
				Aliases:   aliases,
			})

			g := &countryGroup{code: a.code, name: name, aliases: aliases}
			put := func(k string) {
				k = normPlaceKey(k)
				if k == "" {
					return
				}
				if _, ok := idx[k]; !ok {
					idx[k] = g
				}
			}
			put(name)
			put(a.code)
			for _, al := range aliases {
				put(al)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].IPs > list[j].IPs })
		s.countryStats = list
		s.countryIndex = idx
		s.provinceIndex = pIdx
	})
}

// expandProvinceFilter 把过滤条件里的省份名展开成「中文名 + 全部英文别名」。
// countries 用于消歧：同一个英文省名在不同国家含义不同（如 Georgia）。
func (s *Searcher) expandProvinceFilter(countries, provinces []string) []string {
	if len(provinces) == 0 {
		return provinces
	}
	s.ensureCountries()
	codes := make(map[string]struct{}, len(countries))
	for _, v := range countries {
		if g, ok := s.countryIndex[normPlaceKey(v)]; ok && g.code != "" {
			codes[g.code] = struct{}{}
		}
	}
	out := make([]string, 0, len(provinces))
	seen := make(map[string]struct{}, len(provinces))
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		k := strings.ToLower(v)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	for _, v := range provinces {
		add(v)
		groups := s.provinceIndex[normPlaceKey(v)]
		var picked []*provinceGroup
		for _, g := range groups {
			if len(codes) == 0 {
				picked = append(picked, g)
				continue
			}
			if _, ok := codes[g.code]; ok {
				picked = append(picked, g)
			}
		}
		if len(picked) == 0 {
			picked = groups // 国家条件对不上时退回全部同名省份，避免直接漏扫
		}
		for _, g := range picked {
			add(g.name)
			for _, al := range g.aliases {
				add(al)
			}
		}
	}
	return out
}

// ExpandCountryFilter 把界面上的国家名/代码（中英文均可）展开成底层存储的
// 全部原始写法，供 API 层按国家查询代理池时使用（库里存的是 ip2region 原文）。
func (s *Searcher) ExpandCountryFilter(list []string) []string {
	return s.expandCountryFilter(list)
}

// ExpandProvinceFilter 把省份名（中文或英文）展开成底层存储的全部原始写法。
// countries 用于消歧同名省份（如 Georgia 在美国和格鲁吉亚都有）。
func (s *Searcher) ExpandProvinceFilter(countries, provinces []string) []string {
	return s.expandProvinceFilter(countries, provinces)
}

// Countries 统计所有国家/地区（含段数、IP 数量与下属省份），中英文写法已归并。
func (s *Searcher) Countries() []CountryStat {
	s.ensureCountries()
	return s.countryStats
}

// expandCountryFilter 把过滤条件里的国家名展开成「中文名 + 英文别名 + 国家代码」，
// 这样无论用户选的是中文名、英文名还是代码，都能匹配到同一国家的全部网段。
func (s *Searcher) expandCountryFilter(list []string) []string {
	if len(list) == 0 {
		return list
	}
	s.ensureCountries()
	out := make([]string, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		k := strings.ToLower(v)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	for _, v := range list {
		add(v)
		if s.countryIndex == nil {
			continue
		}
		if g, ok := s.countryIndex[normPlaceKey(v)]; ok {
			add(g.name)
			add(g.code)
			for _, a := range g.aliases {
				add(a)
			}
		}
	}
	return out
}

// Provinces 返回指定国家下的省份列表，country 为空时返回全部省份。
// country 支持中文名、英文名或国家代码（内部统一归并为中文规范名）。
func (s *Searcher) Provinces(country string) []ProvinceStat {
	s.ensureCountries()
	key := strings.TrimSpace(country)
	if key != "" && s.countryIndex != nil {
		if g, ok := s.countryIndex[normPlaceKey(key)]; ok {
			key = g.name
		}
	}
	for _, c := range s.countryStats {
		if strings.EqualFold(c.Name, key) {
			return c.Provinces
		}
	}
	var out []ProvinceStat
	if country == "" {
		for _, c := range s.countryStats {
			out = append(out, c.Provinces...)
		}
	}
	return out
}

// IPToUint32 点分十进制转 uint32。
func IPToUint32(ip string) (uint32, error) {
	v := net.ParseIP(strings.TrimSpace(ip))
	if v == nil {
		return 0, fmt.Errorf("无效的 IP 地址: %s", ip)
	}
	v4 := v.To4()
	if v4 == nil {
		return 0, fmt.Errorf("仅支持 IPv4 地址: %s", ip)
	}
	return binary.BigEndian.Uint32(v4), nil
}

// Uint32ToIP uint32 转点分十进制。
func Uint32ToIP(v uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b).String()
}

// RangeToCIDRs 把一段连续的 IPv4 区间转换为最少个数的 CIDR 列表。
func RangeToCIDRs(start, end uint32) []string {
	if end < start {
		return nil
	}
	var out []string
	cur := uint64(start)
	last := uint64(end)
	for cur <= last {
		maxSize := uint64(1) << 32
		if cur != 0 {
			maxSize = cur & (^cur + 1) // 低位能对齐的最大块
		}
		for cur+maxSize-1 > last {
			maxSize >>= 1
		}
		bits := 32 - log2Floor(maxSize)
		out = append(out, fmt.Sprintf("%s/%d", Uint32ToIP(uint32(cur)), bits))
		cur += maxSize
	}
	return out
}

func log2Floor(v uint64) int {
	n := 0
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

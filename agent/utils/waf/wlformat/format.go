// Package wlformat 定义 WAF IP 黑名单的发布格式。
//
// 聚合由 CI 侧完成（拉取多个公开源 -> 解析 -> CIDR 合并去重 -> 折叠成
// 互不重叠的区间 -> 编码），3panel 实例只负责下载与解码。集中聚合的理由是
// 用户所在网络未必能直连 raw.githubusercontent.com 等源站，与其让每个
// 实例各自碰运气，不如由 CI 产出单一制品并多镜像分发。
//
// 文件布局（小端）：
//
//	 0..3   magic "3PWL"
//	 4      version = 2
//	 5..8   u32 flags（预留，当前恒为 0）
//	 9..12  u32 countV4
//	13..16  u32 countV6
//	17..    v4 区间流：varint(gap), varint(len) 反复
//	          gap 为本区间起点与上一区间末地址（首条为 -1）的间距，
//	          因此首条 gap 等于 start+1；len 为区间地址个数
//	          v6 区间流：每条 32 字节，起点 16 字节 + 终点 16 字节
//
// v4 用 delta+varint 而非定长：区间普遍稀疏（实测 13 万条 v4 网段里绝大多数
// 为单 IP），定长 8 字节会把体积推到 1MB 上下，varint 后为 380KB。
package wlformat

import (
	"encoding/binary"
	"errors"
	"fmt"

	"net/netip"
)

const (
	// Magic 是文件头标识，用于在解码前快速拒绝非本格式文件。
	Magic = "3PWL"
	// Version 是当前格式版本。解码时严格比对，未知版本一律拒绝而非猜测布局。
	Version = 2
	// HeaderSize 为固定头部长度：4+1+4+4+4。
	HeaderSize = 17

	// DefaultMetaName 是与数据文件配套的元数据文件名。
	DefaultMetaName = "meta.json"
	// DefaultDataName 是数据文件名。
	DefaultDataName = "wl_v2.bin"
)

var (
	// ErrBadMagic 表示文件头不是本格式。
	ErrBadMagic = errors.New("wlformat: bad magic")
	// ErrBadVersion 表示格式版本不受支持。
	ErrBadVersion = errors.New("wlformat: unsupported version")
	// ErrTruncated 表示数据不足，文件可能被截断。
	ErrTruncated = errors.New("wlformat: truncated payload")
	// ErrCorrupt 表示内部计数与实际数据不符。
	ErrCorrupt = errors.New("wlformat: corrupt payload")
)

// Meta 描述一次聚合产物的元信息，随数据文件一同分发。
// 客户端先取 meta 比对 sha256，命中本地缓存才下载数据文件，避免每次拉全量。
type Meta struct {
	Version     int          `json:"version"`
	GeneratedAt string       `json:"generatedAt"`
	SHA256      string       `json:"sha256"`
	Size        int64        `json:"size"`
	CountV4     int          `json:"countV4"`
	CountV6     int          `json:"countV6"`
	Sources     []MetaSource `json:"sources"`
	Mirrors     []string     `json:"mirrors"`
	// Source 仅在客户端落盘的本地副本里填写，标明这份数据来自哪个镜像。
	// 制品本身不含此字段：同一份数据在所有镜像上内容一致。
	Source string `json:"source,omitempty"`
}

// MetaSource 记录单个上游源的抓取结果。
type MetaSource struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Entries int    `json:"entries"`
	// Err 非空表示该源本次抓取失败，聚合时按缺失处理。
	Err string `json:"err,omitempty"`
}

// Encode 把已折叠的区间编码为二进制。
// v4 与 v6 需按地址升序传入且同版本内互不重叠（Merge 的结果天然满足）。
func Encode(v4, v6 []netip.Prefix) ([]byte, error) {
	if err := checkAscending(v4); err != nil {
		return nil, fmt.Errorf("wlformat: v4 %w", err)
	}
	if err := checkAscending(v6); err != nil {
		return nil, fmt.Errorf("wlformat: v6 %w", err)
	}
	buf := make([]byte, HeaderSize, HeaderSize+len(v4)*3+len(v6)*32)
	copy(buf, Magic)
	buf[4] = Version
	binary.LittleEndian.PutUint32(buf[9:13], uint32(len(v4)))
	binary.LittleEndian.PutUint32(buf[13:17], uint32(len(v6)))

	var prevEnd int64 = -1
	for _, p := range v4 {
		s := v4Start(p)
		length := int64(1) << (32 - p.Bits())
		buf = binary.AppendUvarint(buf, uint64(s-prevEnd))
		buf = binary.AppendUvarint(buf, uint64(length))
		prevEnd = s + length - 1
	}
	for _, p := range v6 {
		start := p.Addr().As16()
		end := lastAddr(p)
		buf = append(buf, start[:]...)
		buf = append(buf, end[:]...)
	}
	return buf, nil
}

// Decode 解析二进制，返回 v4 与 v6 区间。
// 计数不符或长度异常一律报错，不返回部分结果，避免上游产出坏文件时客户端
// 静默拿到残缺名单。
func Decode(data []byte) (v4, v6 []netip.Prefix, err error) {
	if len(data) < HeaderSize {
		return nil, nil, ErrTruncated
	}
	if string(data[:4]) != Magic {
		return nil, nil, ErrBadMagic
	}
	if data[4] != Version {
		return nil, nil, fmt.Errorf("%w: %d", ErrBadVersion, data[4])
	}
	countV4 := int(binary.LittleEndian.Uint32(data[9:13]))
	countV6 := int(binary.LittleEndian.Uint32(data[13:17]))
	if countV4 < 0 || countV6 < 0 {
		return nil, nil, ErrCorrupt
	}

	v4 = make([]netip.Prefix, 0, countV4)
	pos := HeaderSize
	var prevEnd int64 = -1
	for i := 0; i < countV4; i++ {
		var gap, length int64
		if gap, pos, err = readUvarint(data, pos); err != nil {
			return nil, nil, fmt.Errorf("v4[%d] gap: %w", i, err)
		}
		if length, pos, err = readUvarint(data, pos); err != nil {
			return nil, nil, fmt.Errorf("v4[%d] len: %w", i, err)
		}
		if length <= 0 {
			return nil, nil, fmt.Errorf("v4[%d] %w: non-positive length %d", i, ErrCorrupt, length)
		}
		start := prevEnd + gap
		if start < 0 || start+length-1 > 0xFFFFFFFF {
			return nil, nil, fmt.Errorf("v4[%d] %w: out of range", i, ErrCorrupt)
		}
		bits, ok := exactPrefixLen(uint64(length))
		if !ok {
			// 折叠后的区间必然是 2 的幂；否则说明上游未折叠或文件损坏。
			return nil, nil, fmt.Errorf("v4[%d] %w: length %d is not a CIDR size", i, ErrCorrupt, length)
		}
		addr, _ := netip.AddrFromSlice([]byte{
			byte(start >> 24), byte(start >> 16), byte(start >> 8), byte(start),
		})
		v4 = append(v4, netip.PrefixFrom(addr, 32-bits))
		prevEnd = start + length - 1
	}

	if pos+32*countV6 != len(data) {
		return nil, nil, fmt.Errorf("%w: v6 payload %d bytes, want %d",
			ErrCorrupt, len(data)-pos, 32*countV6)
	}
	v6 = make([]netip.Prefix, 0, countV6)
	for i := 0; i < countV6; i++ {
		s, _ := netip.AddrFromSlice(data[pos : pos+16])
		e, _ := netip.AddrFromSlice(data[pos+16 : pos+32])
		pos += 32
		p, ok := prefixOf(s, e)
		if !ok {
			return nil, nil, fmt.Errorf("v6[%d] %w: not a CIDR range", i, ErrCorrupt)
		}
		v6 = append(v6, p)
	}
	return v4, v6, nil
}

// v4Start 返回 v4 前缀的起始地址数值。
func v4Start(p netip.Prefix) int64 {
	a := p.Addr().As4()
	return int64(a[0])<<24 | int64(a[1])<<16 | int64(a[2])<<8 | int64(a[3])
}

// lastAddr 返回前缀的末地址：把 host 位全部置 1。
// As16() 是网络字节序，索引 0 对应最高位字节，故直接用 i 索引而非反向。
// 第 i 字节的绝对位区间是 [i*8, i*8+8)。
func lastAddr(p netip.Prefix) [16]byte {
	a := p.Addr().As16()
	bits := p.Bits()
	for i := 0; i < 16; i++ {
		if i*8 >= bits {
			a[i] = 0xFF
		} else if i*8+8 > bits {
			// 跨界：保留前缀位，host 部分置 1
			a[i] |= byte(0xFF >> uint(bits-i*8))
		}
	}
	return a
}

// exactPrefixLen 把区间地址个数换算为前缀剩余位数。
// 长度非 2 的幂说明区间未对齐，返回 false。v6 的跨度可到 2^128，故循环到 128。
func exactPrefixLen(length uint64) (int, bool) {
	if length == 0 {
		return 0, false
	}
	// uint64 最多表示 2^64-1，故只需比较到 2^63。
	// v6 的 /0（整个地址空间）跨度为 2^128，落在可表示范围外，
	// 由 prefixOf 的 hostBits==bits 分支（start==end）单独处理。
	for i := 0; i < 64; i++ {
		if uint64(1)<<uint(i) == length {
			return i, true
		}
	}
	return 0, false
}

// prefixOf 由起止地址反推前缀，二者必须构成一个对齐的 CIDR。
//
// 用 XOR 求最高不同位而不是算跨度：v6 的跨度最大 2^128，超出 uint64，
// 且跨度法无法区分"未对齐的区间"与"跨度恰好是 2 的幂但起点不对齐"。
func prefixOf(start, end netip.Addr) (netip.Prefix, bool) {
	if !start.IsValid() || !end.IsValid() || start.Compare(end) > 0 {
		return netip.Prefix{}, false
	}
	if start.Is4() != end.Is4() {
		return netip.Prefix{}, false
	}

	sb, eb := start.AsSlice(), end.AsSlice()
	// 从最高位字节向低位扫描，遇到首个不同字节为止；
	// 该字节内相同的高位构成公共前缀，剩下的是 host 位。
	common := 0
	for i := 0; i < len(sb); i++ {
		x := sb[i] ^ eb[i]
		if x == 0 {
			common += 8
			continue
		}
		// 统计该字节内从高位起连续相同的位数
		for b := 7; b >= 0; b-- {
			if x&(1<<uint(b)) != 0 {
				break
			}
			common++
		}
		break
	}
	p := netip.PrefixFrom(start, common)
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p, p.Contains(start) && p.Contains(end)
}

func checkAscending(ps []netip.Prefix) error {
	var prev netip.Addr
	for i, p := range ps {
		if !p.IsValid() {
			return fmt.Errorf("entry %d invalid", i)
		}
		if i > 0 && p.Addr().Compare(prev) <= 0 {
			return fmt.Errorf("entry %d not strictly ascending", i)
		}
		prev = p.Addr()
	}
	return nil
}

func readUvarint(data []byte, pos int) (int64, int, error) {
	if pos >= len(data) {
		return 0, pos, ErrTruncated
	}
	v, n := binary.Uvarint(data[pos:])
	if n == 0 {
		return 0, pos, ErrTruncated
	}
	if n < 0 || v > 1<<62 {
		return 0, pos, ErrCorrupt
	}
	return int64(v), pos + n, nil
}

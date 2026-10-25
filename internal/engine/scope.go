package engine

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ScopeTooLargeError 表示目标范围展开后的主机数超过上限。
// CLI 用 errors.As 取出字段后翻译成当前语言，错误文本本身保持英文。
type ScopeTooLargeError struct {
	Hosts int
	Limit int
}

func (e *ScopeTooLargeError) Error() string {
	return fmt.Sprintf("scope expands to %d hosts, above the limit of %d", e.Hosts, e.Limit)
}

// ParseScope 把用户输入的目标范围展开成主机列表。
//
// 支持四种写法，可用逗号组合：
//   - 单个主机名或 IP：example.com、10.0.0.5、::1
//   - IPv4 CIDR：192.168.1.0/28
//   - IPv4 区间：192.168.1.10-192.168.1.20 或简写 192.168.1.10-20
//
// 展开结果按输入顺序去重。IPv6 仅支持单个地址：IPv6 CIDR 与区间在
// 未认证扫描中没有实际意义（/64 就有 2^64 个地址），因此直接拒绝。
func ParseScope(input string, maxHosts int) ([]string, error) {
	if maxHosts <= 0 {
		maxHosts = DefaultOptions().MaxHosts
	}

	hosts := make([]string, 0, maxHosts)
	seen := make(map[string]struct{}, maxHosts)

	for _, raw := range strings.Split(input, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}

		expanded, err := expandScopePart(part, maxHosts)
		if err != nil {
			return nil, err
		}
		for _, host := range expanded {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
			if len(hosts) > maxHosts {
				return nil, &ScopeTooLargeError{Hosts: len(hosts), Limit: maxHosts}
			}
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("scope %q contains no host", input)
	}
	return hosts, nil
}

// expandScopePart 展开单个范围片段。
func expandScopePart(part string, limit int) ([]string, error) {
	switch {
	case strings.Contains(part, "/"):
		return expandCIDR(part, limit)
	case strings.Count(part, "-") > 0 && startsWithIP(part):
		return expandRange(part, limit)
	default:
		host, err := normalizeHost(part)
		if err != nil {
			return nil, err
		}
		return []string{host}, nil
	}
}

// startsWithIP 判断 "-" 之前的部分是否为 IP，用于区分 IP 区间与含连字符的主机名。
func startsWithIP(part string) bool {
	left, _, ok := strings.Cut(part, "-")
	if !ok {
		return false
	}
	return net.ParseIP(strings.TrimSpace(left)) != nil
}

// normalizeHost 校验并规范化单个主机。
func normalizeHost(part string) (string, error) {
	if ip := net.ParseIP(part); ip != nil {
		return ip.String(), nil
	}
	if len(part) > 253 {
		return "", fmt.Errorf("host %q is too long", part)
	}
	for _, label := range strings.Split(part, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("host %q has an invalid label", part)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("host %q has an invalid label", part)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			case r == '-', r == '_':
			default:
				return "", fmt.Errorf("host %q contains an unsupported character %q", part, r)
			}
		}
	}
	return strings.ToLower(part), nil
}

// expandCIDR 展开 IPv4 CIDR。主机位数量先与上限比较，避免为 /8 这样的
// 大网段分配内存。
func expandCIDR(part string, limit int) ([]string, error) {
	ip, network, err := net.ParseCIDR(part)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("IPv6 CIDR %q is not supported, pass explicit hosts", part)
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits >= 31 {
		return nil, &ScopeTooLargeError{Hosts: limit + 1, Limit: limit}
	}
	size := 1 << hostBits
	if size > limit {
		return nil, &ScopeTooLargeError{Hosts: size, Limit: limit}
	}

	start := binary.BigEndian.Uint32(network.IP.To4())
	hosts := make([]string, 0, size)
	for offset := 0; offset < size; offset++ {
		hosts = append(hosts, uint32ToIPv4(start+uint32(offset)).String())
	}
	return hosts, nil
}

// expandRange 展开 IPv4 区间，支持完整写法和只给末段的简写。
func expandRange(part string, limit int) ([]string, error) {
	left, right, _ := strings.Cut(part, "-")
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)

	startIP := net.ParseIP(left)
	if startIP == nil {
		return nil, fmt.Errorf("invalid range start %q", left)
	}
	start := startIP.To4()
	if start == nil {
		return nil, fmt.Errorf("IPv6 range %q is not supported, pass explicit hosts", part)
	}

	var end net.IP
	if rightIP := net.ParseIP(right); rightIP != nil {
		end = rightIP.To4()
		if end == nil {
			return nil, fmt.Errorf("range %q mixes IPv4 and IPv6", part)
		}
	} else {
		last, err := strconv.Atoi(right)
		if err != nil || last < 0 || last > 255 {
			return nil, fmt.Errorf("invalid range end %q", right)
		}
		base := binary.BigEndian.Uint32(start)
		end = uint32ToIPv4(base&0xffffff00 | uint32(last))
	}

	first := binary.BigEndian.Uint32(start)
	last := binary.BigEndian.Uint32(end)
	if last < first {
		return nil, fmt.Errorf("range %q ends before it starts", part)
	}
	count := int(last-first) + 1
	if count > limit {
		return nil, &ScopeTooLargeError{Hosts: count, Limit: limit}
	}

	hosts := make([]string, 0, count)
	for addr := first; addr <= last; addr++ {
		hosts = append(hosts, uint32ToIPv4(addr).String())
		if addr == last {
			break // 防止 last 为 255.255.255.255 时回绕
		}
	}
	return hosts, nil
}

// uint32ToIPv4 把整数转换回 IPv4 地址。
func uint32ToIPv4(v uint32) net.IP {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return net.IP(buf[:])
}

package engine

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ctkqiang/vecmap/internal/constant"
	"github.com/ctkqiang/vecmap/internal/model"
)

// ParseTarget 解析单个目标字符串。
//
// 参数 raw 支持 URL、host、host:port、IPv4/IPv6 与数据库连接串。
// 返回标准化目标、从 URL 提取的凭据以及解析错误；CIDR 必须交给 ResolveTargets。
func ParseTarget(raw string) (model.Target, model.Credentials, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return model.Target{}, model.Credentials{}, fmt.Errorf("empty target")
	}
	if _, _, err := net.ParseCIDR(raw); err == nil {
		return model.Target{}, model.Credentials{}, fmt.Errorf("CIDR targets must be expanded with ResolveTargets")
	}
	if strings.Contains(raw, "://") {
		return parseURLTarget(raw)
	}
	return parseBareTarget(raw)
}

// ResolveTargets 将 CLI 目标展开为可扫描端点。
//
// 参数 raws 为原始目标列表，ports 为显式端口列表，maxHosts 为展开上限。
// 返回目标切片、与目标等长的凭据切片以及解析错误。
func ResolveTargets(raws []string, ports []int, maxHosts int) ([]model.Target, []model.Credentials, error) {
	if len(raws) == 0 {
		return nil, nil, fmt.Errorf("no targets")
	}
	if maxHosts <= 0 {
		maxHosts = 4096
	}
	targets := make([]model.Target, 0, len(raws))
	credentials := make([]model.Credentials, 0, len(raws))
	seen := map[string]struct{}{}
	add := func(target model.Target, creds model.Credentials) error {
		key := TargetKey(target)
		if _, exists := seen[key]; exists {
			return nil
		}
		if len(targets) >= maxHosts {
			return fmt.Errorf("target expansion exceeds limit of %d", maxHosts)
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
		credentials = append(credentials, creds)
		return nil
	}
	for _, raw := range raws {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(raw); err == nil {
			hosts, err := ExpandCIDR(raw, maxHosts-len(targets))
			if err != nil {
				return nil, nil, err
			}
			effectivePorts := normalizePorts(ports)
			for _, host := range hosts {
				for _, port := range effectivePorts {
					target := model.Target{
						Input:  raw,
						Scheme: SchemeForPort(port),
						Host:   host,
						Port:   port,
						TLS:    SchemeForPort(port) == "https",
					}
					if err := add(target, model.Credentials{}); err != nil {
						return nil, nil, err
					}
				}
			}
			continue
		}
		if isBareHost(raw) {
			host, path := splitHostPath(raw)
			effectivePorts := normalizePorts(ports)
			for _, port := range effectivePorts {
				target := model.Target{
					Input:  raw,
					Scheme: SchemeForPort(port),
					Host:   host,
					Port:   port,
					Path:   path,
					TLS:    SchemeForPort(port) == "https",
				}
				if err := add(target, model.Credentials{}); err != nil {
					return nil, nil, err
				}
			}
			continue
		}
		target, creds, err := ParseTarget(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", raw, err)
		}
		if err := add(target, creds); err != nil {
			return nil, nil, err
		}
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("no valid targets")
	}
	return targets, credentials, nil
}

// ExpandCIDR 展开 CIDR 中的主机地址。
//
// 参数 cidr 为 IPv4 或 IPv6 网段，limit 为最大返回地址数。
// 返回地址字符串切片；超过限制或网段过大时返回错误。
func ExpandCIDR(cidr string, limit int) ([]string, error) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if limit <= 0 {
		limit = 1
	}
	ones, bits := network.Mask.Size()
	if bits == 32 {
		size := uint64(1) << uint(bits-ones)
		if size > uint64(limit) {
			return nil, fmt.Errorf("CIDR %s contains %d addresses, limit is %d", cidr, size, limit)
		}
	} else if bits == 128 {
		if bits-ones > 12 {
			return nil, fmt.Errorf("IPv6 CIDR %s is too large to expand; use a /120 or smaller", cidr)
		}
		size := uint64(1) << uint(bits-ones)
		if size > uint64(limit) {
			return nil, fmt.Errorf("CIDR %s contains %d addresses, limit is %d", cidr, size, limit)
		}
	} else {
		return nil, fmt.Errorf("unsupported CIDR family: %s", cidr)
	}
	current := make(net.IP, len(network.IP))
	copy(current, network.IP)
	result := make([]string, 0, 16)
	for network.Contains(current) {
		result = append(result, current.String())
		if len(result) >= limit {
			break
		}
		incrementIP(current)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("CIDR %s produced no addresses", cidr)
	}
	return result, nil
}

// SchemeForPort 根据端口推断默认 URL 方案。
//
// 参数 port 为 TCP 端口；返回 http、https、postgres 或 redis。
func SchemeForPort(port int) string {
	switch port {
	case 443, 8443, 9443:
		return "https"
	case 5432:
		return "postgres"
	case 6379, 6380:
		return "redis"
	default:
		return "http"
	}
}

// TargetURL 将目标基础地址与路径拼接。
//
// 参数 target 为目标，path 为 API 路径或完整 URL。
// 返回可直接请求的 URL。
func TargetURL(target model.Target, path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	base := strings.TrimRight(target.BaseURL(), "/")
	if path == "" {
		return base
	}
	return base + "/" + strings.TrimLeft(path, "/")
}

// TargetKey 返回目标的唯一键。
//
// 参数 target 为目标；返回用于去重的规范字符串。
func TargetKey(target model.Target) string {
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	if scheme == "postgresql" {
		scheme = "postgres"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, strings.ToLower(target.Host), target.Port, normalizePath(target.Path))
}

// TargetAddress 返回目标拨号地址。
//
// 参数 target 为目标；返回 host:port，端口缺失时仅返回 host。
func TargetAddress(target model.Target) string {
	if target.Port <= 0 {
		return target.Host
	}
	return net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
}

// IsCIDR 判断输入是否为 CIDR。
//
// 参数 raw 为待判断文本；返回 true 表示可被 net.ParseCIDR 解析。
func IsCIDR(raw string) bool {
	_, _, err := net.ParseCIDR(strings.TrimSpace(raw))
	return err == nil
}

// HostPort 返回 host:port 文本。
//
// 参数 host 与 port 分别为主机与端口；返回 IPv6 安全格式。
func HostPort(host string, port int) string {
	if port <= 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func parseURLTarget(raw string) (model.Target, model.Credentials, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return model.Target{}, model.Credentials{}, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Host == "" {
		return model.Target{}, model.Credentials{}, fmt.Errorf("URL has no host")
	}
	scheme := strings.ToLower(parsed.Scheme)
	credentials := model.Credentials{}
	if parsed.User != nil {
		credentials.Username = parsed.User.Username()
		if password, exists := parsed.User.Password(); exists {
			credentials.Password = password
		}
	}
	query := parsed.Query()
	for _, key := range []string{"api_key", "apikey", "apiKey", "token"} {
		if value := query.Get(key); value != "" {
			credentials.APIKey = value
			break
		}
	}
	host := parsed.Hostname()
	tls := scheme == "https" || scheme == "grpcs" || scheme == "rediss"
	switch scheme {
	case "http", "https":
		port, err := parseOptionalPort(parsed.Port())
		if err != nil {
			return model.Target{}, model.Credentials{}, err
		}
		return model.Target{
			Input:  raw,
			Scheme: scheme,
			Host:   host,
			Port:   port,
			Path:   parsed.EscapedPath(),
			TLS:    tls,
		}, credentials, nil
	case "postgres", "postgresql":
		port, err := parseOptionalPort(parsed.Port())
		if err != nil {
			return model.Target{}, model.Credentials{}, err
		}
		if port == 0 {
			port = 5432
		}
		credentials.Database = strings.TrimPrefix(parsed.Path, "/")
		return model.Target{
			Input:  raw,
			Scheme: "postgres",
			Host:   host,
			Port:   port,
			Path:   parsed.EscapedPath(),
			TLS:    tls,
		}, credentials, nil
	case "redis", "rediss":
		port, err := parseOptionalPort(parsed.Port())
		if err != nil {
			return model.Target{}, model.Credentials{}, err
		}
		if port == 0 {
			port = 6379
		}
		if credentials.Password == "" {
			credentials.Password = query.Get("password")
		}
		return model.Target{
			Input:  raw,
			Scheme: "redis",
			Host:   host,
			Port:   port,
			TLS:    tls,
		}, credentials, nil
	case "grpc", "grpcs":
		port, err := parseOptionalPort(parsed.Port())
		if err != nil {
			return model.Target{}, model.Credentials{}, err
		}
		return model.Target{
			Input:  raw,
			Scheme: "grpc",
			Host:   host,
			Port:   port,
			TLS:    scheme == "grpcs",
		}, credentials, nil
	default:
		return model.Target{}, model.Credentials{}, fmt.Errorf("unsupported scheme: %s", scheme)
	}
}

func parseBareTarget(raw string) (model.Target, model.Credentials, error) {
	host, port, path, err := splitBareHost(raw)
	if err != nil {
		return model.Target{}, model.Credentials{}, err
	}
	scheme := SchemeForPort(port)
	return model.Target{
		Input:  raw,
		Scheme: scheme,
		Host:   host,
		Port:   port,
		Path:   path,
		TLS:    scheme == "https",
	}, model.Credentials{}, nil
}

func splitBareHost(raw string) (string, int, string, error) {
	value, path := splitHostPath(raw)
	if value == "" {
		return "", 0, "", fmt.Errorf("empty host")
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return strings.Trim(value, "[]"), 0, path, nil
	}
	if ip := net.ParseIP(value); ip != nil {
		return value, 0, path, nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err == nil {
		port, parseErr := parseRequiredPort(portText)
		if parseErr != nil {
			return "", 0, "", parseErr
		}
		return host, port, path, nil
	}
	if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		port, parseErr := parseRequiredPort(parts[1])
		if parseErr == nil {
			return parts[0], port, path, nil
		}
	}
	if strings.Contains(value, ":") {
		return "", 0, "", fmt.Errorf("invalid host or port: %s", value)
	}
	return value, 0, path, nil
}

func splitHostPath(raw string) (string, string) {
	index := strings.Index(raw, "/")
	if index < 0 {
		return strings.TrimSpace(raw), ""
	}
	return strings.TrimSpace(raw[:index]), raw[index:]
}

func isBareHost(raw string) bool {
	if strings.Contains(raw, "://") {
		return false
	}
	if IsCIDR(raw) {
		return false
	}
	host, port, _, err := splitBareHost(raw)
	return err == nil && port == 0 && host != "" && strings.TrimSpace(raw) == host
}

func parseOptionalPort(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	return parseRequiredPort(raw)
}

func parseRequiredPort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %s", raw)
	}
	return port, nil
}

func normalizePorts(ports []int) []int {
	if len(ports) == 0 {
		return constant.DefaultPorts()
	}
	seen := map[int]struct{}{}
	result := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	if len(result) == 0 {
		return constant.DefaultPorts()
	}
	return result
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func incrementIP(ip net.IP) {
	if len(ip) == 16 {
		value := binary.BigEndian.Uint64(ip[8:]) + 1
		binary.BigEndian.PutUint64(ip[8:], value)
		if value == 0 {
			high := binary.BigEndian.Uint64(ip[:8]) + 1
			binary.BigEndian.PutUint64(ip[:8], high)
		}
		return
	}
	for index := len(ip) - 1; index >= 0; index-- {
		ip[index]++
		if ip[index] != 0 {
			return
		}
	}
}

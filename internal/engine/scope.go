package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"vecmap/internal/model"
)

// ErrScopeDenied 表示目标未被授权范围覆盖。
var ErrScopeDenied = errors.New("target is outside the authorized scope")

// Scoper 执行授权范围校验。
//
// 允许列表、排除列表与端口白名单均按最小授权原则处理；
// 仅配置排除项的“排除式范围”默认为宽松，仅拒绝显式排除的目标。
type Scoper struct {
	allowedCIDRs    []*net.IPNet
	excludedCIDRs   []*net.IPNet
	allowedDomains  []string
	excludedDomains []string
	allowedPorts    map[int]struct{}
	permissive      bool
}

// NewScoper 创建范围校验器。
//
// 参数 scope 为授权范围配置；CIDR 非法时返回错误。
func NewScoper(scope model.Scope) (*Scoper, error) {
	scoper := &Scoper{allowedPorts: map[int]struct{}{}}
	for _, port := range scope.Ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid scope port: %d", port)
		}
		scoper.allowedPorts[port] = struct{}{}
	}
	var err error
	scoper.allowedCIDRs, err = parseCIDRs(scope.CIDRs)
	if err != nil {
		return nil, err
	}
	scoper.excludedCIDRs, err = parseCIDRs(scope.ExcludeCIDRs)
	if err != nil {
		return nil, err
	}
	scoper.allowedDomains = normalizeDomains(scope.Domains)
	scoper.excludedDomains = normalizeDomains(scope.ExcludeDomains)
	scoper.permissive = len(scoper.allowedCIDRs) == 0 && len(scoper.allowedDomains) == 0
	return scoper, nil
}

// Check 判断主机与端口是否位于授权范围。
//
// 参数 ctx 控制 DNS 解析超时，host 为主机名或 IP，port 为目标端口。
// 未命中允许列表或命中排除列表时返回 ErrScopeDenied。
func (s *Scoper) Check(ctx context.Context, host string, port int) error {
	if s == nil {
		return nil
	}
	if len(s.allowedPorts) > 0 && port > 0 {
		if _, exists := s.allowedPorts[port]; !exists {
			return fmt.Errorf("%w: port %d is not allowlisted", ErrScopeDenied, port)
		}
	}
	ips := resolveHost(ctx, host)
	if domainExcluded(host, s.excludedDomains) || anyIPInCIDRs(ips, s.excludedCIDRs) {
		return fmt.Errorf("%w: %s is explicitly excluded", ErrScopeDenied, host)
	}
	if s.permissive {
		return nil
	}
	if domainAllowed(host, s.allowedDomains) || anyIPInCIDRs(ips, s.allowedCIDRs) {
		return nil
	}
	return fmt.Errorf("%w: %s does not match the authorized scope", ErrScopeDenied, host)
}

// Empty 判断校验器是否完全未配置。
//
// 返回 true 表示不存在任何限制。
func (s *Scoper) Empty() bool {
	if s == nil {
		return true
	}
	return s.permissive && len(s.excludedCIDRs) == 0 && len(s.excludedDomains) == 0 && len(s.allowedPorts) == 0
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			value = value + "/32"
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid scope CIDR %q: %w", value, err)
		}
		result = append(result, network)
	}
	return result, nil
}

func normalizeDomains(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), ".")))
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func resolveHost(ctx context.Context, host string) []net.IP {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	resolver := net.Resolver{}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.IP)
	}
	return result
}

func anyIPInCIDRs(ips []net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		for _, ip := range ips {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func domainAllowed(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func domainExcluded(host string, domains []string) bool {
	return domainAllowed(host, domains)
}

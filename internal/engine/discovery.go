package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/vecmap/internal/constant"
	"github.com/ctkqiang/vecmap/internal/model"
)

// Discover 对主机与端口组合执行并发只读发现。
//
// 参数 ctx 控制整体任务生命周期，hosts 为主机列表，options 控制端口、并发与超时。
// 返回开放端口、可用目标与聚合错误；单个端口失败不会中断整体发现。
func Discover(ctx context.Context, hosts []string, options model.DiscoveryOptions) (*model.DiscoveryResult, error) {
	options = options.Normalize()
	uniqueHosts := normalizeDiscoveryHosts(hosts)
	if len(uniqueHosts) == 0 {
		return nil, fmt.Errorf("no hosts supplied")
	}
	ports := normalizeDiscoveryPorts(options.Ports)
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports supplied")
	}
	total := len(uniqueHosts) * len(ports)
	if total > 65536 {
		return nil, fmt.Errorf("discovery matrix %d exceeds limit", total)
	}
	started := time.Now()
	result := &model.DiscoveryResult{}
	var mutex sync.Mutex
	var wait sync.WaitGroup
	semaphore := make(chan struct{}, options.Concurrency)
	for _, host := range uniqueHosts {
		for _, port := range ports {
			wait.Add(1)
			go func(host string, port int) {
				defer wait.Done()
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-ctx.Done():
					return
				}
				probeCtx, cancel := context.WithTimeout(ctx, options.Timeout)
				observation := probePort(probeCtx, host, port, options)
				cancel()
				if !observation.open {
					return
				}
				mutex.Lock()
				defer mutex.Unlock()
				result.OpenPorts = append(result.OpenPorts, model.OpenPort{
					Host:     host,
					Port:     port,
					Protocol: observation.protocol,
					Banner:   observation.banner,
					TLS:      observation.tls,
					Vendor:   vendorHintForPort(port),
					Duration: observation.duration,
				})
				scheme := observation.scheme
				if scheme == "" {
					scheme = SchemeForPort(port)
				}
				result.Targets = append(result.Targets, model.Target{
					Input:     net.JoinHostPort(host, strconv.Itoa(port)),
					Scheme:    scheme,
					Host:      host,
					Port:      port,
					Vendor:    vendorHintForPort(port),
					Transport: string(observation.protocol),
					Reachable: true,
					TLS:       observation.tls,
					Banner:    observation.banner,
				})
			}(host, port)
		}
	}
	wait.Wait()
	sort.SliceStable(result.OpenPorts, func(left, right int) bool {
		if result.OpenPorts[left].Host == result.OpenPorts[right].Host {
			return result.OpenPorts[left].Port < result.OpenPorts[right].Port
		}
		return result.OpenPorts[left].Host < result.OpenPorts[right].Host
	})
	sort.SliceStable(result.Targets, func(left, right int) bool {
		if result.Targets[left].Host == result.Targets[right].Host {
			return result.Targets[left].Port < result.Targets[right].Port
		}
		return result.Targets[left].Host < result.Targets[right].Host
	})
	result.Duration = time.Since(started)
	return result, nil
}

type portObservation struct {
	open     bool
	protocol model.Protocol
	scheme   string
	banner   string
	tls      bool
	duration time.Duration
}

func probePort(ctx context.Context, host string, port int, options model.DiscoveryOptions) portObservation {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	started := time.Now()
	dialer := &net.Dialer{Timeout: options.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return portObservation{}
	}
	observation := portObservation{open: true, protocol: model.ProtocolTCP, duration: time.Since(started)}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(options.Timeout))
	switch {
	case port == 6379 || port == 6380:
		if text, ok := probeRESP(conn); ok {
			observation.protocol = model.ProtocolRESP
			observation.scheme = "redis"
			observation.banner = text
			return observation
		}
	case port == 5432:
		observation.protocol = model.ProtocolPostgres
		observation.scheme = "postgres"
		return observation
	case port == 6334 || port == 50051 || port == 19530:
		if banner, ok := probeHTTP2(conn); ok {
			observation.protocol = model.ProtocolGRPC
			observation.scheme = "grpc"
			observation.banner = banner
			return observation
		}
	}
	if banner, secure, ok := probeHTTP(conn, address, false); ok {
		observation.protocol = model.ProtocolHTTP
		observation.banner = banner
		observation.tls = secure
		if secure {
			observation.protocol = model.ProtocolHTTPS
			observation.scheme = "https"
		} else {
			observation.scheme = "http"
		}
		return observation
	}
	if banner, secure, ok := probeHTTP(conn, address, true); ok {
		observation.protocol = model.ProtocolHTTPS
		observation.scheme = "https"
		observation.banner = banner
		observation.tls = secure
		return observation
	}
	observation.scheme = SchemeForPort(port)
	if observation.scheme == "https" {
		observation.tls = true
	}
	return observation
}

func probeRESP(conn net.Conn) (string, bool) {
	payload := "*1\r\n$4\r\nPING\r\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", false
	}
	reader := bufio.NewReader(io.LimitReader(conn, 4096))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "+PONG"):
		return "PONG", true
	case strings.HasPrefix(line, "-NOAUTH"):
		return "NOAUTH (authentication required)", true
	case strings.HasPrefix(line, "-ERR"):
		return strings.TrimPrefix(line, "-"), true
	default:
		return "", false
	}
}

func probeHTTP2(conn net.Conn) (string, bool) {
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if _, err := conn.Write([]byte(preface)); err != nil {
		return "", false
	}
	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", false
	}
	frameType := header[3]
	if frameType == 4 || frameType == 0 {
		return "HTTP/2 preface accepted", true
	}
	return "", false
}

func probeHTTP(conn net.Conn, address string, secure bool) (string, bool, bool) {
	if secure {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         HostFromAddress(address),
			InsecureSkipVerify: true, //nolint:gosec
		})
		if err := tlsConn.Handshake(); err != nil {
			return "", false, false
		}
		conn = tlsConn
	}
	request := "GET / HTTP/1.0\r\nHost: " + address + "\r\nUser-Agent: vecmap/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", false, false
	}
	reader := bufio.NewReader(io.LimitReader(conn, 64*1024))
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return "", false, false
	}
	statusLine = strings.TrimSpace(statusLine)
	if !strings.HasPrefix(statusLine, "HTTP/") {
		return "", false, false
	}
	server := ""
	contentType := ""
	total := len(statusLine)
	for total < 16*1024 {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		total += len(line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "server:") {
			server = strings.TrimSpace(trimmed[len("server:"):])
		}
		if strings.HasPrefix(lower, "content-type:") {
			contentType = strings.TrimSpace(trimmed[len("content-type:"):])
		}
	}
	banner := statusLine
	if server != "" {
		banner += "; Server: " + server
	}
	if contentType != "" {
		banner += "; Content-Type: " + contentType
	}
	return banner, secure, true
}

func normalizeDiscoveryHosts(hosts []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		result = append(result, host)
	}
	sort.Strings(result)
	return result
}

func normalizeDiscoveryPorts(ports []int) []int {
	if len(ports) == 0 {
		ports = constant.DefaultPorts()
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
	sort.Ints(result)
	return result
}

func vendorHintForPort(port int) model.Vendor {
	excluded := map[int]struct{}{
		443: {}, 8080: {}, 9200: {}, 9300: {}, 9091: {}, 50051: {}, 8000: {},
	}
	if _, skip := excluded[port]; skip {
		return model.VendorUnknown
	}
	candidate := model.VendorUnknown
	for vendor, ports := range constant.VendorPorts {
		if vendor == model.VendorApache {
			continue
		}
		for _, value := range ports {
			if value != port {
				continue
			}
			if candidate != model.VendorUnknown && candidate != vendor {
				return model.VendorUnknown
			}
			candidate = vendor
		}
	}
	return candidate
}

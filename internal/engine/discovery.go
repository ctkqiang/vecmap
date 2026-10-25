// Package engine 实现 vecmap 的扫描引擎：端口发现、服务指纹识别与 Schema 枚举。
//
// 并发模型统一为「任务 channel + 固定数量 worker + 结果汇总」，
// 所有探测都带超时并支持 context 取消，避免扫描中途无法退出。
package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vecmap/internal/constant"
	"vecmap/internal/model"
)

// Tracer 接收引擎产生的底层协议事件。
// 引擎本身不依赖日志包，由调用方决定是否打印、写到哪一层。
type Tracer func(protocol, target, action, detail string)

// Options 是所有引擎共用的一组探测参数。
type Options struct {
	Timeout   time.Duration // 单次探测超时
	Workers   int           // 并发 worker 数量
	Insecure  bool          // 跳过 TLS 证书校验（自签证书场景）
	UserAgent string        // HTTP 请求 UA
	MaxHosts  int           // 单次扫描允许的最大主机数
	Trace     Tracer        // 协议事件回调，可为空
}

// trace 在设置了回调时转发一条协议事件。
func (o Options) trace(protocol, target, action, detail string) {
	if o.Trace != nil {
		o.Trace(protocol, target, action, detail)
	}
}

// DefaultOptions 返回一组稳妥的默认值。
func DefaultOptions() Options {
	return Options{
		Timeout:   800 * time.Millisecond,
		Workers:   64,
		UserAgent: "vecmap/0.1 (vector database auditing)",
		MaxHosts:  256,
	}
}

// normalized 补齐零值，避免调用方漏填导致 0 并发或 0 超时。
func (o Options) normalized() Options {
	def := DefaultOptions()
	if o.Timeout <= 0 {
		o.Timeout = def.Timeout
	}
	if o.Workers <= 0 {
		o.Workers = def.Workers
	}
	if o.UserAgent == "" {
		o.UserAgent = def.UserAgent
	}
	if o.MaxHosts <= 0 {
		o.MaxHosts = def.MaxHosts
	}
	return o
}

// DefaultPorts 返回内置的向量数据库端口，按端口号升序去重。
func DefaultPorts() []int {
	set := make(map[int]struct{}, len(constant.SupportedVendors)+2)
	for _, db := range constant.SupportedVendors {
		set[int(db.DefaultPort)] = struct{}{}
	}
	// Qdrant 的 gRPC 端口与 pgvector 使用的 PostgreSQL 端口不在默认映射里。
	set[int(constant.PortQdrantGRPC)] = struct{}{}
	set[int(constant.PortPostgres)] = struct{}{}

	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// VendorForPort 根据端口推断厂商，无法判断时返回空字符串。
func VendorForPort(port int) string {
	for vendor, db := range constant.SupportedVendors {
		if int(db.DefaultPort) == port {
			return string(vendor)
		}
	}
	if port == int(constant.PortQdrantGRPC) {
		return string(constant.VendorQdrant)
	}
	if port == int(constant.PortPostgres) {
		return string(constant.VendorPgVector)
	}
	return ""
}

// ParsePorts 解析 "8080,6333,8000-8002" 形式的端口列表，去重后升序返回。
// 空字符串返回错误，由调用方决定是否回退到 DefaultPorts。
func ParsePorts(input string) ([]int, error) {
	set := make(map[int]struct{})
	for _, raw := range strings.Split(input, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			left, right, _ := strings.Cut(part, "-")
			start, err := parsePort(left)
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			end, err := parsePort(right)
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", part, err)
			}
			if end < start {
				return nil, fmt.Errorf("port range %q ends before it starts", part)
			}
			if end-start > 65535 {
				return nil, fmt.Errorf("port range %q is too wide", part)
			}
			for port := start; port <= end; port++ {
				set[port] = struct{}{}
			}
			continue
		}

		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		set[port] = struct{}{}
	}

	if len(set) == 0 {
		return nil, fmt.Errorf("no port given")
	}

	ports := make([]int, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

// parsePort 校验单个端口号。
func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", raw)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d is out of range", port)
	}
	return port, nil
}

// Discoverer 是 TCP 端口探活器。
type Discoverer struct {
	opts Options
}

// NewDiscoverer 创建探活器。
func NewDiscoverer(opts Options) *Discoverer {
	return &Discoverer{opts: opts.normalized()}
}

// Scan 并发探测 hosts × ports 的所有组合。
// 返回结果按 host、port 排序；调用方通常只关心 Open 为 true 的条目。
func (d *Discoverer) Scan(ctx context.Context, hosts []string, ports []int) []model.DiscoveryResult {
	if len(hosts) == 0 || len(ports) == 0 {
		return nil
	}

	type job struct {
		host string
		port int
	}

	jobs := make(chan job)
	results := make(chan model.DiscoveryResult)
	var wg sync.WaitGroup

	workers := d.opts.Workers
	if workers > len(hosts)*len(ports) {
		workers = len(hosts) * len(ports)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- d.probe(ctx, j.host, j.port)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{host: host, port: port}:
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]model.DiscoveryResult, 0, len(hosts)*len(ports))
	seen := make(map[string]struct{}, len(hosts)*len(ports))
	for res := range results {
		key := fmt.Sprintf("%s:%d", res.Endpoint.Host, res.Endpoint.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		collected = append(collected, res)
	}

	sort.Slice(collected, func(i, j int) bool {
		if collected[i].Endpoint.Host != collected[j].Endpoint.Host {
			return collected[i].Endpoint.Host < collected[j].Endpoint.Host
		}
		return collected[i].Endpoint.Port < collected[j].Endpoint.Port
	})
	return collected
}

// probe 对单个 host:port 做一次 TCP 建连，能连上即视为端口开放。
// 连接会立即关闭，不发送任何业务数据，避免触发目标侧的协议解析。
func (d *Discoverer) probe(ctx context.Context, host string, port int) model.DiscoveryResult {
	res := model.DiscoveryResult{
		Endpoint: model.Endpoint{
			Host:     host,
			Port:     port,
			Protocol: string(constant.ProtocolTCP),
			Vendor:   VendorForPort(port),
		},
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialCtx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()

	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	res.Latency = time.Since(started)
	if err != nil {
		res.Err = err
		d.opts.trace(string(constant.ProtocolTCP), address, "connect", err.Error())
		return res
	}
	_ = conn.Close()

	res.Open = true
	d.opts.trace(string(constant.ProtocolTCP), address, "connect",
		fmt.Sprintf("open in %s", res.Latency.Round(time.Millisecond)))
	return res
}

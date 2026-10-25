package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/ctkqiang/vecmap/internal/constant"
	"github.com/ctkqiang/vecmap/internal/logger"
	"github.com/ctkqiang/vecmap/internal/model"
)

var (
	// ErrNotMatched 表示适配器未能识别目标产品。
	ErrNotMatched = errors.New("target did not match adapter")
	// ErrNotSupported 表示目标或接口不支持请求的操作。
	ErrNotSupported = errors.New("operation not supported")
	// ErrUnauthorized 表示目标拒绝了匿名或当前凭据访问。
	ErrUnauthorized = errors.New("target requires authentication")
)

// Adapter 定义向量数据库厂商适配器契约。
//
// 适配器负责指纹识别、只读暴露面探测与集合/记录枚举；
// 核心引擎不包含任何厂商分支，新增产品只需注册新适配器。
type Adapter interface {
	// Vendor 返回适配器对应的厂商标识。
	Vendor() model.Vendor

	// DefaultPorts 返回该厂商常见服务端口。
	DefaultPorts() []int

	// Fingerprint 识别目标产品与版本。
	//
	// 参数 ctx 控制探测超时，target 为已解析目标，options 为扫描配置。
	// 返回指纹；无法识别时返回 ErrNotMatched。
	Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error)

	// Probe 执行只读暴露面探测。
	//
	// 参数与 Fingerprint 相同；返回探测结果列表，单个路径失败不会中断整体探测。
	Probe(ctx context.Context, target *model.Target, options model.ScanOptions) ([]*model.ProbeResult, error)

	// Enumerate 执行集合枚举与只读记录提取。
	//
	// 参数 dump 控制记录上限与向量采样；返回提取结果。
	Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error)
}

// Runtime 向适配器提供共享的协议客户端与日志器。
type Runtime struct {
	HTTP *HTTPClient
	GRPC *GRPCClient
	Log  *logger.Logger
}

// NewRuntime 创建扫描运行期依赖。
//
// 参数 options 为扫描配置，log 为日志器。
// 返回共享客户端；调用方负责关闭。
func NewRuntime(options model.ScanOptions, log *logger.Logger) (*Runtime, error) {
	httpClient := NewHTTPClient(model.HTTPOptions{
		Timeout:   options.Timeout,
		Insecure:  options.Insecure,
		Proxy:     options.Proxy,
		UserAgent: options.UserAgent,
		Headers:   options.Headers,
		RateLimit: options.RateLimit,
	})
	metadata := map[string]string{}
	if options.Credentials.APIKey != "" {
		metadata["authorization"] = "Bearer " + options.Credentials.APIKey
		metadata["api-key"] = options.Credentials.APIKey
	}
	if options.Credentials.Bearer != "" {
		metadata["authorization"] = "Bearer " + options.Credentials.Bearer
	}
	grpcClient := NewGRPCClient(model.GRPCOptions{
		Timeout:  options.Timeout,
		Insecure: options.Insecure,
		Metadata: metadata,
	})
	return &Runtime{HTTP: httpClient, GRPC: grpcClient, Log: log}, nil
}

// Close 释放运行期连接资源。
//
// 返回关闭错误；空闲 HTTP 连接会被立即释放。
func (r *Runtime) Close() error {
	if r == nil || r.HTTP == nil {
		return nil
	}
	r.HTTP.Close()
	return nil
}

// Registry 管理厂商适配器注册表。
type Registry struct {
	mu       sync.RWMutex
	adapters map[model.Vendor]Adapter
	order    []model.Vendor
}

// NewRegistry 创建空适配器注册表。
//
// 返回可并发注册与查询的注册表实例。
func NewRegistry() *Registry {
	return &Registry{adapters: map[model.Vendor]Adapter{}}
}

// Register 注册厂商适配器。
//
// 参数 adapter 为适配器实例；厂商标识为空、重复或适配器为 nil 时返回错误。
func (r *Registry) Register(adapter Adapter) error {
	if adapter == nil {
		return fmt.Errorf("adapter is nil")
	}
	vendor := adapter.Vendor()
	if vendor == model.VendorUnknown {
		return fmt.Errorf("adapter vendor is unknown")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.adapters[vendor]; exists {
		return fmt.Errorf("adapter already registered: %s", vendor)
	}
	r.adapters[vendor] = adapter
	r.order = append(r.order, vendor)
	return nil
}

// Get 按厂商读取适配器。
//
// 参数 vendor 为厂商标识；返回适配器与是否存在标志。
func (r *Registry) Get(vendor model.Vendor) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, exists := r.adapters[vendor]
	return adapter, exists
}

// All 返回按注册顺序排列的适配器。
//
// 返回适配器切片；调用方不得修改切片内容。
func (r *Registry) All() []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Adapter, 0, len(r.order))
	for _, vendor := range r.order {
		result = append(result, r.adapters[vendor])
	}
	return result
}

// Vendors 返回已注册厂商列表。
//
// 返回按注册顺序排列的厂商切片。
func (r *Registry) Vendors() []model.Vendor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]model.Vendor, len(r.order))
	copy(result, r.order)
	return result
}

// ForPort 返回默认端口匹配的适配器。
//
// 参数 port 为 TCP 端口；返回去重后的适配器切片。
func (r *Registry) ForPort(port int) []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Adapter, 0, 4)
	for _, vendor := range r.order {
		adapter := r.adapters[vendor]
		if containsPort(adapter.DefaultPorts(), port) {
			result = append(result, adapter)
		}
	}
	return result
}

// Candidates 返回适合当前目标的候选适配器。
//
// 参数 target 为已解析目标；优先使用已知厂商与默认端口，其次按 URL 方案回退。
func (r *Registry) Candidates(target *model.Target) []Adapter {
	if target == nil {
		return nil
	}
	if target.Vendor != "" && target.Vendor != model.VendorUnknown {
		if adapter, exists := r.Get(target.Vendor); exists {
			return []Adapter{adapter}
		}
	}
	result := r.ForPort(target.Port)
	if isPineconeHost(target.Host) {
		if adapter, exists := r.Get(model.VendorPinecone); exists {
			result = appendUnique(result, adapter)
		}
	}
	if len(result) > 0 {
		return result
	}
	return r.byScheme(target.Scheme)
}

func (r *Registry) byScheme(scheme string) []Adapter {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Adapter, 0, len(r.order))
	for _, vendor := range r.order {
		if scheme == "" || scheme == "http" || scheme == "https" {
			if vendor == model.VendorRedis || vendor == model.VendorPgVector {
				continue
			}
			result = append(result, r.adapters[vendor])
			continue
		}
		if scheme == "redis" && vendor == model.VendorRedis {
			result = append(result, r.adapters[vendor])
		}
		if (scheme == "postgres" || scheme == "postgresql") && vendor == model.VendorPgVector {
			result = append(result, r.adapters[vendor])
		}
	}
	return result
}

func containsPort(ports []int, port int) bool {
	for _, value := range ports {
		if value == port {
			return true
		}
	}
	return false
}

func appendUnique(adapters []Adapter, adapter Adapter) []Adapter {
	for _, existing := range adapters {
		if existing.Vendor() == adapter.Vendor() {
			return adapters
		}
	}
	return append(adapters, adapter)
}

func isPineconeHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.HasSuffix(host, ".pinecone.io") || host == "api.pinecone.io"
}

// DefaultPortsFor 返回厂商端口或全局默认端口。
//
// 参数 vendor 为厂商标识；返回该厂商端口，未知厂商使用内置默认端口。
func DefaultPortsFor(vendor model.Vendor) []int {
	if ports, exists := constant.VendorPorts[vendor]; exists && len(ports) > 0 {
		result := make([]int, len(ports))
		copy(result, ports)
		return result
	}
	return constant.DefaultPorts()
}

// SortAdapters 按厂商名称排序适配器。
//
// 参数 adapters 为输入切片；返回按厂商名升序排列的新切片。
func SortAdapters(adapters []Adapter) []Adapter {
	result := make([]Adapter, len(adapters))
	copy(result, adapters)
	sort.SliceStable(result, func(left, right int) bool {
		return result[left].Vendor() < result[right].Vendor()
	})
	return result
}

// HostFromAddress 从 host:port 中提取主机。
//
// 参数 address 为网络地址；返回主机部分，解析失败时返回原值。
func HostFromAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return strings.Trim(address, "[]")
	}
	return host
}

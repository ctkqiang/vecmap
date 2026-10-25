package model

import "time"

// HTTPOptions 控制共享 HTTP 客户端行为。
type HTTPOptions struct {
	Timeout   time.Duration     `json:"timeout"`
	Insecure  bool              `json:"insecure"`
	Proxy     string            `json:"proxy,omitempty"`
	UserAgent string            `json:"user_agent"`
	Headers   map[string]string `json:"headers,omitempty"`
	RateLimit float64           `json:"rate_limit"`
	MaxBody   int64             `json:"max_body"`
}

// GRPCOptions 控制 gRPC 探测与反射行为。
type GRPCOptions struct {
	Timeout    time.Duration     `json:"timeout"`
	TLS        bool              `json:"tls"`
	Insecure   bool              `json:"insecure"`
	MaxMsgSize int               `json:"max_msg_size"`
	Metadata   map[string]string `json:"-"`
	UserAgent  string            `json:"user_agent"`
}

// DiscoveryOptions 控制端口发现行为。
type DiscoveryOptions struct {
	Ports       []int         `json:"ports,omitempty"`
	Timeout     time.Duration `json:"timeout"`
	Concurrency int           `json:"concurrency"`
	TLS         bool          `json:"tls"`
	MaxHosts    int           `json:"max_hosts"`
}

// Normalize 为发现选项补齐默认值。
//
// 返回限制在安全区间内的副本。
func (o DiscoveryOptions) Normalize() DiscoveryOptions {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	if o.Concurrency > 512 {
		o.Concurrency = 512
	}
	if o.MaxHosts <= 0 {
		o.MaxHosts = 4096
	}
	return o
}

// FuzzOptions 控制只读 REST 路径探测。
type FuzzOptions struct {
	Enabled     bool     `json:"enabled"`
	MaxRequests int      `json:"max_requests"`
	Paths       []string `json:"paths,omitempty"`
}

// Normalize 为路径探测选项补齐默认值。
//
// 返回限制在安全区间内的副本。
func (o FuzzOptions) Normalize() FuzzOptions {
	if o.MaxRequests <= 0 {
		o.MaxRequests = 120
	}
	if o.MaxRequests > 1000 {
		o.MaxRequests = 1000
	}
	return o
}

// Payload 表示导入的漏洞公告集合文件。
type Payload struct {
	Advisories []Advisory `json:"advisories"`
}

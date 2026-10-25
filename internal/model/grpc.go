package model

import "time"

// GRPCMethod 表示反射发现的一个 gRPC 方法。
type GRPCMethod struct {
	Name       string `json:"name"`
	FullName   string `json:"full_name"`
	InputType  string `json:"input_type,omitempty"`
	OutputType string `json:"output_type,omitempty"`
}

// GRPCService 表示反射发现的一个 gRPC 服务。
type GRPCService struct {
	Name     string       `json:"name"`
	Package  string       `json:"package,omitempty"`
	FullName string       `json:"full_name"`
	Methods  []GRPCMethod `json:"methods,omitempty"`
}

// GRPCInfo 表示 gRPC 端点的健康检查与反射结果。
type GRPCInfo struct {
	Reachable     bool          `json:"reachable"`
	TLS           bool          `json:"tls"`
	Status        string        `json:"status,omitempty"`
	ServingStatus string        `json:"serving_status,omitempty"`
	Reflection    bool          `json:"reflection"`
	Services      []GRPCService `json:"services,omitempty"`
	RawMessages   []string      `json:"raw_messages,omitempty"`
}

// HTTPExchange 表示一次已脱敏的 HTTP 请求/响应证据。
type HTTPExchange struct {
	ID              string    `gorm:"primaryKey;size:48" json:"id"`
	SessionID       string    `gorm:"size:48;index" json:"session_id"`
	TargetID        string    `gorm:"size:48;index" json:"target_id"`
	Method          string    `gorm:"size:12" json:"method"`
	URL             string    `gorm:"size:2048" json:"url"`
	Path            string    `gorm:"size:1024" json:"path"`
	RequestHeaders  string    `gorm:"type:text" json:"request_headers,omitempty"`
	RequestBody     string    `gorm:"type:text" json:"request_body,omitempty"`
	RequestBytes    int64     `json:"request_bytes"`
	StatusCode      int       `json:"status_code"`
	ResponseHeaders string    `gorm:"type:text" json:"response_headers,omitempty"`
	ResponseBody    string    `gorm:"type:text" json:"response_body,omitempty"`
	ContentType     string    `gorm:"size:160" json:"content_type,omitempty"`
	ResponseBytes   int64     `json:"response_bytes"`
	BodySHA256      string    `gorm:"size:64" json:"body_sha256,omitempty"`
	TLS             bool      `json:"tls"`
	Truncated       bool      `json:"truncated"`
	Error           string    `gorm:"type:text" json:"error,omitempty"`
	DurationMS      int64     `json:"duration_ms"`
	CreatedAt       time.Time `json:"created_at"`
}

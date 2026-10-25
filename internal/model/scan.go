package model

import (
	"encoding/json"
	"time"
)

// ScanMode 表示扫描深度。
type ScanMode string

const (
	// ModeStandard 执行指纹识别、暴露面分析与只读路径探测。
	ModeStandard ScanMode = "standard"
	// ModeDeep 在标准模式基础上执行集合枚举与记录提取。
	ModeDeep ScanMode = "deep"
)

// ScanOptions 控制发现、指纹、探测与提取行为。
type ScanOptions struct {
	Mode            ScanMode          `json:"mode"`
	Ports           []int             `json:"ports,omitempty"`
	Timeout         time.Duration     `json:"timeout"`
	Concurrency     int               `json:"concurrency"`
	RateLimit       float64           `json:"rate_limit"`
	Insecure        bool              `json:"insecure"`
	Fuzz            bool              `json:"fuzz"`
	Extract         bool              `json:"extract"`
	Collection      string            `json:"collection,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	MaxRecords      int               `json:"max_records"`
	BatchSize       int               `json:"batch_size"`
	IncludeVectors  bool              `json:"include_vectors"`
	MaxVectorValues int               `json:"max_vector_values"`
	UserAgent       string            `json:"user_agent"`
	Proxy           string            `json:"proxy,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Credentials     Credentials       `json:"-"`
	AdvisoriesPath  string            `json:"advisories_path,omitempty"`
	DryRun          bool              `json:"dry_run"`
}

// Normalize 为扫描选项补齐企业级默认值。
//
// 返回限制在安全区间内的副本，避免无界并发、无限提取或空 User-Agent。
func (o ScanOptions) Normalize() ScanOptions {
	if o.Mode != ModeDeep {
		o.Mode = ModeStandard
	}
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Timeout > 2*time.Minute {
		o.Timeout = 2 * time.Minute
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.Concurrency > 256 {
		o.Concurrency = 256
	}
	if o.RateLimit < 0 {
		o.RateLimit = 0
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = 200
	}
	if o.MaxRecords > 100000 {
		o.MaxRecords = 100000
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.BatchSize > 1000 {
		o.BatchSize = 1000
	}
	if o.MaxVectorValues <= 0 {
		o.MaxVectorValues = 256
	}
	if o.UserAgent == "" {
		o.UserAgent = "github.com/ctkqiang/vecmap/1.0"
	}
	if o.Headers == nil {
		o.Headers = map[string]string{}
	}
	if o.Extract && o.Mode != ModeDeep {
		o.Mode = ModeDeep
	}
	return o
}

// DumpOptions 将扫描选项转换为数据枚举选项。
//
// 返回只读提取所需的采集上限与向量采样配置。
func (o ScanOptions) DumpOptions() DumpOptions {
	return DumpOptions{
		Collection:      o.Collection,
		Namespace:       o.Namespace,
		MaxRecords:      o.MaxRecords,
		BatchSize:       o.BatchSize,
		IncludeVectors:  o.IncludeVectors,
		MaxVectorValues: o.MaxVectorValues,
		ExtractRecords:  o.Extract,
	}.Normalize()
}

// RedactedJSON 返回可安全写入会话记录的选项摘要。
//
// 返回 JSON 文本；密码、API Key 与 DSN 等敏感字段不会被序列化。
func (o ScanOptions) RedactedJSON() string {
	payload, err := json.Marshal(o)
	if err != nil {
		return "{}"
	}
	return string(payload)
}

// ScanRequest 表示应用层发起的一次扫描任务。
type ScanRequest struct {
	Targets    []string    `json:"targets"`
	Name       string      `json:"name,omitempty"`
	Scope      Scope       `json:"scope"`
	Options    ScanOptions `json:"options"`
	Authorized bool        `json:"authorized"`
}

// ScanResult 汇总一次扫描的内存结果。
type ScanResult struct {
	Session     *Session        `json:"session"`
	Targets     []*Target       `json:"targets"`
	Findings    []*Finding      `json:"findings"`
	Collections []*Collection   `json:"collections"`
	Records     []*Record       `json:"records"`
	Probes      []*ProbeResult  `json:"probes"`
	Exchanges   []*HTTPExchange `json:"-"`
	Steps       []*Step         `json:"steps"`
	Errors      []string        `json:"errors,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	Duration    time.Duration   `json:"duration"`
}

// HTTPInfo 表示通用 HTTP 指纹信息。
type HTTPInfo struct {
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	BodyPreview  string   `json:"body_preview,omitempty"`
	Redirect     string   `json:"redirect,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

// Fingerprint 表示目标的产品与版本指纹。
type Fingerprint struct {
	Vendor       Vendor         `json:"vendor"`
	Product      string         `json:"product,omitempty"`
	Version      string         `json:"version,omitempty"`
	Confidence   Confidence     `json:"confidence"`
	AuthRequired bool           `json:"auth_required"`
	AuthType     AuthType       `json:"auth_type,omitempty"`
	TLS          bool           `json:"tls"`
	Server       string         `json:"server,omitempty"`
	Banner       string         `json:"banner,omitempty"`
	Evidence     []string       `json:"evidence,omitempty"`
	Endpoints    []Endpoint     `json:"endpoints,omitempty"`
	GRPC         *GRPCInfo      `json:"grpc,omitempty"`
	HTTP         *HTTPInfo      `json:"http,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// ProbeResult 表示持久化的只读探测结果。
type ProbeResult struct {
	ID           string    `gorm:"primaryKey;size:48" json:"id"`
	SessionID    string    `gorm:"size:48;index" json:"session_id"`
	TargetID     string    `gorm:"size:48;index" json:"target_id"`
	Vendor       Vendor    `gorm:"size:32" json:"vendor"`
	Protocol     string    `gorm:"size:24" json:"protocol"`
	Method       string    `gorm:"size:12" json:"method"`
	Path         string    `gorm:"size:512" json:"path"`
	StatusCode   int       `json:"status_code"`
	AuthRequired bool      `json:"auth_required"`
	Sensitive    bool      `json:"sensitive"`
	Category     string    `gorm:"size:64;index" json:"category"`
	Summary      string    `gorm:"type:text" json:"summary"`
	SummaryZH    string    `gorm:"type:text" json:"summary_zh,omitempty"`
	ExchangeID   string    `gorm:"size:48" json:"exchange_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// OpenPort 表示发现阶段识别到的开放端口。
type OpenPort struct {
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	Protocol Protocol      `json:"protocol"`
	Banner   string        `json:"banner,omitempty"`
	TLS      bool          `json:"tls"`
	Vendor   Vendor        `json:"vendor,omitempty"`
	Duration time.Duration `json:"duration"`
}

// DiscoveryResult 表示端口发现结果。
type DiscoveryResult struct {
	OpenPorts []OpenPort    `json:"open_ports"`
	Targets   []Target      `json:"targets"`
	Duration  time.Duration `json:"duration"`
	Errors    []string      `json:"errors,omitempty"`
}

// SessionBundle 表示报告与导出所需的聚合数据。
type SessionBundle struct {
	Session     *Session        `json:"session"`
	Targets     []*Target       `json:"targets"`
	Findings    []*Finding      `json:"findings"`
	Collections []*Collection   `json:"collections"`
	Records     []*Record       `json:"records"`
	Probes      []*ProbeResult  `json:"probes"`
	Steps       []*Step         `json:"steps"`
	Endpoints   []*Endpoint     `json:"endpoints"`
	Exchanges   []*HTTPExchange `json:"-"`
}

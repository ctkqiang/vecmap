package model

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Session 表示一次本地扫描会话。
//
// 会话是目标、步骤、发现、集合与提取记录的聚合根，所有证据均可在离线状态复现。
type Session struct {
	ID              string     `gorm:"primaryKey;size:48" json:"id"`
	Name            string     `gorm:"size:200;index" json:"name"`
	Mode            string     `gorm:"size:32" json:"mode"`
	Language        string     `gorm:"size:8" json:"language"`
	Status          string     `gorm:"size:32;index" json:"status"`
	Authorized      bool       `json:"authorized"`
	ScopeJSON       string     `gorm:"type:text" json:"-"`
	OptionsJSON     string     `gorm:"type:text" json:"-"`
	TargetCount     int        `json:"targets"`
	FindingCount    int        `json:"findings"`
	CollectionCount int        `json:"collections"`
	RecordCount     int        `json:"records"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Target 表示会话中被探测的单个端点。
type Target struct {
	ID              string    `gorm:"primaryKey;size:48" json:"id"`
	SessionID       string    `gorm:"size:48;index" json:"session_id"`
	Input           string    `gorm:"size:512" json:"input"`
	Scheme          string    `gorm:"size:24" json:"scheme"`
	Host            string    `gorm:"size:255;index" json:"host"`
	Port            int       `json:"port"`
	Path            string    `gorm:"size:255" json:"path"`
	Vendor          Vendor    `gorm:"size:32;index" json:"vendor"`
	Product         string    `gorm:"size:120" json:"product"`
	Version         string    `gorm:"size:80" json:"version"`
	Transport       string    `gorm:"size:16" json:"transport"`
	Reachable       bool      `json:"reachable"`
	AuthRequired    bool      `json:"auth_required"`
	TLS             bool      `json:"tls"`
	Server          string    `gorm:"size:255" json:"server"`
	Banner          string    `gorm:"type:text" json:"banner"`
	FingerprintJSON string    `gorm:"type:text" json:"-"`
	CreatedAt       time.Time `json:"created_at"`
}

// Address 返回适合网络拨号的 host:port。
//
// 返回 IPv6 会自动加上方括号；端口未知时仅返回主机。
func (t Target) Address() string {
	if t.Port <= 0 {
		return t.Host
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// BaseURL 返回该目标的 HTTP(S) 基础地址。
//
// 返回地址会保留用户输入的子路径，并自动处理 IPv6 与默认端口。
func (t Target) BaseURL() string {
	scheme := strings.ToLower(strings.TrimSpace(t.Scheme))
	if scheme == "" {
		if t.TLS {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := t.Host
	if host == "" {
		return ""
	}
	address := host
	if t.Port > 0 && !isDefaultPort(scheme, t.Port) {
		address = net.JoinHostPort(host, strconv.Itoa(t.Port))
	} else if strings.Contains(host, ":") {
		address = "[" + host + "]"
	}
	path := strings.TrimSpace(t.Path)
	if path != "" && path != "/" {
		path = "/" + strings.TrimLeft(path, "/")
	}
	return fmt.Sprintf("%s://%s%s", scheme, address, path)
}

// GRPCAddress 返回适合 gRPC 拨号的 host:port。
//
// 返回值为端口为空或非法时回退到 Address。
func (t Target) GRPCAddress() string {
	return t.Address()
}

func isDefaultPort(scheme string, port int) bool {
	switch scheme {
	case "http":
		return port == 80
	case "https":
		return port == 443
	case "postgres", "postgresql":
		return port == 5432
	default:
		return false
	}
}

// Scope 表示本次评估允许覆盖的网络范围。
//
// 所有主动探测在发起前必须通过 Scope 校验，避免越界扫描。
type Scope struct {
	CIDRs          []string `json:"cidrs,omitempty"`
	Domains        []string `json:"domains,omitempty"`
	ExcludeCIDRs   []string `json:"exclude_cidrs,omitempty"`
	ExcludeDomains []string `json:"exclude_domains,omitempty"`
	Ports          []int    `json:"ports,omitempty"`
}

// Empty 判断范围是否为空。
//
// 返回 true 表示未配置显式范围，调用方应采用目标自身主机作为默认范围。
func (s Scope) Empty() bool {
	return len(s.CIDRs) == 0 && len(s.Domains) == 0
}

// Credentials 表示运行期认证材料。
//
// 该结构不会原样写入数据库或报告，持久化前必须调用 Redacted。
type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"-"`
	APIKey   string `json:"-"`
	Bearer   string `json:"-"`
	Database string `json:"database,omitempty"`
	DSN      string `json:"-"`
}

// Empty 判断是否未提供任何认证材料。
//
// 返回 true 表示当前请求应当按匿名访问处理。
func (c Credentials) Empty() bool {
	return c.Username == "" && c.Password == "" && c.APIKey == "" &&
		c.Bearer == "" && c.Database == "" && c.DSN == ""
}

// Redacted 返回可安全持久化的认证摘要。
//
// 返回副本仅保留用户名与数据库名，所有密钥字段均被清空。
func (c Credentials) Redacted() Credentials {
	return Credentials{Username: c.Username, Database: c.Database}
}

// Step 表示扫描过程中的一个可审计步骤。
type Step struct {
	ID         string    `gorm:"primaryKey;size:48" json:"id"`
	SessionID  string    `gorm:"size:48;index" json:"session_id"`
	TargetID   string    `gorm:"size:48;index" json:"target_id"`
	Phase      string    `gorm:"size:48;index" json:"phase"`
	Action     string    `gorm:"size:160" json:"action"`
	Protocol   string    `gorm:"size:24" json:"protocol"`
	Status     string    `gorm:"size:24" json:"status"`
	Detail     string    `gorm:"type:text" json:"detail"`
	Error      string    `gorm:"type:text" json:"error,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

// Endpoint 表示已发现的 HTTP/gRPC 端点或 API 路径。
type Endpoint struct {
	ID           string    `gorm:"primaryKey;size:48" json:"id"`
	SessionID    string    `gorm:"size:48;index" json:"session_id"`
	TargetID     string    `gorm:"size:48;index" json:"target_id"`
	Vendor       Vendor    `gorm:"size:32" json:"vendor"`
	Protocol     string    `gorm:"size:24" json:"protocol"`
	Method       string    `gorm:"size:12" json:"method"`
	Path         string    `gorm:"size:512" json:"path"`
	Status       string    `gorm:"size:24" json:"status"`
	AuthRequired bool      `json:"auth_required"`
	Summary      string    `gorm:"type:text" json:"summary"`
	TagsJSON     string    `gorm:"type:text" json:"-"`
	ExchangeID   string    `gorm:"size:48" json:"exchange_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

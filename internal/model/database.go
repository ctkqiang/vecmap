// Package model 存放 vecmap 的数据结构（DTO）：纯类型定义，不含任何函数。
//
// 会话（Session）→ 目标（Target）→ 漏洞（Vulnerability）三层结构，
// 外加一条按序号排列的操作步骤（Step）历史，全部落在本地 SQLite 中。
//
// 读写函数统一放在 internal/database/local.go，本包不依赖任何内部包，
// 由 database 单向引用，避免出现循环依赖。
package model

import (
	"time"

	"gorm.io/gorm"
)

// 会话状态，写入 session_records.status 字段。
const (
	StatusRunning   = "running"   // 进行中
	StatusCompleted = "completed" // 已完成，数据可直接回放
	StatusAborted   = "aborted"   // 已中止
)

// 漏洞严重级别，与报告输出保持一致的英文大写写法。
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// SessionRecord 代表一次扫描会话。该次运行中发现的所有目标、漏洞以及操作
// 步骤都挂在会话下，这样历史会话可以整体从 SQLite 回放，不必重复扫描。
type SessionRecord struct {
	gorm.Model
	SessionName string `gorm:"uniqueIndex;not null"` // 会话名，全局唯一，便于按名回看
	TargetScope string // 目标范围，例如 "192.168.1.0/24"
	Language    string // 本次运行使用的界面语言，例如 "en" / "zh"
	Status      string `gorm:"index;not null;default:running"`
	StartedAt   time.Time
	FinishedAt  *time.Time
	Targets     []TargetRecord `gorm:"foreignKey:SessionID"`
	Steps       []StepRecord   `gorm:"foreignKey:SessionID"`
}

// TargetRecord 记录会话中发现的一个 host:port 端点及其探测结果。
type TargetRecord struct {
	gorm.Model
	SessionID       uint                  `gorm:"uniqueIndex:idx_target_unique;not null"`
	Host            string                `gorm:"uniqueIndex:idx_target_unique;index;not null"`
	Port            int                   `gorm:"uniqueIndex:idx_target_unique;not null"`
	Protocol        string                `gorm:"uniqueIndex:idx_target_unique;not null"`
	Engine          string                `gorm:"index"` // 探测引擎，例如 "nmap"、"httpx"
	Version         string                // 识别到的服务版本
	IsVulnerable    bool                  `gorm:"not null;default:false"`
	FindingsCount   int                   `gorm:"not null;default:0"` // 该目标下的漏洞数量
	Vulnerabilities []VulnerabilityRecord `gorm:"foreignKey:TargetID"`
}

// StepRecord 是会话的审计线索：端口扫描、服务识别、版本探测、漏洞检测等
// 每一步按顺序落库，包含执行结果与耗时，用于回放与复盘。
type StepRecord struct {
	gorm.Model
	SessionID  uint   `gorm:"index;not null"`
	Seq        int    `gorm:"uniqueIndex:idx_step_seq;not null"` // 会话内从 1 开始的步骤序号
	Action     string `gorm:"index;not null"`                    // 步骤代码，同时是本地化键，如 "step.port.scan"
	Target     string // 作用对象：host、host:port 或目标范围
	Detail     string // 附加信息，引擎输出摘要等
	Success    bool   `gorm:"not null;default:false"`
	StartedAt  time.Time
	DurationMs int64 // 耗时（毫秒）
}

// VulnerabilityRecord 保存明确的漏洞发现，可关联 CVE 与 MITRE ATT&CK TTP。
type VulnerabilityRecord struct {
	gorm.Model
	TargetID    uint `gorm:"index;not null"`
	SessionID   uint `gorm:"index"` // 冗余存储，便于按会话快速统计
	Title       string
	Severity    string `gorm:"index"`
	CVE         string `gorm:"index"`
	Code        string `gorm:"index"` // 非 CVE 发现的代码，见 model 中的 FindingCode 常量
	Data        string // 非 CVE 发现的参数，JSON 编码，回放时重新生成文案
	MitreTTP    string
	Fixed       string // 修复版本，来自公告
	Reference   string // 公告链接，便于复核
	Description string
}

// TargetInput 是写入目标时的入参结构，对应一次端点探测结果。
type TargetInput struct {
	Host     string
	Port     int
	Protocol string
	Engine   string
	Version  string
}

// StepInput 是写入步骤历史时的入参结构，对应一次执行动作。
type StepInput struct {
	Action   string // 步骤代码，例如 localisation.go 中的 KeyStepScanPort
	Target   string // 作用对象
	Detail   string // 附加信息
	Success  bool   // 是否成功
	Duration time.Duration
}

// VulnInput 是写入漏洞发现时的入参结构。
type VulnInput struct {
	Title       string
	Severity    string
	CVE         string
	Code        string
	Data        string
	MitreTTP    string
	Fixed       string
	Reference   string
	Description string
}

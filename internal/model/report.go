package model

import "time"

// ReportFormat 表示报告输出格式。
type ReportFormat string

const (
	// ReportMarkdown 输出 Markdown 报告。
	ReportMarkdown ReportFormat = "markdown"
	// ReportJSON 输出 JSON 报告。
	ReportJSON ReportFormat = "json"
	// ReportHTML 输出 HTML 报告。
	ReportHTML ReportFormat = "html"
)

// ReportOptions 控制报告生成行为。
type ReportOptions struct {
	Format   ReportFormat `json:"format"`
	Language string       `json:"language"`
	Path     string       `json:"path,omitempty"`
}

// Normalize 为报告选项补齐默认值。
//
// 返回 format 与 language 均已验证的副本。
func (o ReportOptions) Normalize() ReportOptions {
	switch o.Format {
	case ReportMarkdown, ReportJSON, ReportHTML:
	default:
		o.Format = ReportMarkdown
	}
	if o.Language != "zh" && o.Language != "en" {
		o.Language = "en"
	}
	return o
}

// RiskSummary 汇总报告中的风险分布。
type RiskSummary struct {
	Critical    int      `json:"critical"`
	High        int      `json:"high"`
	Medium      int      `json:"medium"`
	Low         int      `json:"low"`
	Info        int      `json:"info"`
	Total       int      `json:"total"`
	MaxSeverity Severity `json:"max_severity,omitempty"`
}

// MITREUsage 汇总单条 MITRE 技术在本报告中的使用情况。
type MITREUsage struct {
	Technique  MITRETechnique `json:"technique"`
	Count      int            `json:"count"`
	FindingIDs []string       `json:"finding_ids,omitempty"`
}

// Report 表示一次会话的完整评估报告。
type Report struct {
	SessionID   string          `json:"session_id"`
	SessionName string          `json:"session_name"`
	Language    string          `json:"language"`
	GeneratedAt time.Time       `json:"generated_at"`
	StartedAt   time.Time       `json:"started_at,omitempty"`
	EndedAt     *time.Time      `json:"ended_at,omitempty"`
	Duration    time.Duration   `json:"duration"`
	Summary     RiskSummary     `json:"summary"`
	Targets     []*Target       `json:"targets"`
	Findings    []*Finding      `json:"findings"`
	Collections []*Collection   `json:"collections"`
	Records     []*Record       `json:"records"`
	MITRE       []MITREUsage    `json:"mitre"`
	Advisories  []*Advisory     `json:"advisories,omitempty"`
	Exchanges   []*HTTPExchange `json:"exchanges,omitempty"`
}

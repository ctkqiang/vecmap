// Package reporter 把一次扫描会话整理成结构化报告：目标、版本、CVE、
// 漏洞明细与 MITRE ATT&CK 映射，可直接输出到终端或导出 JSON。
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"vecmap/internal/constant"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// Finding 是报告中的一条发现。
type Finding struct {
	Kind        string `json:"kind"`
	Target      string `json:"target"`
	Vendor      string `json:"vendor,omitempty"`
	Version     string `json:"version,omitempty"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	CVE         string `json:"cve,omitempty"`
	TTP         string `json:"ttp"`
	TTPName     string `json:"ttp_name"`
	Description string `json:"description,omitempty"`
	Fixed       string `json:"fixed,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// Target 是报告中的一个端点摘要。
type Target struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Version  string `json:"version,omitempty"`
	Findings int    `json:"findings"`
}

// Summary 按严重级别统计发现数量。
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Report 是一次会话的完整报告。
type Report struct {
	Session     string     `json:"session"`
	Scope       string     `json:"scope"`
	Status      string     `json:"status"`
	Language    string     `json:"language,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	GeneratedAt time.Time  `json:"generated_at"`
	Targets     []Target   `json:"targets"`
	Findings    []Finding  `json:"findings"`
	Summary     Summary    `json:"summary"`
}

// 报告样式。颜色只影响终端，JSON 输出不受影响。
var (
	reportTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	reportSectionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	reportMutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	reportBorderStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

// Build 把落库后的会话整理成报告。没有任何目标或漏洞时也返回一份
// 结构完整的报告，调用方无需额外判空。
func Build(session *model.SessionRecord) Report {
	report := Report{GeneratedAt: time.Now()}
	if session == nil {
		return report
	}

	report.Session = session.SessionName
	report.Scope = session.TargetScope
	report.Status = session.Status
	report.Language = session.Language
	report.StartedAt = session.StartedAt
	report.FinishedAt = session.FinishedAt

	targets := append([]model.TargetRecord(nil), session.Targets...)
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Host != targets[j].Host {
			return targets[i].Host < targets[j].Host
		}
		return targets[i].Port < targets[j].Port
	})

	for _, target := range targets {
		address := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
		summary := Target{
			Address:  address,
			Protocol: target.Protocol,
			Vendor:   target.Engine,
			Version:  target.Version,
			Findings: len(target.Vulnerabilities),
		}

		vulns := append([]model.VulnerabilityRecord(nil), target.Vulnerabilities...)
		sort.SliceStable(vulns, func(i, j int) bool {
			return severityRank(vulns[i].Severity) > severityRank(vulns[j].Severity)
		})

		for _, vuln := range vulns {
			kind := findingKind(vuln)
			ttp := vuln.MitreTTP
			if ttp == "" {
				ttp = MapKind(kind)
			}
			technique := TechniqueOf(ttp)
			title, description, fixed, reference := resolveFinding(vuln)

			report.Findings = append(report.Findings, Finding{
				Kind:        string(kind),
				Target:      address,
				Vendor:      target.Engine,
				Version:     target.Version,
				Title:       title,
				Severity:    strings.ToUpper(vuln.Severity),
				CVE:         vuln.CVE,
				TTP:         technique.ID,
				TTPName:     technique.Name,
				Description: description,
				Fixed:       fixed,
				Reference:   reference,
			})
			report.Summary.add(vuln.Severity)
		}
		report.Targets = append(report.Targets, summary)
	}
	return report
}

// findingKind 依据发现代码、TTP 与 CVE 推断发现类别：
// 数据读取代码与 T1213/T1005 表示外泄，带 CVE 的是已知漏洞，
// 其余归为暴露面。
func findingKind(vuln model.VulnerabilityRecord) model.FindingKind {
	switch {
	case vuln.Code == model.FindingCodeExfiltration:
		return model.FindingExfiltration
	case vuln.MitreTTP == TTPDataFromInfoRepo, vuln.MitreTTP == TTPDataFromLocalSystem:
		return model.FindingExfiltration
	case vuln.CVE != "":
		return model.FindingVulnerability
	default:
		return model.FindingExposure
	}
}

// resolveFinding 按当前界面语言重新生成发现的文案。
// CVE 条目从内置公告目录重新取词，非 CVE 条目由 Code + Data 还原，
// 因此历史会话在另一种语言下回放时不会出现中英混杂。
func resolveFinding(vuln model.VulnerabilityRecord) (title, description, fixed, reference string) {
	title, description = vuln.Title, vuln.Description
	fixed, reference = vuln.Fixed, vuln.Reference

	if vuln.CVE != "" {
		entry, ok := constant.LookupCVE(vuln.CVE)
		if !ok {
			return
		}
		return AdvisoryTitle(entry), AdvisoryDescription(entry), entry.Fixed, entry.Reference
	}
	if vuln.Code == "" {
		return
	}

	var data model.FindingData
	if err := json.Unmarshal([]byte(vuln.Data), &data); err != nil {
		return
	}

	switch vuln.Code {
	case model.FindingCodeAnonymous:
		return utilities.T(utilities.KeyFindingAnonymousTitle),
			utilities.Tf(utilities.KeyFindingAnonymousDesc, data.Vendor),
			"", ""
	case model.FindingCodeMetadata:
		return utilities.T(utilities.KeyFindingMetadataTitle),
			utilities.Tf(utilities.KeyFindingMetadataDesc, data.Collections, data.Vendor),
			"", ""
	case model.FindingCodeExfiltration:
		description = utilities.Tf(utilities.KeyFindingExfilDesc, data.Samples, data.Vendor)
		if data.KnnHits > 0 {
			description += " " + utilities.Tf(utilities.KeyFindingKnnDesc, data.KnnHits)
		}
		return utilities.T(utilities.KeyFindingExfilTitle), description, "", ""
	default:
		return
	}
}

// severityRank 用于报告内排序，数值越大越严重。
func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// add 记录一条发现并累加对应级别计数。
func (s *Summary) add(severity string) {
	s.Total++
	switch strings.ToUpper(severity) {
	case model.SeverityCritical:
		s.Critical++
	case model.SeverityHigh:
		s.High++
	case model.SeverityMedium:
		s.Medium++
	case model.SeverityLow:
		s.Low++
	default:
		s.Info++
	}
}

// AdvisoryTitle 按当前界面语言选择公告标题。
func AdvisoryTitle(entry constant.CVEEntry) string {
	if utilities.Locale() == utilities.Chinese && entry.TitleZH != "" {
		return entry.TitleZH
	}
	return entry.Title
}

// AdvisoryDescription 按当前界面语言选择公告说明。
func AdvisoryDescription(entry constant.CVEEntry) string {
	if utilities.Locale() == utilities.Chinese && entry.DescriptionZH != "" {
		return entry.DescriptionZH
	}
	return entry.Description
}

// WriteJSON 以缩进格式写出报告，不转义 HTML 字符，便于直接阅读与入库。
func WriteJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

// Render 把报告写到终端。所有分节标题与字段名都经过本地化，
// 颜色只用于区分严重级别，不影响日志与 JSON。
func Render(w io.Writer, report Report) error {
	border := reportBorderStyle.Render(strings.Repeat("─", 64))

	if _, err := fmt.Fprintln(w, border); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  %s\n", reportTitleStyle.Render(utilities.T(utilities.KeyReportHeader))); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, border); err != nil {
		return err
	}

	for _, line := range []string{
		utilities.Tf(utilities.KeyReportSession, report.Session),
		utilities.Tf(utilities.KeyReportScope, report.Scope),
		utilities.Tf(utilities.KeyReportStatus, statusLabel(report.Status)),
		utilities.Tf(utilities.KeyReportGenerated, report.GeneratedAt.Format("2006-01-02 15:04:05")),
	} {
		if _, err := fmt.Fprintf(w, "  %s\n", line); err != nil {
			return err
		}
	}

	if err := renderTargets(w, report); err != nil {
		return err
	}
	if err := renderFindings(w, report); err != nil {
		return err
	}
	return renderSummary(w, report)
}

// renderTargets 输出目标列表。
func renderTargets(w io.Writer, report Report) error {
	if _, err := fmt.Fprintf(w, "\n  %s %s\n",
		reportSectionStyle.Render(utilities.T(utilities.KeyReportTargets)),
		reportMutedStyle.Render(fmt.Sprintf("(%d)", len(report.Targets)))); err != nil {
		return err
	}

	if len(report.Targets) == 0 {
		_, err := fmt.Fprintf(w, "  %s\n", reportMutedStyle.Render(utilities.T(utilities.KeyReportNoTargets)))
		return err
	}

	for _, target := range report.Targets {
		version := strings.TrimSpace(strings.Join([]string{target.Vendor, target.Version}, " "))
		if version == "" {
			version = "-"
		}
		if _, err := fmt.Fprintf(w, "  %-24s %-8s %s %s\n",
			target.Address,
			target.Protocol,
			version,
			reportMutedStyle.Render(fmt.Sprintf("(%d)", target.Findings))); err != nil {
			return err
		}
	}
	return nil
}

// renderFindings 按目标聚合输出发现明细。
func renderFindings(w io.Writer, report Report) error {
	if _, err := fmt.Fprintf(w, "\n  %s %s\n",
		reportSectionStyle.Render(utilities.T(utilities.KeyReportFindings)),
		reportMutedStyle.Render(fmt.Sprintf("(%d)", len(report.Findings)))); err != nil {
		return err
	}

	if len(report.Findings) == 0 {
		_, err := fmt.Fprintf(w, "  %s\n", reportMutedStyle.Render(utilities.T(utilities.KeyReportNoFindings)))
		return err
	}

	for _, finding := range report.Findings {
		title := finding.Title
		if finding.CVE != "" {
			title = finding.CVE + " — " + title
		}
		if _, err := fmt.Fprintf(w, "  %s %s\n", severityTag(finding.Severity), title); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "        %s\n", reportMutedStyle.Render(
			utilities.Tf(utilities.KeyReportTarget, finding.Target))); err != nil {
			return err
		}

		technique := TechniqueOf(finding.TTP)
		if _, err := fmt.Fprintf(w, "        %s\n", reportMutedStyle.Render(
			utilities.Tf(utilities.KeyReportTTPLine, technique.ID, techniqueName(technique)))); err != nil {
			return err
		}

		if finding.Fixed != "" {
			if _, err := fmt.Fprintf(w, "        %s\n", reportMutedStyle.Render(
				utilities.Tf(utilities.KeyReportFix, finding.Fixed))); err != nil {
				return err
			}
		}
		if finding.Reference != "" {
			if _, err := fmt.Fprintf(w, "        %s\n", reportMutedStyle.Render(
				utilities.Tf(utilities.KeyReportReference, finding.Reference))); err != nil {
				return err
			}
		}
		if finding.Description != "" {
			if _, err := fmt.Fprintf(w, "        %s\n", finding.Description); err != nil {
				return err
			}
		}
	}
	return nil
}

// renderSummary 输出按严重级别统计的汇总行。
func renderSummary(w io.Writer, report Report) error {
	if _, err := fmt.Fprintf(w, "\n  %s\n  ", reportSectionStyle.Render(utilities.T(utilities.KeyReportSummary))); err != nil {
		return err
	}

	parts := []string{
		fmt.Sprintf("%s %d", utilities.T(utilities.KeySeverityCritical), report.Summary.Critical),
		fmt.Sprintf("%s %d", utilities.T(utilities.KeySeverityHigh), report.Summary.High),
		fmt.Sprintf("%s %d", utilities.T(utilities.KeySeverityMedium), report.Summary.Medium),
		fmt.Sprintf("%s %d", utilities.T(utilities.KeySeverityLow), report.Summary.Low),
	}
	if _, err := fmt.Fprintln(w, strings.Join(parts, "   ")); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "  %s\n", reportMutedStyle.Render(
		utilities.Tf(utilities.KeyReportTotal, report.Summary.Total)))
	return err
}

// severityTag 渲染带颜色的严重级别标签。
func severityTag(severity string) string {
	style := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
	switch strings.ToUpper(severity) {
	case model.SeverityCritical:
		style = style.Foreground(lipgloss.Color("196"))
	case model.SeverityHigh:
		style = style.Foreground(lipgloss.Color("208"))
	case model.SeverityMedium:
		style = style.Foreground(lipgloss.Color("214"))
	case model.SeverityLow:
		style = style.Foreground(lipgloss.Color("75"))
	}
	return style.Render("[" + severityLabel(severity) + "]")
}

// severityLabel 返回本地化的严重级别名称。
func severityLabel(severity string) string {
	switch strings.ToUpper(severity) {
	case model.SeverityCritical:
		return utilities.T(utilities.KeySeverityCritical)
	case model.SeverityHigh:
		return utilities.T(utilities.KeySeverityHigh)
	case model.SeverityMedium:
		return utilities.T(utilities.KeySeverityMedium)
	case model.SeverityLow:
		return utilities.T(utilities.KeySeverityLow)
	default:
		return utilities.T(utilities.KeySeverityInfo)
	}
}

// statusLabel 返回本地化的会话状态名称。
func statusLabel(status string) string {
	switch status {
	case model.StatusRunning:
		return utilities.T(utilities.KeyStatusRunning)
	case model.StatusCompleted:
		return utilities.T(utilities.KeyStatusCompleted)
	case model.StatusAborted:
		return utilities.T(utilities.KeyStatusAborted)
	default:
		return status
	}
}

// techniqueName 按当前界面语言选择技术名称。
func techniqueName(technique Technique) string {
	if utilities.Locale() == utilities.Chinese && technique.NameZH != "" {
		return technique.NameZH
	}
	return technique.Name
}

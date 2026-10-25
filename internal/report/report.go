package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"vecmap/internal/constant"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// Builder 根据会话聚合数据构建评估报告。
type Builder struct {
	Language string
}

// New 创建报告构建器。
//
// 参数 language 为报告语言，取值 en 或 zh。
// 返回可复用的构建器。
func New(language string) *Builder {
	if language != "zh" && language != "en" {
		language = "en"
	}
	return &Builder{Language: language}
}

// Build 将会话聚合数据转换为报告模型。
//
// 参数 bundle 为数据库聚合结果，advisories 为公告目录副本。
// 返回包含风险汇总、MITRE 覆盖与证据附录的报告。
func (b *Builder) Build(bundle *model.SessionBundle, advisories []model.Advisory) *model.Report {
	report := &model.Report{
		Language:    b.Language,
		GeneratedAt: time.Now().UTC(),
		Targets:     bundle.Targets,
		Findings:    bundle.Findings,
		Collections: bundle.Collections,
		Records:     bundle.Records,
		Exchanges:   bundle.Exchanges,
	}
	if bundle.Session != nil {
		report.SessionID = bundle.Session.ID
		report.SessionName = bundle.Session.Name
		report.StartedAt = bundle.Session.StartedAt
		report.EndedAt = bundle.Session.EndedAt
	}
	if report.EndedAt != nil {
		report.Duration = report.EndedAt.Sub(report.StartedAt)
	}
	report.Summary = summarizeFindings(bundle.Findings)
	report.MITRE = summarizeMITRE(bundle.Findings, b.Language)
	report.Advisories = resolveAdvisories(bundle.Findings, advisories)
	return report
}

// Render 按格式渲染报告文本。
//
// 参数 report 为报告模型，format 为输出格式。
// 返回渲染后的文本；不支持的格式返回错误。
func (b *Builder) Render(report *model.Report, format model.ReportFormat) (string, error) {
	switch format {
	case model.ReportMarkdown:
		return b.renderMarkdown(report), nil
	case model.ReportJSON:
		return renderJSON(report)
	case model.ReportHTML:
		return b.renderHTML(report), nil
	default:
		return "", fmt.Errorf("unsupported report format: %s", format)
	}
}

// Write 将报告渲染并写入文件。
//
// 参数 report 为报告模型，options 为格式与路径配置。
// 返回写入错误；文件以仅属主权限写入。
func (b *Builder) Write(report *model.Report, options model.ReportOptions) error {
	options = options.Normalize()
	if options.Path == "" {
		return fmt.Errorf("report path is empty")
	}
	content, err := b.Render(report, options.Format)
	if err != nil {
		return err
	}
	return utilities.WriteFilePrivate(options.Path, []byte(content))
}

func summarizeFindings(findings []*model.Finding) model.RiskSummary {
	summary := model.RiskSummary{}
	for _, finding := range findings {
		summary.Total++
		switch finding.Severity {
		case model.SeverityCritical:
			summary.Critical++
		case model.SeverityHigh:
			summary.High++
		case model.SeverityMedium:
			summary.Medium++
		case model.SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
		if finding.Severity.Rank() > summary.MaxSeverity.Rank() {
			summary.MaxSeverity = finding.Severity
		}
	}
	return summary
}

func summarizeMITRE(findings []*model.Finding, language string) []model.MITREUsage {
	counts := map[string]*model.MITREUsage{}
	for _, finding := range findings {
		for _, id := range finding.MITRE() {
			technique, exists := constant.MITREByID(id)
			if !exists {
				technique = model.MITRETechnique{ID: id, Name: id, NameZH: id}
			}
			usage, ok := counts[id]
			if !ok {
				usage = &model.MITREUsage{Technique: technique}
				counts[id] = usage
			}
			usage.Count++
			usage.FindingIDs = append(usage.FindingIDs, finding.ID)
		}
	}
	result := make([]model.MITREUsage, 0, len(counts))
	for _, usage := range counts {
		result = append(result, *usage)
	}
	sort.SliceStable(result, func(left, right int) bool {
		return result[left].Technique.ID < result[right].Technique.ID
	})
	return result
}

// mitreName 返回按界面语言本地化的技术名称。
//
// 参数 technique 为技术条目，language 为 en 或 zh。
func mitreName(technique model.MITRETechnique, language string) string {
	if language == "zh" && technique.NameZH != "" {
		return technique.NameZH
	}
	return technique.Name
}

// mitreTactic 返回按界面语言本地化的战术名称。
//
// 参数 technique 为技术条目，language 为 en 或 zh。
func mitreTactic(technique model.MITRETechnique, language string) string {
	if language == "zh" && technique.TacticZH != "" {
		return technique.TacticZH
	}
	return technique.Tactic
}

func resolveAdvisories(findings []*model.Finding, advisories []model.Advisory) []*model.Advisory {
	byID := map[string]model.Advisory{}
	for _, advisory := range advisories {
		byID[advisory.ID] = advisory
		if advisory.CVE != "" {
			byID[advisory.CVE] = advisory
		}
		if advisory.CNVD != "" {
			byID[advisory.CNVD] = advisory
		}
	}
	seen := map[string]struct{}{}
	result := make([]*model.Advisory, 0, 4)
	for _, finding := range findings {
		key := utilities.FirstNonEmpty(finding.AdvisoryID, finding.CVE, finding.CNVD)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if advisory, ok := byID[key]; ok {
			copyAdvisory := advisory
			result = append(result, &copyAdvisory)
		}
	}
	sort.SliceStable(result, func(left, right int) bool {
		return result[left].ID < result[right].ID
	})
	return result
}

func (b *Builder) t(key string) string {
	return utilities.TIn(b.Language, key)
}

func (b *Builder) tf(key string, args ...any) string {
	return utilities.TfIn(b.Language, key, args...)
}

func (b *Builder) title(finding *model.Finding) string {
	if b.Language == "zh" && finding.TitleZH != "" {
		return finding.TitleZH
	}
	return finding.Title
}

func (b *Builder) description(finding *model.Finding) string {
	if b.Language == "zh" && finding.DescriptionZH != "" {
		return finding.DescriptionZH
	}
	return finding.Description
}

func (b *Builder) impact(finding *model.Finding) string {
	if b.Language == "zh" && finding.ImpactZH != "" {
		return finding.ImpactZH
	}
	return finding.Impact
}

func (b *Builder) remediation(finding *model.Finding) string {
	if b.Language == "zh" && finding.RemediationZH != "" {
		return finding.RemediationZH
	}
	return finding.Remediation
}

func (b *Builder) severityLabel(severity model.Severity) string {
	key := "report.severity." + string(severity)
	label := b.t(key)
	if label == key {
		return string(severity)
	}
	return label
}

func renderJSON(report *model.Report) (string, error) {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode report JSON: %w", err)
	}
	return string(payload) + "\n", nil
}

func (b *Builder) renderMarkdown(report *model.Report) string {
	var output strings.Builder
	output.WriteString("# " + b.t("report.title") + "\n\n")
	if report.SessionName != "" {
		output.WriteString(fmt.Sprintf("**%s:** %s\n\n", b.t("report.session"), report.SessionName))
	}
	output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.generated"), report.GeneratedAt.UTC().Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.session"), report.SessionID))
	if !report.StartedAt.IsZero() {
		output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.started"), report.StartedAt.UTC().Format(time.RFC3339)))
	}
	if report.EndedAt != nil {
		output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.ended"), report.EndedAt.UTC().Format(time.RFC3339)))
	}
	output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.duration"), utilities.FormatDuration(report.Duration)))
	output.WriteString(fmt.Sprintf("- **%s:** %d / **%s:** %d / **%s:** %d\n\n", b.t("report.targets"), len(report.Targets), b.t("report.collections"), len(report.Collections), b.t("report.records"), len(report.Records)))

	output.WriteString("## " + b.t("report.summary") + "\n\n")
	output.WriteString("| " + b.t("report.severity.critical") + " | " + b.t("report.severity.high") + " | " + b.t("report.severity.medium") + " | " + b.t("report.severity.low") + " | " + b.t("report.severity.info") + " | " + b.t("report.field.status") + " |\n")
	output.WriteString("|---|---|---|---|---|---|\n")
	output.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d | %d |\n\n", report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Low, report.Summary.Info, report.Summary.Total))

	output.WriteString("## " + b.t("report.findings") + "\n\n")
	if len(report.Findings) == 0 {
		output.WriteString(b.t("report.none") + "\n\n")
	} else {
		for index, finding := range report.Findings {
			output.WriteString(fmt.Sprintf("### %d. %s\n\n", index+1, markdownEscape(b.title(finding))))
			output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.severity."+string(finding.Severity)), b.severityLabel(finding.Severity)))
			output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.field.target"), finding.TargetID))
			if finding.CVE != "" {
				output.WriteString(fmt.Sprintf("- **CVE:** %s\n", finding.CVE))
			}
			if finding.CNVD != "" {
				output.WriteString(fmt.Sprintf("- **CNVD:** %s\n", finding.CNVD))
			}
			if finding.CVSSScore > 0 {
				output.WriteString(fmt.Sprintf("- **CVSS:** %.1f\n", finding.CVSSScore))
			}
			output.WriteString(fmt.Sprintf("- **%s:** %s\n", b.t("report.confidence"), finding.Confidence))
			description := b.description(finding)
			if description != "" {
				output.WriteString("\n" + markdownEscape(description) + "\n")
			}
			impact := b.impact(finding)
			if impact != "" {
				output.WriteString("\n**" + b.t("report.impact") + ":** " + markdownEscape(impact) + "\n")
			}
			remediation := b.remediation(finding)
			if remediation != "" {
				output.WriteString("\n**" + b.t("report.remediation") + ":** " + markdownEscape(remediation) + "\n")
			}
			if evidence := finding.Evidence(); len(evidence) > 0 {
				output.WriteString("\n**" + b.t("report.evidence") + ":**\n\n")
				for _, item := range evidence {
					output.WriteString("- " + markdownEscape(item) + "\n")
				}
			}
			if references := finding.References(); len(references) > 0 {
				output.WriteString("\n**" + b.t("report.references") + ":**\n\n")
				for _, reference := range references {
					output.WriteString("- [" + markdownEscape(utilities.FirstNonEmpty(reference.Title, reference.URL)) + "](" + reference.URL + ")\n")
				}
			}
			if techniques := finding.MITRE(); len(techniques) > 0 {
				output.WriteString("\n**MITRE:** " + strings.Join(techniques, ", ") + "\n")
			}
			output.WriteString("\n")
		}
	}

	output.WriteString("## " + b.t("report.targets") + "\n\n")
	output.WriteString("| " + b.t("report.field.target") + " | " + b.t("report.field.vendor") + " | " + b.t("report.field.product") + " | " + b.t("report.field.version") + " | " + b.t("report.field.auth") + " | " + b.t("report.field.transport") + " |\n")
	output.WriteString("|---|---|---|---|---|---|\n")
	for _, target := range report.Targets {
		auth := "no"
		if target.AuthRequired {
			auth = "yes"
		}
		output.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			markdownEscape(target.BaseURL()), target.Vendor, markdownEscape(target.Product), markdownEscape(target.Version), auth, markdownEscape(target.Transport)))
	}
	output.WriteString("\n")

	output.WriteString("## " + b.t("report.collections") + "\n\n")
	output.WriteString("| " + b.t("report.field.collection") + " | " + b.t("report.field.namespace") + " | " + b.t("report.field.dimension") + " | " + b.t("report.field.metric") + " | " + b.t("report.field.index") + " | " + b.t("report.field.points") + " |\n")
	output.WriteString("|---|---|---|---|---|---|\n")
	for _, collection := range report.Collections {
		points := "0"
		if collection.PointCount > 0 {
			points = fmt.Sprintf("%d", collection.PointCount)
		}
		output.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s |\n",
			markdownEscape(collection.Name), markdownEscape(collection.Namespace), collection.Dimension, markdownEscape(collection.Metric), markdownEscape(collection.IndexType), points))
	}
	output.WriteString("\n")

	output.WriteString("## " + b.t("report.records") + "\n\n")
	if len(report.Records) == 0 {
		output.WriteString(b.t("report.none") + "\n\n")
	} else {
		output.WriteString("| " + b.t("report.field.collection") + " | " + b.t("report.field.external_id") + " | " + b.t("report.field.dimension") + " |\n")
		output.WriteString("|---|---|---|\n")
		limit := len(report.Records)
		if limit > 200 {
			limit = 200
		}
		for _, record := range report.Records[:limit] {
			output.WriteString(fmt.Sprintf("| %s | %s | %d |\n", markdownEscape(record.CollectionName), markdownEscape(record.ExternalID), record.VectorDim))
		}
		output.WriteString("\n")
	}

	output.WriteString("## " + b.t("report.mitre") + "\n\n")
	if len(report.MITRE) == 0 {
		output.WriteString(b.t("report.none") + "\n\n")
	} else {
		output.WriteString("| ID | Name | Tactic | Count |\n")
		output.WriteString("|---|---|---|---|\n")
		for _, usage := range report.MITRE {
			output.WriteString(fmt.Sprintf("| %s | %s | %s | %d |\n", usage.Technique.ID, markdownEscape(mitreName(usage.Technique, b.Language)), markdownEscape(mitreTactic(usage.Technique, b.Language)), usage.Count))
		}
		output.WriteString("\n")
	}

	if len(report.Advisories) > 0 {
		output.WriteString("## " + b.t("report.advisories") + "\n\n")
		for _, advisory := range report.Advisories {
			output.WriteString(fmt.Sprintf("- **%s** — %s\n", advisory.ID, markdownEscape(utilities.FirstNonEmpty(advisory.Title, advisory.Summary))))
		}
		output.WriteString("\n")
	}

	output.WriteString("## " + b.t("report.appendix") + "\n\n")
	if len(report.Exchanges) == 0 {
		output.WriteString(b.t("report.none") + "\n")
	} else {
		output.WriteString("| " + b.t("report.field.method") + " | " + b.t("report.field.path") + " | " + b.t("report.field.status") + " | " + b.t("report.field.bytes") + " |\n")
		output.WriteString("|---|---|---|---|\n")
		for _, exchange := range report.Exchanges {
			output.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n", markdownEscape(exchange.Method), markdownEscape(exchange.Path), exchange.StatusCode, utilities.FormatBytes(exchange.ResponseBytes)))
		}
		output.WriteString("\n")
	}
	return output.String()
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="{{.Language}}">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:2rem auto;max-width:960px;padding:0 1rem;color:#1c2733;line-height:1.55}
h1{border-bottom:3px solid #2d6cdf;padding-bottom:.4rem}
h2{border-bottom:1px solid #ccd6e0;padding-bottom:.25rem;margin-top:2rem}
h3{margin-top:1.5rem}
table{border-collapse:collapse;width:100%;margin:.6rem 0}
th,td{border:1px solid #ccd6e0;padding:.35rem .55rem;text-align:left;font-size:.92rem}
th{background:#eef3fa}
.sev-critical{color:#b00020;font-weight:700}
.sev-high{color:#d04a00;font-weight:700}
.sev-medium{color:#b07d00;font-weight:700}
.sev-low{color:#2e7d32;font-weight:700}
code{background:#f2f5f9;padding:.1rem .3rem;border-radius:3px}
</style>
</head>
<body>
{{.Body}}
</body>
</html>`))

func (b *Builder) renderHTML(report *model.Report) string {
	var body bytes.Buffer
	body.WriteString("<h1>" + template.HTMLEscapeString(b.t("report.title")) + "</h1>")
	body.WriteString("<p><strong>" + template.HTMLEscapeString(b.t("report.session")) + ":</strong> " + template.HTMLEscapeString(report.SessionID) + "</p>")
	body.WriteString("<p><strong>" + template.HTMLEscapeString(b.t("report.generated")) + ":</strong> " + report.GeneratedAt.UTC().Format(time.RFC3339) + "</p>")
	body.WriteString("<p><strong>" + template.HTMLEscapeString(b.t("report.duration")) + ":</strong> " + template.HTMLEscapeString(utilities.FormatDuration(report.Duration)) + "</p>")

	body.WriteString("<h2>" + template.HTMLEscapeString(b.t("report.summary")) + "</h2>")
	body.WriteString("<table><tr><th>" + template.HTMLEscapeString(b.t("report.severity.critical")) + "</th><th>" + template.HTMLEscapeString(b.t("report.severity.high")) + "</th><th>" + template.HTMLEscapeString(b.t("report.severity.medium")) + "</th><th>" + template.HTMLEscapeString(b.t("report.severity.low")) + "</th><th>" + template.HTMLEscapeString(b.t("report.severity.info")) + "</th></tr>")
	body.WriteString(fmt.Sprintf("<tr><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr></table>", report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Low, report.Summary.Info))

	body.WriteString("<h2>" + template.HTMLEscapeString(b.t("report.findings")) + "</h2>")
	if len(report.Findings) == 0 {
		body.WriteString("<p>" + template.HTMLEscapeString(b.t("report.none")) + "</p>")
	} else {
		for _, finding := range report.Findings {
			severityClass := "sev-" + string(finding.Severity)
			body.WriteString("<h3>" + template.HTMLEscapeString(b.title(finding)) + " <span class=\"" + severityClass + "\">" + template.HTMLEscapeString(string(finding.Severity)) + "</span></h3>")
			body.WriteString("<p>" + template.HTMLEscapeString(b.description(finding)) + "</p>")
			if impact := b.impact(finding); impact != "" {
				body.WriteString("<p><strong>" + template.HTMLEscapeString(b.t("report.impact")) + ":</strong> " + template.HTMLEscapeString(impact) + "</p>")
			}
			if remediation := b.remediation(finding); remediation != "" {
				body.WriteString("<p><strong>" + template.HTMLEscapeString(b.t("report.remediation")) + ":</strong> " + template.HTMLEscapeString(remediation) + "</p>")
			}
			if techniques := finding.MITRE(); len(techniques) > 0 {
				body.WriteString("<p><strong>MITRE:</strong> " + template.HTMLEscapeString(strings.Join(techniques, ", ")) + "</p>")
			}
		}
	}

	body.WriteString("<h2>" + template.HTMLEscapeString(b.t("report.targets")) + "</h2>")
	body.WriteString("<table><tr><th>" + template.HTMLEscapeString(b.t("report.field.target")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.vendor")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.product")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.version")) + "</th></tr>")
	for _, target := range report.Targets {
		body.WriteString("<tr><td>" + template.HTMLEscapeString(target.BaseURL()) + "</td><td>" + template.HTMLEscapeString(string(target.Vendor)) + "</td><td>" + template.HTMLEscapeString(target.Product) + "</td><td>" + template.HTMLEscapeString(target.Version) + "</td></tr>")
	}
	body.WriteString("</table>")

	body.WriteString("<h2>" + template.HTMLEscapeString(b.t("report.collections")) + "</h2>")
	body.WriteString("<table><tr><th>" + template.HTMLEscapeString(b.t("report.field.collection")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.dimension")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.metric")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.index")) + "</th></tr>")
	for _, collection := range report.Collections {
		body.WriteString("<tr><td>" + template.HTMLEscapeString(collection.Name) + "</td><td>" + fmt.Sprintf("%d", collection.Dimension) + "</td><td>" + template.HTMLEscapeString(collection.Metric) + "</td><td>" + template.HTMLEscapeString(collection.IndexType) + "</td></tr>")
	}
	body.WriteString("</table>")

	body.WriteString("<h2>" + template.HTMLEscapeString(b.t("report.mitre")) + "</h2>")
	body.WriteString("<table><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Count</th></tr>")
	for _, usage := range report.MITRE {
		body.WriteString("<tr><td>" + template.HTMLEscapeString(usage.Technique.ID) + "</td><td>" + template.HTMLEscapeString(mitreName(usage.Technique, b.Language)) + "</td><td>" + template.HTMLEscapeString(mitreTactic(usage.Technique, b.Language)) + "</td><td>" + fmt.Sprintf("%d", usage.Count) + "</td></tr>")
	}
	body.WriteString("</table>")

	body.WriteString("<h2>" + template.HTMLEscapeString(b.t("report.appendix")) + "</h2>")
	body.WriteString("<table><tr><th>" + template.HTMLEscapeString(b.t("report.field.method")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.path")) + "</th><th>" + template.HTMLEscapeString(b.t("report.field.status")) + "</th></tr>")
	for _, exchange := range report.Exchanges {
		body.WriteString("<tr><td>" + template.HTMLEscapeString(exchange.Method) + "</td><td>" + template.HTMLEscapeString(exchange.Path) + "</td><td>" + fmt.Sprintf("%d", exchange.StatusCode) + "</td></tr>")
	}
	body.WriteString("</table>")

	var rendered bytes.Buffer
	_ = htmlTemplate.Execute(&rendered, map[string]any{
		"Language": report.Language,
		"Title":    b.t("report.title"),
		"Body":     template.HTML(body.String()), //nolint:gosec
	})
	return rendered.String()
}

func markdownEscape(value string) string {
	replacer := strings.NewReplacer("|", "\\|", "\n", " ")
	return replacer.Replace(value)
}

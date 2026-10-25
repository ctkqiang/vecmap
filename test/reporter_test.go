package test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"vecmap/internal/constant"
	"vecmap/internal/model"
	"vecmap/internal/reporter"
	"vecmap/internal/utilities"
)

// sampleSession 构造一次包含 CVE 与暴露面发现的已完成会话。
func sampleSession() *model.SessionRecord {
	started := time.Now().Add(-2 * time.Minute)
	finished := time.Now().Add(-time.Minute)

	return &model.SessionRecord{
		SessionName: "lab",
		TargetScope: "10.0.0.0/30",
		Language:    "en",
		Status:      model.StatusCompleted,
		StartedAt:   started,
		FinishedAt:  &finished,
		Targets: []model.TargetRecord{
			{
				Host:     "10.0.0.1",
				Port:     8080,
				Protocol: "HTTP",
				Engine:   "Weaviate",
				Version:  "1.30.10",
				Vulnerabilities: []model.VulnerabilityRecord{
					{
						Title:       "Path traversal in backup restore (ZipSlip)",
						Severity:    model.SeverityHigh,
						CVE:         "CVE-2025-67818",
						MitreTTP:    reporter.TTPExploitPublicFacing,
						Fixed:       "1.30.20",
						Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2025-67818",
						Description: "zip slip",
					},
					{
						Title:       "Anonymous access enabled",
						Severity:    model.SeverityMedium,
						MitreTTP:    reporter.TTPExploitPublicFacing,
						Description: "no credentials required",
					},
				},
			},
			{
				Host:     "10.0.0.2",
				Port:     6333,
				Protocol: "HTTP",
				Engine:   "Qdrant",
				Version:  "1.15.5",
			},
		},
	}
}

// TestReporterBuild 校验目标排序、发现排序、类别映射与严重级别汇总。
func TestReporterBuild(t *testing.T) {
	utilities.SetLocale(utilities.English)
	defer utilities.SetLocale(utilities.English)

	report := reporter.Build(sampleSession())

	if report.Session != "lab" || report.Scope != "10.0.0.0/30" || report.Status != model.StatusCompleted {
		t.Fatalf("report header = %+v", report)
	}
	if len(report.Targets) != 2 || len(report.Findings) != 2 {
		t.Fatalf("targets=%d findings=%d", len(report.Targets), len(report.Findings))
	}
	if report.Targets[0].Address != "10.0.0.1:8080" || report.Targets[1].Address != "10.0.0.2:6333" {
		t.Fatalf("target order = %s, %s", report.Targets[0].Address, report.Targets[1].Address)
	}
	if report.Targets[0].Findings != 2 || report.Targets[1].Findings != 0 {
		t.Fatalf("finding counts = %d, %d", report.Targets[0].Findings, report.Targets[1].Findings)
	}

	if report.Findings[0].Severity != model.SeverityHigh || report.Findings[1].Severity != model.SeverityMedium {
		t.Fatalf("findings are not sorted by severity: %+v", report.Findings)
	}
	if report.Findings[0].Kind != string(model.FindingVulnerability) {
		t.Fatalf("CVE finding kind = %q", report.Findings[0].Kind)
	}
	if report.Findings[1].Kind != string(model.FindingExposure) {
		t.Fatalf("exposure finding kind = %q", report.Findings[1].Kind)
	}
	if report.Findings[0].TTP != reporter.TTPExploitPublicFacing ||
		report.Findings[0].TTPName != "Exploit Public-Facing Application" {
		t.Fatalf("TTP mapping = %q %q", report.Findings[0].TTP, report.Findings[0].TTPName)
	}
	if report.Findings[0].Fixed == "" || report.Findings[0].Reference == "" {
		t.Fatalf("advisory metadata lost: %+v", report.Findings[0])
	}
	entry, ok := constant.LookupCVE("CVE-2025-67818")
	if !ok || report.Findings[0].Fixed != entry.Fixed {
		t.Fatalf("fixed version = %q, want catalog value %q", report.Findings[0].Fixed, entry.Fixed)
	}

	summary := report.Summary
	if summary.Total != 2 || summary.High != 1 || summary.Medium != 1 {
		t.Fatalf("summary = %+v", summary)
	}

	report = reporter.Build(nil)
	if report.Session != "" || report.GeneratedAt.IsZero() {
		t.Fatalf("empty report = %+v", report)
	}
}

// TestReporterRender 校验终端输出包含会话、CVE 与技术编号。
func TestReporterRender(t *testing.T) {
	utilities.SetLocale(utilities.English)
	defer utilities.SetLocale(utilities.English)

	var buffer bytes.Buffer
	if err := reporter.Render(&buffer, reporter.Build(sampleSession())); err != nil {
		t.Fatalf("Render: %v", err)
	}

	output := buffer.String()
	for _, want := range []string{"lab", "10.0.0.1:8080", "CVE-2025-67818", "T1190", "1.30.20"} {
		if !strings.Contains(output, want) {
			t.Fatalf("render output missing %q:\n%s", want, output)
		}
	}
}

// TestReporterJSON 校验 JSON 导出字段与汇总计数。
func TestReporterJSON(t *testing.T) {
	utilities.SetLocale(utilities.English)
	defer utilities.SetLocale(utilities.English)

	var buffer bytes.Buffer
	if err := reporter.WriteJSON(&buffer, reporter.Build(sampleSession())); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	output := buffer.String()
	for _, want := range []string{`"session": "lab"`, `"high": 1`, `"total": 2`, `"ttp": "T1190"`} {
		if !strings.Contains(output, want) {
			t.Fatalf("JSON output missing %q:\n%s", want, output)
		}
	}
}

// TestReporterAdvisoryLocalisation 校验公告文案随界面语言切换。
func TestReporterAdvisoryLocalisation(t *testing.T) {
	entry := constant.CVEs[0]
	if entry.TitleZH == "" || entry.DescriptionZH == "" {
		t.Fatal("catalog entry is missing the Chinese advisory text")
	}

	utilities.SetLocale(utilities.Chinese)
	if got := reporter.AdvisoryTitle(entry); got != entry.TitleZH {
		t.Fatalf("zh title = %q, want %q", got, entry.TitleZH)
	}
	if got := reporter.AdvisoryDescription(entry); got != entry.DescriptionZH {
		t.Fatalf("zh description mismatch")
	}

	utilities.SetLocale(utilities.English)
	if got := reporter.AdvisoryTitle(entry); got != entry.Title {
		t.Fatalf("en title = %q, want %q", got, entry.Title)
	}
}

// TestReporterReplayLocalisation 校验按中文落库的历史会话在英文界面回放时，
// CVE 与非 CVE 发现的标题、说明都会按当前语言重新生成。
func TestReporterReplayLocalisation(t *testing.T) {
	entry, ok := constant.LookupCVE("CVE-2025-67818")
	if !ok || entry.TitleZH == "" || entry.DescriptionZH == "" {
		t.Fatal("catalog entry CVE-2025-67818 is missing")
	}

	session := &model.SessionRecord{
		SessionName: "replay",
		TargetScope: "10.0.0.1",
		Language:    string(utilities.Chinese),
		Status:      model.StatusCompleted,
		Targets: []model.TargetRecord{
			{
				Host: "10.0.0.1", Port: 8080, Protocol: "HTTP", Engine: "Weaviate",
				Vulnerabilities: []model.VulnerabilityRecord{
					{
						Title: entry.TitleZH, Description: entry.DescriptionZH,
						Severity: model.SeverityHigh, CVE: entry.ID,
						Fixed: entry.Fixed, Reference: entry.Reference,
					},
					{
						Title: "无凭证即可读取向量数据", Description: "中文说明",
						Severity: model.SeverityHigh,
						Code:     model.FindingCodeExfiltration,
						Data:     `{"vendor":"Weaviate","samples":3,"knn_hits":1}`,
					},
					{
						Title: "允许匿名访问", Description: "中文说明",
						Severity: model.SeverityMedium,
						Code:     model.FindingCodeAnonymous,
						Data:     `{"vendor":"Weaviate"}`,
					},
				},
			},
		},
	}

	utilities.SetLocale(utilities.English)
	defer utilities.SetLocale(utilities.English)

	report := reporter.Build(session)
	if len(report.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(report.Findings))
	}

	byCVE, byCode := map[string]reporter.Finding{}, map[string]reporter.Finding{}
	for _, finding := range report.Findings {
		switch {
		case finding.CVE != "":
			byCVE[finding.CVE] = finding
		case finding.Title == utilities.T(utilities.KeyFindingExfilTitle):
			byCode[model.FindingCodeExfiltration] = finding
		case finding.Title == utilities.T(utilities.KeyFindingAnonymousTitle):
			byCode[model.FindingCodeAnonymous] = finding
		}
	}

	cve, ok := byCVE[entry.ID]
	if !ok {
		t.Fatal("CVE finding is missing from the report")
	}
	if cve.Title != entry.Title {
		t.Fatalf("replayed CVE title = %q, want %q", cve.Title, entry.Title)
	}
	if cve.Description != entry.Description {
		t.Fatalf("replayed CVE description was not re-localised")
	}

	exfil, ok := byCode[model.FindingCodeExfiltration]
	if !ok {
		t.Fatal("exfiltration finding is missing from the report")
	}
	for _, want := range []string{"3 record(s)", "1 record(s)"} {
		if !strings.Contains(exfil.Description, want) {
			t.Fatalf("exfiltration description %q missing %q", exfil.Description, want)
		}
	}

	anonymous, ok := byCode[model.FindingCodeAnonymous]
	if !ok {
		t.Fatal("anonymous finding is missing from the report")
	}
	if !strings.Contains(anonymous.Description, "Weaviate") {
		t.Fatalf("anonymous description = %q", anonymous.Description)
	}
}

// TestMITREMapping 校验发现类别到 ATT&CK 技术的默认映射。
func TestMITREMapping(t *testing.T) {
	cases := map[model.FindingKind]string{
		model.FindingDiscovery:     reporter.TTPNetworkServiceDiscovery,
		model.FindingExposure:      reporter.TTPExploitPublicFacing,
		model.FindingVulnerability: reporter.TTPExploitPublicFacing,
		model.FindingExfiltration:  reporter.TTPDataFromInfoRepo,
	}
	for kind, want := range cases {
		if got := reporter.MapKind(kind); got != want {
			t.Fatalf("MapKind(%q) = %q, want %q", kind, got, want)
		}
	}

	unknown := reporter.TechniqueOf("T9999")
	if unknown.ID != "T9999" || unknown.Name == "" {
		t.Fatalf("unknown technique = %+v", unknown)
	}
}

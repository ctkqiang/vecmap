package test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vecmap/internal/model"
	"vecmap/internal/report"
	"vecmap/internal/utilities"
)

func TestBuilderBuildAndRenderMarkdown(t *testing.T) {
	bundle := sampleBundle(t)
	builder := report.New("en")
	built := builder.Build(bundle, nil)
	if built.Summary.Total != 1 || built.Summary.Critical != 1 {
		t.Fatalf("unexpected risk summary: %+v", built.Summary)
	}
	if len(built.MITRE) != 2 {
		t.Fatalf("expected 2 MITRE techniques, got %d", len(built.MITRE))
	}
	content, err := builder.Render(built, model.ReportMarkdown)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"# Vector Database Attack-Surface Assessment Report", "Risk Summary", "CVE-2024-3829", "T1210"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected markdown to contain %q", want)
		}
	}
}

func TestBuilderRenderChinese(t *testing.T) {
	bundle := sampleBundle(t)
	builder := report.New("zh")
	built := builder.Build(bundle, nil)
	content, err := builder.Render(built, model.ReportMarkdown)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(content, "风险") {
		t.Fatalf("expected Chinese section headers, got: %s", content[:200])
	}
	if !strings.Contains(content, "远程服务利用") {
		t.Fatalf("expected localized MITRE technique name in Chinese report")
	}
	if !strings.Contains(content, "横向移动") {
		t.Fatalf("expected localized MITRE tactic name in Chinese report")
	}
}

func TestBuilderRenderJSON(t *testing.T) {
	builder := report.New("en")
	built := builder.Build(sampleBundle(t), nil)
	content, err := builder.Render(built, model.ReportJSON)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var decoded model.Report
	if err := json.Unmarshal([]byte(content), &decoded); err != nil {
		t.Fatalf("rendered JSON does not parse: %v", err)
	}
	if decoded.SessionID != built.SessionID {
		t.Fatalf("round-trip session mismatch")
	}
}

func TestBuilderRenderHTML(t *testing.T) {
	builder := report.New("en")
	built := builder.Build(sampleBundle(t), nil)
	content, err := builder.Render(built, model.ReportHTML)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(content, "<html") || !strings.Contains(content, "</html>") {
		t.Fatalf("expected HTML document, got %s", content[:100])
	}
}

func TestBuilderUnsupportedFormat(t *testing.T) {
	builder := report.New("en")
	if _, err := builder.Render(builder.Build(sampleBundle(t), nil), model.ReportFormat("yaml")); err == nil {
		t.Fatalf("expected unsupported format to fail")
	}
}

func TestBuilderWrite(t *testing.T) {
	builder := report.New("en")
	built := builder.Build(sampleBundle(t), nil)
	path := t.TempDir() + "/report.md"
	if err := builder.Write(built, model.ReportOptions{Format: model.ReportMarkdown, Path: path}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := utilities.ReadJSONFile(path, &map[string]any{}); err == nil {
		t.Fatalf("expected markdown file to not parse as JSON")
	}
}

func sampleBundle(t *testing.T) *model.SessionBundle {
	t.Helper()
	now := time.Now().UTC()
	session := &model.Session{
		ID:        "ses_test",
		Name:      "sample",
		Mode:      "deep",
		Status:    "completed",
		StartedAt: now,
	}
	finding := &model.Finding{
		ID:         "fnd_test",
		SessionID:  session.ID,
		TargetID:   "tgt_test",
		Title:      "Vulnerable version: CVE-2024-3829",
		Severity:   model.SeverityCritical,
		Confidence: model.ConfidenceHigh,
		Category:   "advisory",
		CVE:        "CVE-2024-3829",
		CVSSScore:  9.1,
	}
	finding.SetMITRE([]string{"T1210", "T1595"})
	finding.SetEvidence([]string{"product=qdrant version=1.8.2"})
	target := &model.Target{
		ID:        "tgt_test",
		SessionID: session.ID,
		Host:      "10.0.0.5",
		Port:      6333,
		Vendor:    model.VendorQdrant,
		Product:   "qdrant",
		Version:   "1.8.2",
		Scheme:    "http",
	}
	return &model.SessionBundle{
		Session:  session,
		Targets:  []*model.Target{target},
		Findings: []*model.Finding{finding},
	}
}

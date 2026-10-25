package test

import (
	"testing"

	"vecmap/internal/model"
)

func TestSeverityLabel(t *testing.T) {
	cases := map[model.Severity]struct{ en, zh string }{
		model.SeverityCritical: {"critical", "严重"},
		model.SeverityHigh:     {"high", "高危"},
		model.SeverityMedium:   {"medium", "中危"},
		model.SeverityLow:      {"low", "低危"},
		model.SeverityInfo:     {"info", "信息"},
	}
	for severity, want := range cases {
		if got := severity.Label("en"); got != want.en {
			t.Fatalf("Label(en) for %s = %q, want %q", severity, got, want.en)
		}
		if got := severity.Label("zh"); got != want.zh {
			t.Fatalf("Label(zh) for %s = %q, want %q", severity, got, want.zh)
		}
	}
	if got := model.Severity("bogus").Label("zh"); got != "bogus" {
		t.Fatalf("expected raw fallback for unknown severity, got %q", got)
	}
}

func TestConfidenceLabel(t *testing.T) {
	cases := map[model.Confidence]struct{ en, zh string }{
		model.ConfidenceHigh:   {"high", "高"},
		model.ConfidenceMedium: {"medium", "中"},
		model.ConfidenceLow:    {"low", "低"},
	}
	for confidence, want := range cases {
		if got := confidence.Label("en"); got != want.en {
			t.Fatalf("Label(en) for %s = %q, want %q", confidence, got, want.en)
		}
		if got := confidence.Label("zh"); got != want.zh {
			t.Fatalf("Label(zh) for %s = %q, want %q", confidence, got, want.zh)
		}
	}
}

func TestVendorDisplayNameIn(t *testing.T) {
	if got := model.VendorPgVector.DisplayNameIn("en"); got != "PostgreSQL pgvector" {
		t.Fatalf("unexpected en name: %q", got)
	}
	if got := model.VendorPgVector.DisplayNameIn("zh"); got != "PostgreSQL pgvector 扩展" {
		t.Fatalf("unexpected zh name: %q", got)
	}
	if got := model.VendorUnknown.DisplayNameIn("zh"); got != "未知" {
		t.Fatalf("unexpected zh unknown name: %q", got)
	}
	if got := model.VendorUnknown.DisplayNameIn("en"); got != "Unknown" {
		t.Fatalf("unexpected en unknown name: %q", got)
	}
	if got := model.VendorQdrant.DisplayNameIn("zh"); got != "Qdrant" {
		t.Fatalf("brand names must stay as-is: %q", got)
	}
}

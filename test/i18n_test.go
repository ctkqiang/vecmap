package test

import (
	"strings"
	"testing"

	"vecmap/internal/utilities"
)

func TestTBasics(t *testing.T) {
	if utilities.T("msg.scan.start") != "Scanning %d target(s)" {
		t.Fatalf("unexpected English text: %q", utilities.T("msg.scan.start"))
	}
	if utilities.T("missing.key.abc") != "missing.key.abc" {
		t.Fatalf("expected key fallback")
	}
}

func TestTfFormatting(t *testing.T) {
	got := utilities.Tf("msg.scan.start", 3)
	if !strings.Contains(got, "3") {
		t.Fatalf("expected formatted argument, got %q", got)
	}
}

func TestTInChinese(t *testing.T) {
	zh := utilities.TIn("zh", "finding.unauth_api.title")
	if zh == utilities.TIn("en", "finding.unauth_api.title") {
		t.Fatalf("expected distinct Chinese text, got %q", zh)
	}
	if utilities.TIn("zh", "missing.key.abc") != "missing.key.abc" {
		t.Fatalf("expected key fallback for missing Chinese key")
	}
	if utilities.TIn("fr", "msg.scan.start") != utilities.T("msg.scan.start") {
		t.Fatalf("expected English fallback for unknown language")
	}
}

func TestTfInChineseFormatting(t *testing.T) {
	got := utilities.TfIn("zh", "msg.scan.start", 5)
	if !strings.Contains(got, "5") {
		t.Fatalf("expected formatted Chinese output, got %q", got)
	}
}

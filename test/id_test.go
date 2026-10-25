package test

import (
	"strings"
	"testing"

	"github.com/ctkqiang/vecmap/internal/utilities"
)

func TestNewID(t *testing.T) {
	first := utilities.NewID("ses")
	second := utilities.NewID("ses")
	if first == second {
		t.Fatalf("expected unique IDs, got %q twice", first)
	}
	if !strings.HasPrefix(first, "ses_") {
		t.Fatalf("expected prefix, got %q", first)
	}
	if len(first) != len("ses_")+16 {
		t.Fatalf("expected 16 hex chars after prefix, got %q", first)
	}
	plain := utilities.NewID("")
	if strings.Contains(plain, "_") {
		t.Fatalf("expected bare ID without prefix, got %q", plain)
	}
}

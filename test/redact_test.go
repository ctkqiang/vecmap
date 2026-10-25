package test

import (
	"net/http"
	"strings"
	"testing"

	"vecmap/internal/utilities"
)

func TestSanitizeURL(t *testing.T) {
	got := utilities.SanitizeURL("https://user:password@db.example.com:6333/collections?api_key=secret123&q=1")
	if strings.Contains(got, "user:password") || strings.Contains(got, "user@") {
		t.Fatalf("expected userinfo to be stripped, got %q", got)
	}
	if strings.Contains(got, "secret123") {
		t.Fatalf("expected api_key to be redacted, got %q", got)
	}
	if !strings.Contains(got, "db.example.com") {
		t.Fatalf("expected host to be preserved, got %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("expected REDACTED marker, got %q", got)
	}
}

func TestRedactHTTPHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token-abc")
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Custom", "visible")
	redacted := utilities.RedactHTTPHeaders(headers)
	if redacted["authorization"] != "REDACTED" {
		t.Fatalf("expected authorization to be redacted, got %q", redacted["authorization"])
	}
	if redacted["content-type"] != "application/json" {
		t.Fatalf("expected content-type to be preserved, got %q", redacted["content-type"])
	}
	if redacted["x-custom"] != "visible" {
		t.Fatalf("expected custom header to be preserved, got %q", redacted["x-custom"])
	}
}

func TestRedactText(t *testing.T) {
	got := utilities.RedactText("failed with Bearer abc123def and api_key=mykey password=hunter2")
	for _, forbidden := range []string{"abc123def", "mykey", "hunter2"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("expected %q to be redacted, got %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("expected REDACTED marker, got %q", got)
	}
}

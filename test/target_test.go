package test

import (
	"testing"

	"github.com/ctkqiang/vecmap/internal/engine"
)

func TestParseTargetURL(t *testing.T) {
	target, credentials, err := engine.ParseTarget("http://user:secret@10.0.0.5:6333/base?api_key=abc123")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if target.Scheme != "http" || target.Host != "10.0.0.5" || target.Port != 6333 {
		t.Fatalf("unexpected target: %+v", target)
	}
	if credentials.Username != "user" || credentials.Password != "secret" {
		t.Fatalf("unexpected credentials: %+v", credentials)
	}
	if credentials.APIKey != "abc123" {
		t.Fatalf("expected api key from query, got %q", credentials.APIKey)
	}
	if target.BaseURL() != "http://10.0.0.5:6333/base" {
		t.Fatalf("unexpected base URL: %s", target.BaseURL())
	}
}

func TestParseTargetRedis(t *testing.T) {
	target, credentials, err := engine.ParseTarget("redis://10.0.0.5:6379?password=topsecret")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if target.Scheme != "redis" || target.Port != 6379 {
		t.Fatalf("unexpected target: %+v", target)
	}
	if credentials.Password != "topsecret" {
		t.Fatalf("unexpected password: %q", credentials.Password)
	}
}

func TestParseTargetBareHost(t *testing.T) {
	target, _, err := engine.ParseTarget("10.0.0.5:6333")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if target.Host != "10.0.0.5" || target.Port != 6333 || target.Scheme != "http" {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestResolveTargetsCIDR(t *testing.T) {
	targets, _, err := engine.ResolveTargets([]string{"10.0.0.0/30"}, []int{6333}, 64)
	if err != nil {
		t.Fatalf("ResolveTargets: %v", err)
	}
	if len(targets) != 4 {
		t.Fatalf("expected 4 hosts from /30, got %d", len(targets))
	}
}

func TestExpandCIDR(t *testing.T) {
	hosts, err := engine.ExpandCIDR("192.0.2.0/31", 4)
	if err != nil {
		t.Fatalf("ExpandCIDR: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(hosts))
	}
	if _, err := engine.ExpandCIDR("192.0.2.0/24", 10); err == nil {
		t.Fatalf("expected limit error for /24 with limit 10")
	}
}

func TestSchemeForPort(t *testing.T) {
	cases := map[int]string{443: "https", 8443: "https", 5432: "postgres", 6379: "redis", 6380: "redis", 6333: "http", 80: "http"}
	for port, want := range cases {
		if got := engine.SchemeForPort(port); got != want {
			t.Fatalf("SchemeForPort(%d) = %q, want %q", port, got, want)
		}
	}
}

func TestTargetURLJoin(t *testing.T) {
	target, _, err := engine.ParseTarget("https://db.example.com:8443/prefix")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got := engine.TargetURL(target, "/collections"); got != "https://db.example.com:8443/prefix/collections" {
		t.Fatalf("TargetURL = %q", got)
	}
}

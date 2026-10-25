package test

import (
	"context"
	"errors"
	"testing"

	"vecmap/internal/engine"
	"vecmap/internal/model"
)

func TestScoperPermissiveExclusionOnly(t *testing.T) {
	scoper, err := engine.NewScoper(model.Scope{ExcludeCIDRs: []string{"10.99.0.0/16"}})
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	if err := scoper.Check(context.Background(), "10.0.0.5", 6333); err != nil {
		t.Fatalf("expected permissive scope to allow 10.0.0.5: %v", err)
	}
	if err := scoper.Check(context.Background(), "10.99.1.2", 6333); !errors.Is(err, engine.ErrScopeDenied) {
		t.Fatalf("expected excluded host to be denied, got %v", err)
	}
}

func TestScoperAllowlistDeniesUnknown(t *testing.T) {
	scoper, err := engine.NewScoper(model.Scope{CIDRs: []string{"10.0.0.0/24"}})
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	if err := scoper.Check(context.Background(), "10.0.0.5", 6333); err != nil {
		t.Fatalf("expected allowlisted host to pass: %v", err)
	}
	if err := scoper.Check(context.Background(), "192.168.1.5", 6333); !errors.Is(err, engine.ErrScopeDenied) {
		t.Fatalf("expected unlisted host to be denied, got %v", err)
	}
}

func TestScoperSingleIPAllow(t *testing.T) {
	scoper, err := engine.NewScoper(model.Scope{CIDRs: []string{"10.0.0.5"}})
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	if err := scoper.Check(context.Background(), "10.0.0.5", 6333); err != nil {
		t.Fatalf("expected single IP to pass: %v", err)
	}
	if err := scoper.Check(context.Background(), "10.0.0.6", 6333); !errors.Is(err, engine.ErrScopeDenied) {
		t.Fatalf("expected neighbor IP to be denied, got %v", err)
	}
}

func TestScoperExcludedDomain(t *testing.T) {
	scoper, err := engine.NewScoper(model.Scope{ExcludeDomains: []string{"internal.example.com"}})
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	if err := scoper.Check(context.Background(), "api.internal.example.com", 80); !errors.Is(err, engine.ErrScopeDenied) {
		t.Fatalf("expected subdomain of excluded domain to be denied, got %v", err)
	}
	if err := scoper.Check(context.Background(), "public.example.com", 80); err != nil {
		t.Fatalf("expected unrelated domain to pass: %v", err)
	}
}

func TestScoperPortAllowlist(t *testing.T) {
	scoper, err := engine.NewScoper(model.Scope{Ports: []int{6333, 6334}})
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	if err := scoper.Check(context.Background(), "10.0.0.5", 6333); err != nil {
		t.Fatalf("expected allowlisted port to pass: %v", err)
	}
	if err := scoper.Check(context.Background(), "10.0.0.5", 8080); !errors.Is(err, engine.ErrScopeDenied) {
		t.Fatalf("expected unlisted port to be denied, got %v", err)
	}
}

func TestScoperInvalidCIDR(t *testing.T) {
	if _, err := engine.NewScoper(model.Scope{CIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Fatalf("expected invalid CIDR to fail construction")
	}
	if _, err := engine.NewScoper(model.Scope{Ports: []int{70000}}); err == nil {
		t.Fatalf("expected invalid port to fail construction")
	}
}

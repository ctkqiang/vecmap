package test

import (
	"testing"

	"vecmap/internal/constant"
	"vecmap/internal/engine"
)

func TestProbeCatalogReadOnly(t *testing.T) {
	for _, vendor := range constant.AllVendors() {
		for _, spec := range engine.ProbeCatalog(vendor) {
			if !engine.RequireMethod(spec.Method) {
				t.Fatalf("vendor %s: probe %s %s uses a non-read-only method", vendor, spec.Method, spec.Path)
			}
			if engine.IsDestructivePath(spec.Path) {
				t.Fatalf("vendor %s: probe path %s is destructive", vendor, spec.Path)
			}
		}
	}
}

func TestIsDestructivePath(t *testing.T) {
	for _, path := range []string{
		"/management/stop",
		"/collections/x/delete",
		"/snapshots/create",
		"/_delete_by_query",
		"/api/v1/collections/upsert",
	} {
		if !engine.IsDestructivePath(path) {
			t.Fatalf("expected %q to be flagged destructive", path)
		}
	}
	for _, path := range []string{
		"/collections",
		"/healthz",
		"/snapshots",
		"/v1/schema",
	} {
		if engine.IsDestructivePath(path) {
			t.Fatalf("expected %q to be safe", path)
		}
	}
}

func TestProbeCatalogHasCore(t *testing.T) {
	for _, vendor := range constant.AllVendors() {
		specs := engine.ProbeCatalog(vendor)
		found := false
		for _, spec := range specs {
			if spec.Core {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("vendor %s has no core probes", vendor)
		}
	}
}

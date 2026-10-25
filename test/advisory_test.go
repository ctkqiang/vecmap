package test

import (
	"testing"

	"github.com/ctkqiang/vecmap/internal/engine"
	"github.com/ctkqiang/vecmap/internal/model"
)

func TestAdvisoryCatalogBuiltins(t *testing.T) {
	catalog := engine.NewAdvisoryCatalog(nil)
	advisories := catalog.All()
	if len(advisories) < 10 {
		t.Fatalf("expected at least 10 built-in advisories, got %d", len(advisories))
	}
	verified := 0
	withGHSA := 0
	for _, advisory := range advisories {
		if advisory.Verified {
			verified++
		}
		if advisory.Matchable && advisory.Verified && len(advisory.References) == 0 {
			t.Fatalf("matchable advisory %s has no references", advisory.ID)
		}
		if advisory.Source == "" {
			t.Fatalf("advisory %s has no source", advisory.ID)
		}
		if advisory.GHSA != "" {
			withGHSA++
		}
	}
	if verified == 0 {
		t.Fatalf("expected verified advisories in catalog")
	}
	if withGHSA < 8 {
		t.Fatalf("expected most advisories to come from GHSA records, got %d with GHSA IDs", withGHSA)
	}
}

func TestAdvisoryCatalogByID(t *testing.T) {
	catalog := engine.NewAdvisoryCatalog(nil)
	if _, exists := catalog.ByID("CVE-2024-3829"); !exists {
		t.Fatalf("expected CVE-2024-3829 in catalog")
	}
	if _, exists := catalog.ByID("cve-2024-3829"); !exists {
		t.Fatalf("expected case-insensitive lookup to work")
	}
	if _, exists := catalog.ByID("CNVD-2021-95914"); !exists {
		t.Fatalf("expected CNVD-2021-95914 in catalog")
	}
	if _, exists := catalog.ByID("GHSA-mhjq-8c7m-3f7p"); !exists {
		t.Fatalf("expected GHSA lookup to work")
	}
	if _, exists := catalog.ByID("CVE-9999-99999"); exists {
		t.Fatalf("expected fabricated ID to be absent")
	}
}

func TestAdvisoryMatchQdrant(t *testing.T) {
	catalog := engine.NewAdvisoryCatalog(nil)
	matches := catalog.Match(model.VendorQdrant, "qdrant", "1.8.2")
	ids := matchIDs(matches)
	if !contains(ids, "CVE-2024-3829") {
		t.Fatalf("expected CVE-2024-3829 to match qdrant 1.8.2, got %v", ids)
	}
	if !contains(ids, "CVE-2024-3584") {
		t.Fatalf("expected CVE-2024-3584 to match qdrant 1.8.2, got %v", ids)
	}
	if len(catalog.Match(model.VendorQdrant, "qdrant", "1.9.0")) != 0 {
		t.Fatalf("expected qdrant 1.9.0 to be clean for snapshot CVEs")
	}
	if !contains(matchIDs(catalog.Match(model.VendorQdrant, "qdrant", "1.15.5")), "CVE-2026-25628") {
		t.Fatalf("expected CVE-2026-25628 to match qdrant 1.15.5")
	}
}

func TestAdvisoryMatchMilvus(t *testing.T) {
	catalog := engine.NewAdvisoryCatalog(nil)
	ids := matchIDs(catalog.Match(model.VendorMilvus, "milvus", "2.5.10"))
	for _, want := range []string{"CVE-2025-64513", "CVE-2026-26190", "CVE-2026-69111"} {
		if !contains(ids, want) {
			t.Fatalf("expected %s to match milvus 2.5.10, got %v", want, ids)
		}
	}
	// 2.5.27 已修复 64513 与 26190，但 69111（<= 2.6.22）仍然命中。
	if !contains(matchIDs(catalog.Match(model.VendorMilvus, "milvus", "2.5.27")), "CVE-2026-69111") {
		t.Fatalf("expected CVE-2026-69111 to still match milvus 2.5.27")
	}
}

func TestAdvisoryMatchOtherVendors(t *testing.T) {
	catalog := engine.NewAdvisoryCatalog(nil)
	if !contains(matchIDs(catalog.Match(model.VendorWeaviate, "weaviate", "1.33.0")), "CVE-2026-11500") {
		t.Fatalf("expected CVE-2026-11500 to match weaviate 1.33.0")
	}
	if !contains(matchIDs(catalog.Match(model.VendorChroma, "chroma", "1.2.0")), "CVE-2026-45829") {
		t.Fatalf("expected CVE-2026-45829 to match chroma 1.2.0")
	}
	if !contains(matchIDs(catalog.Match(model.VendorChroma, "chroma", "1.5.9")), "CVE-2026-92782") {
		t.Fatalf("expected CVE-2026-92782 to match chroma 1.5.9")
	}
	if !contains(matchIDs(catalog.Match(model.VendorTypesense, "typesense", "30.1")), "CVE-2026-47216") {
		t.Fatalf("expected CVE-2026-47216 to match typesense 30.1")
	}
}

func TestAdvisoryLog4jNotAutoMatched(t *testing.T) {
	catalog := engine.NewAdvisoryCatalog(nil)
	if len(catalog.Match(model.VendorApache, "log4j2", "2.14.1")) != 0 {
		t.Fatalf("expected Log4j advisory to not auto-match (packaging cannot be proven remotely)")
	}
	advisory, exists := catalog.ByID("CVE-2021-44228")
	if !exists {
		t.Fatalf("expected CVE-2021-44228 entry")
	}
	if advisory.Matchable {
		t.Fatalf("expected CVE-2021-44228 entry to be non-matchable")
	}
	if advisory.CNVD != "CNVD-2021-95914" {
		t.Fatalf("expected CNVD linkage, got %q", advisory.CNVD)
	}
}

func TestAdvisoryLoadFileValidation(t *testing.T) {
	path := writeTempJSON(t, map[string]any{
		"advisories": []map[string]any{
			{"id": "EXT-1", "cve": "CVE-2020-00001", "title": "extra", "vendor": "qdrant", "severity": "high"},
		},
	})
	extra, err := engine.LoadAdvisoryFile(path)
	if err != nil {
		t.Fatalf("LoadAdvisoryFile: %v", err)
	}
	if len(extra) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(extra))
	}
	if extra[0].Verified {
		t.Fatalf("expected imported advisory to remain unverified")
	}
	catalog := engine.NewAdvisoryCatalog(extra)
	if len(catalog.Match(model.VendorQdrant, "qdrant", "1.8.2")) == 0 {
		t.Fatalf("imported entries must not suppress built-in matches")
	}
}

func matchIDs(matches []model.AdvisoryMatch) []string {
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		result = append(result, match.AdvisoryID)
	}
	return result
}

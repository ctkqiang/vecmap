package test

import (
	"strings"
	"testing"

	"vecmap/internal/constant"
)

func TestMITRECatalogExpanded(t *testing.T) {
	techniques := constant.MITRETechniques()
	if len(techniques) < 50 {
		t.Fatalf("expected at least 50 techniques, got %d", len(techniques))
	}
	seen := map[string]struct{}{}
	for _, technique := range techniques {
		if technique.ID == "" || technique.Name == "" || technique.NameZH == "" {
			t.Fatalf("technique %q missing identifier or names: %+v", technique.ID, technique)
		}
		if technique.Tactic == "" || technique.TacticZH == "" {
			t.Fatalf("technique %s missing tactic: %+v", technique.ID, technique)
		}
		if !strings.HasPrefix(technique.URL, "https://attack.mitre.org/techniques/") {
			t.Fatalf("technique %s has invalid URL %q", technique.ID, technique.URL)
		}
		if _, exists := seen[technique.ID]; exists {
			t.Fatalf("duplicate technique %s", technique.ID)
		}
		seen[technique.ID] = struct{}{}
	}
}

func TestMITREByID(t *testing.T) {
	technique, exists := constant.MITREByID("T1595.002")
	if !exists {
		t.Fatalf("expected T1595.002 to exist")
	}
	if technique.NameZH != "主动扫描：漏洞扫描" {
		t.Fatalf("unexpected Chinese name: %q", technique.NameZH)
	}
	if technique.TacticZH != "侦察" {
		t.Fatalf("unexpected Chinese tactic: %q", technique.TacticZH)
	}
	if technique.URL != "https://attack.mitre.org/techniques/T1595/002/" {
		t.Fatalf("unexpected sub-technique URL: %q", technique.URL)
	}
	if _, exists := constant.MITREByID("T9999"); exists {
		t.Fatalf("expected fabricated technique to be absent")
	}
}

func TestMITRECatalogCoversFindings(t *testing.T) {
	// 风险分析层引用的全部技术编号必须在目录中存在。
	referenced := []string{
		"T1595", "T1595.002", "T1592", "T1046", "T1213", "T1119", "T1567",
		"T1530", "T1185", "T1040", "T1005", "T1059", "T1078", "T1210", "T1499",
	}
	for _, id := range referenced {
		if _, exists := constant.MITREByID(id); !exists {
			t.Fatalf("technique %s referenced by findings is missing from catalog", id)
		}
	}
}

func TestMITRETacticsCovered(t *testing.T) {
	techniques := constant.MITRETechniques()
	tactics := map[string]struct{}{}
	for _, technique := range techniques {
		tactics[technique.Tactic] = struct{}{}
	}
	for _, want := range []string{
		constant.TacticReconnaissance, constant.TacticResourceDevelopment,
		constant.TacticInitialAccess, constant.TacticExecution, constant.TacticPersistence,
		constant.TacticPrivilegeEscalation, constant.TacticDefenseEvasion,
		constant.TacticCredentialAccess, constant.TacticDiscovery,
		constant.TacticLateralMovement, constant.TacticCollection,
		constant.TacticCommandAndControl, constant.TacticExfiltration, constant.TacticImpact,
	} {
		if _, exists := tactics[want]; !exists {
			t.Fatalf("expected tactic %q to be covered by the catalog", want)
		}
	}
}

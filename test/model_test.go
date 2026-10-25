package test

import (
	"errors"
	"path/filepath"
	"testing"

	"vecmap/internal/database"
	"vecmap/internal/model"
)

// TestSmokeEndToEnd 走通一次会话的完整链路：
// 建会话 → 目标去重 → 逐步落库 → 记录漏洞 → 结束会话 → 重新打开回放。
// 读写函数在 database 包，DTO 类型在 model 包。
func TestSmokeEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vecmap.db")
	if _, err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	defer database.Close()

	s, err := database.CreateSession("run-1", "192.168.1.0/24", "zh")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := database.CreateSession("run-1", "x", "zh"); !errors.Is(err, database.ErrSessionExists) {
		t.Fatalf("expected ErrSessionExists, got %v", err)
	}

	tgt, err := database.UpsertTarget(s.ID, model.TargetInput{Host: "192.168.1.10", Port: 443, Protocol: "TCP", Engine: "nmap", Version: "1.3"})
	if err != nil {
		t.Fatalf("UpsertTarget: %v", err)
	}
	dup, err := database.UpsertTarget(s.ID, model.TargetInput{Host: "192.168.1.10", Port: 443, Protocol: "TCP", Engine: "nmap"})
	if err != nil {
		t.Fatalf("UpsertTarget dup: %v", err)
	}
	if dup.ID != tgt.ID {
		t.Fatalf("dedup failed: %d != %d", dup.ID, tgt.ID)
	}

	for i, action := range []string{"step.port.scan", "step.service.probe", "step.vuln.check"} {
		step, err := database.RecordStep(s.ID, model.StepInput{Action: action, Target: "192.168.1.10:443", Success: true})
		if err != nil {
			t.Fatalf("RecordStep %d: %v", i, err)
		}
		if step.Seq != i+1 {
			t.Fatalf("expected seq %d, got %d", i+1, step.Seq)
		}
	}

	v, err := database.AddVulnerability(s.ID, tgt.ID, model.VulnInput{Title: "Heartbleed", Severity: model.SeverityCritical, CVE: "CVE-2014-0160", MitreTTP: "T1190"})
	if err != nil {
		t.Fatalf("AddVulnerability: %v", err)
	}
	if v.SessionID != s.ID {
		t.Fatalf("vuln session mismatch: %d", v.SessionID)
	}

	if err := database.FinishSession(s.ID, model.StatusCompleted); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}

	loaded, err := database.OpenSession(s.ID)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if loaded.Status != model.StatusCompleted {
		t.Fatalf("status = %s, want completed", loaded.Status)
	}
	if len(loaded.Targets) != 1 || len(loaded.Steps) != 3 || len(loaded.Targets[0].Vulnerabilities) != 1 {
		t.Fatalf("replay shape wrong: targets=%d steps=%d vulns=%d",
			len(loaded.Targets), len(loaded.Steps), len(loaded.Targets[0].Vulnerabilities))
	}
	if !loaded.Targets[0].IsVulnerable || loaded.Targets[0].FindingsCount != 1 {
		t.Fatalf("target counters wrong: vuln=%v count=%d",
			loaded.Targets[0].IsVulnerable, loaded.Targets[0].FindingsCount)
	}

	byName, err := database.FindSessionByName("run-1")
	if err != nil || byName.ID != s.ID {
		t.Fatalf("FindSessionByName: %v / %+v", err, byName)
	}
	if _, err := database.FindSessionByName("nope"); !errors.Is(err, database.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	list, err := database.ListSessions(0)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSessions: %v / %d", err, len(list))
	}
	if _, err := database.OpenSession(9999); !errors.Is(err, database.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

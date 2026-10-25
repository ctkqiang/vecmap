package test

import (
	"testing"

	"vecmap/internal/database"
	"vecmap/internal/model"
)

// TestTargetAndFindingDedupe 覆盖重扫同一会话时的去重行为：
//   - 端口扫描先把目标记成 TCP，指纹阶段改成 HTTP 后，
//     再次 Upsert 必须命中同一条目标；
//   - 非 CVE 发现按 Code 去重，切换界面语言后标题变化也不会重复入库。
func TestTargetAndFindingDedupe(t *testing.T) {
	if _, err := database.InitDB(":memory:"); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()

	session, err := database.CreateSession("dedupe", "127.0.0.1", "en")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	first, err := database.UpsertTarget(session.ID, model.TargetInput{
		Host:     "127.0.0.1",
		Port:     8080,
		Protocol: "TCP",
		Engine:   "Weaviate",
	})
	if err != nil {
		t.Fatalf("UpsertTarget: %v", err)
	}

	if err := database.UpdateTarget(first.ID, "Weaviate", "1.30.10", "HTTP"); err != nil {
		t.Fatalf("UpdateTarget: %v", err)
	}

	second, err := database.UpsertTarget(session.ID, model.TargetInput{
		Host:     "127.0.0.1",
		Port:     8080,
		Protocol: "TCP",
	})
	if err != nil {
		t.Fatalf("UpsertTarget (rescan): %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("rescan created target %d, want existing %d", second.ID, first.ID)
	}

	input := model.VulnInput{
		Title:       "允许匿名访问",
		Severity:    model.SeverityMedium,
		Code:        model.FindingCodeAnonymous,
		Data:        `{"vendor":"Weaviate"}`,
		MitreTTP:    "T1190",
		Description: "中文说明",
	}
	if _, err := database.AddVulnerability(session.ID, first.ID, input); err != nil {
		t.Fatalf("AddVulnerability: %v", err)
	}

	exists, err := database.HasFinding(first.ID, "", model.FindingCodeAnonymous, "Anonymous access enabled")
	if err != nil {
		t.Fatalf("HasFinding: %v", err)
	}
	if !exists {
		t.Fatal("code-based dedupe must match even when the localised title differs")
	}

	exists, err = database.HasFinding(first.ID, "CVE-2025-67818", "", "")
	if err != nil {
		t.Fatalf("HasFinding: %v", err)
	}
	if exists {
		t.Fatal("HasFinding matched an unrelated CVE")
	}
}

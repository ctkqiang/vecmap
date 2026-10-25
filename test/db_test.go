package test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vecmap/internal/database"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

func TestStoreOpenAndWAL(t *testing.T) {
	store, err := database.Open(filepath.Join(t.TempDir(), "vecmap.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	mode, err := store.JournalMode(context.Background())
	if err != nil {
		t.Fatalf("JournalMode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("expected WAL journal mode, got %q", mode)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestStoreSessionLifecycle(t *testing.T) {
	store, err := database.Open(filepath.Join(t.TempDir(), "vecmap.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	session := &model.Session{
		ID:        utilities.NewID("ses"),
		Name:      "test-session",
		Mode:      "standard",
		Language:  "en",
		Status:    "running",
		CreatedAt: nowUTC(),
		UpdatedAt: nowUTC(),
	}
	if err := store.CreateSession(session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	loaded, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if loaded.Name != "test-session" {
		t.Fatalf("unexpected session: %+v", loaded)
	}
	targets := []*model.Target{{
		ID:        utilities.NewID("tgt"),
		SessionID: session.ID,
		Input:     "10.0.0.5:6333",
		Scheme:    "http",
		Host:      "10.0.0.5",
		Port:      6333,
		CreatedAt: nowUTC(),
	}}
	if err := store.SaveTargets(targets); err != nil {
		t.Fatalf("SaveTargets: %v", err)
	}
	finding := &model.Finding{
		ID:         utilities.NewID("fnd"),
		SessionID:  session.ID,
		TargetID:   targets[0].ID,
		Title:      "test finding",
		Severity:   model.SeverityHigh,
		Confidence: model.ConfidenceHigh,
		Category:   "test",
		CreatedAt:  nowUTC(),
	}
	finding.SetEvidence([]string{"GET / -> 200"})
	finding.SetMITRE([]string{"T1595"})
	if err := store.SaveFindings([]*model.Finding{finding}); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}
	updated, err := store.UpdateSessionCounts(session)
	if err != nil {
		t.Fatalf("UpdateSessionCounts: %v", err)
	}
	if updated.TargetCount != 1 || updated.FindingCount != 1 {
		t.Fatalf("unexpected counts: %+v", updated)
	}
	bundle, err := store.SessionBundle(session.ID)
	if err != nil {
		t.Fatalf("SessionBundle: %v", err)
	}
	if len(bundle.Targets) != 1 || len(bundle.Findings) != 1 {
		t.Fatalf("unexpected bundle: targets=%d findings=%d", len(bundle.Targets), len(bundle.Findings))
	}
	loadedFinding := bundle.Findings[0]
	if len(loadedFinding.Evidence()) != 1 || len(loadedFinding.MITRE()) != 1 {
		t.Fatalf("expected serialized evidence and MITRE to round-trip")
	}
}

func TestStoreDeleteSessionCascade(t *testing.T) {
	store, err := database.Open(filepath.Join(t.TempDir(), "vecmap.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	session := &model.Session{
		ID:        utilities.NewID("ses"),
		Name:      "cascade",
		Mode:      "standard",
		Status:    "completed",
		CreatedAt: nowUTC(),
		UpdatedAt: nowUTC(),
	}
	if err := store.CreateSession(session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := store.SaveTargets([]*model.Target{{
		ID:        utilities.NewID("tgt"),
		SessionID: session.ID,
		Host:      "10.0.0.5",
		CreatedAt: nowUTC(),
	}}); err != nil {
		t.Fatalf("SaveTargets: %v", err)
	}
	if err := store.DeleteSession(session.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := store.GetSession(session.ID); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if _, err := store.GetSession("missing"); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDefaultPathInHomeDirectory(t *testing.T) {
	path := database.DefaultPath()
	if path == "" {
		t.Fatalf("expected non-empty default path")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("home directory is not resolvable: %v", err)
	}
	if filepath.Dir(path) != filepath.Join(home, ".vecmap") {
		t.Fatalf("expected default path under ~/.vecmap, got %q", path)
	}
	if filepath.Base(path) != "vecmap.db" {
		t.Fatalf("expected vecmap.db basename, got %q", filepath.Base(path))
	}
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

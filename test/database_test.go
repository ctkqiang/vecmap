// Package test 集中存放 vecmap 的全部测试用例。
// 所有 _test.go 文件只放在本目录，业务代码目录不放测试文件。
// 这里的测试通过导出接口访问 internal/ 下的包，因此只验证对外行为。
package test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"vecmap/internal/database"
)

// TestOpenStatClose 覆盖本地存储的完整生命周期：
// 未打开时的报错 → 打开（自动补扩展名、建目录）→ 健康检查 → 状态统计 → 关闭。
func TestOpenStatClose(t *testing.T) {
	// 未打开时应返回 ErrNotOpen
	if _, err := database.DB(); !errors.Is(err, database.ErrNotOpen) {
		t.Fatalf("打开前 DB() 应返回 ErrNotOpen，实际：%v", err)
	}
	if database.IsOpen() {
		t.Fatal("打开前 IsOpen() 应为 false")
	}

	// 故意不带扩展名、且父目录不存在，验证补扩展名与自动建目录
	base := filepath.Join(t.TempDir(), "nested", "vecmap")
	db, err := database.Open(base)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if db == nil {
		t.Fatal("Open 返回了空句柄")
	}
	if !database.IsOpen() {
		t.Fatal("打开后 IsOpen() 应为 true")
	}

	// 路径应被补上 .db 扩展名，文件应真实落盘
	if got := database.Path(); got != base+".db" {
		t.Fatalf("Path() = %q，期望 %q", got, base+".db")
	}
	if _, err := os.Stat(base + ".db"); err != nil {
		t.Fatalf("数据库文件未创建: %v", err)
	}

	// 重复打开应返回同一句柄，不会重建库
	again, err := database.Open(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatalf("重复 Open: %v", err)
	}
	if again != db {
		t.Fatal("重复 Open 应返回已打开的句柄")
	}

	if err := database.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// 建一张表，确认 journal 模式与表数量统计正确
	if err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY)").Error; err != nil {
		t.Fatalf("建表: %v", err)
	}
	info, err := database.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.JournalMode != "wal" {
		t.Fatalf("JournalMode = %q，期望 wal", info.JournalMode)
	}
	if info.Tables != 1 {
		t.Fatalf("Tables = %d，期望 1", info.Tables)
	}
	if info.MainBytes <= 0 {
		t.Fatalf("MainBytes = %d，期望大于 0", info.MainBytes)
	}
	mainBytes, walBytes := database.SizeBytes()
	if mainBytes != info.MainBytes || walBytes != info.WALBytes {
		t.Fatalf("SizeBytes 与 Stat 不一致: %d/%d vs %d/%d",
			mainBytes, walBytes, info.MainBytes, info.WALBytes)
	}

	if err := database.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if err := database.Vacuum(); err != nil {
		t.Fatalf("Vacuum: %v", err)
	}

	// 关闭两次都应安全，关闭后状态复位
	if err := database.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("重复 Close: %v", err)
	}
	if database.IsOpen() {
		t.Fatal("关闭后 IsOpen() 应为 false")
	}
	if got := database.Path(); got != "" {
		t.Fatalf("关闭后 Path() = %q，应为空", got)
	}
	if _, err := database.DB(); !errors.Is(err, database.ErrNotOpen) {
		t.Fatalf("关闭后 DB() 应返回 ErrNotOpen，实际：%v", err)
	}
	if err := database.Checkpoint(); !errors.Is(err, database.ErrNotOpen) {
		t.Fatalf("关闭后 Checkpoint 应返回 ErrNotOpen，实际：%v", err)
	}

	// 内存库路径：不应落盘，容量统计返回 0
	mem, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("打开内存库: %v", err)
	}
	if mem == nil {
		t.Fatal("内存库句柄为空")
	}
	if m, w := database.SizeBytes(); m != 0 || w != 0 {
		t.Fatalf("内存库 SizeBytes = %d/%d，应为 0/0", m, w)
	}
	_ = database.Close()
}

// TestDefaultDBPath 确认默认路径落在用户主目录下的 .vecmap 中。
func TestDefaultDBPath(t *testing.T) {
	got := database.DefaultDBPath()
	if got == "" || filepath.Base(got) != "vecmap.db" {
		t.Fatalf("DefaultDBPath() = %q，期望以 vecmap.db 结尾", got)
	}
	if filepath.Base(filepath.Dir(got)) != ".vecmap" {
		t.Fatalf("DefaultDBPath() 应位于 .vecmap 目录，实际：%q", got)
	}
}

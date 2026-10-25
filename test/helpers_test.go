package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTempJSON 将对象序列化到临时目录中的 JSON 文件。
//
// 参数 t 为测试句柄，value 为待序列化对象。
// 返回文件路径；测试结束时临时目录由 testing 框架自动清理。
func writeTempJSON(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

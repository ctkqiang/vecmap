package utilities

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ReadJSONFile 读取并解析 JSON 文件。
//
// 参数 path 为文件路径，target 为解析目标。
// 返回文件或解析错误；文件不存在时返回错误。
func ReadJSONFile(path string, target any) error {
	if path == "" {
		return fmt.Errorf("file path is empty")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	return nil
}

// WriteFilePrivate 以仅属主权限写入文件。
//
// 参数 path 为文件路径，data 为内容。
// 父目录不存在时以 0700 创建，文件以 0600 写入。
// 返回写入错误。
func WriteFilePrivate(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("file path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	if err := os.WriteFile(absolute, data, 0o600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// WriteJSONFilePrivate 以仅属主权限序列化并写入 JSON 文件。
//
// 参数 path 为文件路径，value 为待序列化对象。
// 返回序列化或写入错误。
func WriteJSONFilePrivate(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return WriteFilePrivate(path, payload)
}

package utilities

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Truncate 将文本截断到指定长度。
//
// 参数 value 为原始文本，limit 为最大字符数。
// 返回截断文本；超限时附加省略号，limit 小于等于 0 时返回空字符串。
func Truncate(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit-1]) + "…"
}

// FirstNonEmpty 返回首个非空字符串。
//
// 参数 values 为候选值列表；全部为空时返回空字符串。
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// SortedKeys 返回映射的排序键。
//
// 参数 values 为任意映射；返回按键升序排列的键切片。
func SortedKeys(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

// SHA256Hex 返回数据的 SHA-256 十六进制摘要。
//
// 参数 data 为任意字节序列；返回 64 位十六进制文本。
func SHA256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// FormatBytes 将字节数格式化为人类可读文本。
//
// 参数 size 为字节数；返回形如 1.5 MB 的文本。
func FormatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	divisor, exponent := int64(unit), 0
	for value := size / unit; value >= unit && exponent < 4; value /= unit {
		divisor *= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(divisor), "KMGTPE"[exponent])
}

// FormatDuration 将时长格式化为紧凑文本。
//
// 参数 duration 为任意时长；返回形如 3m42s 的文本。
func FormatDuration(duration time.Duration) string {
	if duration < time.Second {
		return duration.Round(time.Millisecond).String()
	}
	total := int64(duration / time.Second)
	hours := total / 3600
	minutes := (total % 3600) / 60
	seconds := total % 60
	switch {
	case hours > 0:
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

package utilities

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// NewID 生成带前缀的本地唯一标识。
//
// 参数 prefix 为业务前缀，例如 ses、tgt、fnd；空前缀返回纯随机标识。
// 返回形如 prefix_xxxxxxxxxxxxxxxx 的标识。
func NewID(prefix string) string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return prefix + "_0000000000000000"
	}
	value := hex.EncodeToString(buffer)
	if strings.TrimSpace(prefix) == "" {
		return value
	}
	return strings.TrimSpace(prefix) + "_" + value
}

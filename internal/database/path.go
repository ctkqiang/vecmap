package database

import (
	"os"
	"path/filepath"

	"vecmap/internal/constant"
)

// DefaultPath 返回本地数据库的默认绝对路径。
//
// 路径位于用户主目录下的 .vecmap/vecmap.db（Unix 约定）；
// 无法解析主目录时回退到当前工作目录中的文件名。
// 目录与文件权限由 Open 负责收紧（0700/0600）。
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return constant.DefaultDatabaseFile
	}
	return filepath.Join(home, ".vecmap", "vecmap.db")
}

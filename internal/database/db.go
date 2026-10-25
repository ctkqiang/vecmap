package database

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ctkqiang/vecmap/internal/model"
)

// ErrNotFound 表示查询的持久化实体不存在。
var ErrNotFound = errors.New("record not found")

// Store 封装本地 SQLite 数据库与 GORM 会话。
//
// 所有写入均使用 WAL 与忙等待，适合单机多协程扫描场景。
type Store struct {
	db   *gorm.DB
	path string
}

// Open 打开或创建本地 SQLite 数据库。
//
// 参数 path 为数据库文件路径；传空值时返回错误。
// 返回已执行迁移的存储实例；关闭责任由调用方承担。
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on", filepath.ToSlash(absolute))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("access sqlite handle: %w", err)
	}
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(time.Hour)
	if err := applyPragmas(db); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	store := &Store{db: db, path: absolute}
	if err := store.migrate(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	_ = os.Chmod(absolute, 0o600)
	return store, nil
}

// DB 返回底层 GORM 句柄。
//
// 返回句柄仅用于只读查询与测试辅助；业务写入应优先使用 Store 方法。
func (s *Store) DB() *gorm.DB {
	return s.db
}

// Path 返回数据库文件的绝对路径。
//
// 返回值为打开时解析的绝对路径。
func (s *Store) Path() string {
	return s.path
}

// Close 关闭底层数据库连接。
//
// 返回关闭错误；重复关闭由 database/sql 安全处理。
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping 检查数据库连通性。
//
// 参数 ctx 控制检查超时；返回连接错误。
func (s *Store) Ping(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// JournalMode 返回当前 SQLite 日志模式。
//
// 返回形如 wal 或 delete 的模式文本，用于自检与测试。
func (s *Store) JournalMode(ctx context.Context) (string, error) {
	var mode string
	if err := s.db.WithContext(ctx).Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil {
		return "", err
	}
	return mode, nil
}

func applyPragmas(db *gorm.DB) error {
	statements := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA temp_store=MEMORY",
	}
	for _, statement := range statements {
		if err := db.Exec(statement).Error; err != nil {
			return fmt.Errorf("apply sqlite pragma %q: %w", statement, err)
		}
	}
	return nil
}

func (s *Store) migrate() error {
	entities := []any{
		&model.Session{},
		&model.Target{},
		&model.Step{},
		&model.Finding{},
		&model.Collection{},
		&model.Record{},
		&model.ProbeResult{},
		&model.Endpoint{},
		&model.HTTPExchange{},
	}
	if err := s.db.AutoMigrate(entities...); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}

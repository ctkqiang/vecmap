// Package database 负责 vecmap 本地 SQLite 存储的全部读写：
// 打开 / 关闭、连接句柄共享、健康检查与维护，以及会话、目标、漏洞、步骤
// 的增删查改。数据结构（DTO）定义在 internal/model，本包单向引用它。
//
// 分层约定：
//   - model 只放类型，不放函数；
//   - 所有落库函数都在本文件，业务代码不要绕开本包直接操作 *gorm.DB；
//   - 错误文本保持英文（Go 惯例），界面展示时由 localisation.go 翻译。
package database

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"vecmap/internal/model"
)

// ErrNotOpen 在尚未调用 Open() 就访问本地存储时返回。
var ErrNotOpen = errors.New("local store is not open, call database.Open first")

// 持久层错误。刻意保持语言无关，界面层用 localisation.go 翻译后再显示。
var (
	ErrSessionExists    = errors.New("session name already exists")
	ErrSessionNotFound  = errors.New("session not found")
	ErrTargetNotFound   = errors.New("target not found")
	ErrInvalidSessionID = errors.New("invalid session id")
	ErrInvalidStatus    = errors.New("invalid session status")
)

// 连接句柄与文件路径由本包独占持有；读操作走 RLock，写操作走 Lock。
var (
	handle    *gorm.DB
	storePath string
	mu        sync.RWMutex
)

// DefaultDBPath 返回默认数据库文件路径：<用户主目录>/.vecmap/vecmap.db。
// 用户未指定路径时使用它，保证扫描记录始终落在本地。
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "vecmap.db"
	}
	return filepath.Join(home, ".vecmap", "vecmap.db")
}

// buildDSN 根据用户给出的路径生成 SQLite DSN，同时返回规范化后的文件路径。
//
//   - ":memory:" 使用共享内存库，进程内多次打开指向同一个库，便于测试；
//   - 没写扩展名时自动补 ".db"，避免出现 vecmap 这种无后缀文件；
//   - 自动创建上级目录，否则 Open 会因目录不存在而失败；
//   - _journal_mode=WAL：写入期间读操作不被阻塞；
//   - _busy_timeout=5000：等待锁 5 秒而不是立刻报 database is locked；
//   - SQLite 默认不开启外键，这里显式开启，让 会话→目标→漏洞 的关联真正生效。
func buildDSN(path string) (dsn, clean string) {
	if path == ":memory:" {
		return "file:vecmap?mode=memory&cache=shared&_foreign_keys=on", path
	}

	if filepath.Ext(path) == "" {
		path += ".db"
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}

	return fmt.Sprintf(
		"file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on",
		path,
	), path
}

// Open 打开（必要时创建）本地存储并返回连接句柄。
// path 为空时使用 DefaultDBPath()；若已打开则直接返回现有句柄，不重复建库。
func Open(path string) (*gorm.DB, error) {
	mu.Lock()
	defer mu.Unlock()

	if handle != nil {
		return handle, nil
	}
	if path == "" {
		path = DefaultDBPath()
	}

	dsn, clean := buildDSN(path)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	handle = db
	storePath = clean
	return db, nil
}

// InitDB 打开本地存储并按 model 中的结构体自动迁移表结构，是程序启动时
// 唯一需要调用的入口。dbPath 为空时使用 DefaultDBPath()。
func InitDB(dbPath string) (*gorm.DB, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(
		&model.SessionRecord{},
		&model.TargetRecord{},
		&model.StepRecord{},
		&model.VulnerabilityRecord{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}
	return db, nil
}

// DB 返回当前连接句柄；未打开时返回 ErrNotOpen。
// 所有业务代码都通过这里拿连接，避免各自持有句柄。
func DB() (*gorm.DB, error) {
	mu.RLock()
	defer mu.RUnlock()

	if handle == nil {
		return nil, ErrNotOpen
	}
	return handle, nil
}

// IsOpen 返回本地存储是否已打开，用于启动时的快速判断。
func IsOpen() bool {
	mu.RLock()
	defer mu.RUnlock()
	return handle != nil
}

// Path 返回当前数据库文件路径；未打开时返回空字符串。
func Path() string {
	mu.RLock()
	defer mu.RUnlock()
	return storePath
}

// Close 关闭本地存储并释放文件句柄；未打开时直接返回，可安全重复调用。
func Close() error {
	mu.Lock()
	defer mu.Unlock()

	if handle == nil {
		return nil
	}
	db, err := handle.DB()
	handle = nil
	storePath = ""
	if err != nil {
		return err
	}
	return db.Close()
}

// Ping 检测连接是否仍然可用（数据库文件被删除或被独占时会返回错误）。
func Ping() error {
	db, err := DB()
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return sqlDB.PingContext(ctx)
}

// Checkpoint 把 WAL 日志并入主库文件并截断，防止 -wal 文件无限增长，
// 这样用户直接拷走单个 .db 文件就能完整备份。
func Checkpoint() error {
	db, err := DB()
	if err != nil {
		return err
	}
	if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error; err != nil {
		return fmt.Errorf("failed to checkpoint wal: %w", err)
	}
	return nil
}

// Vacuum 重建数据库文件以回收已删除数据占用的空间。执行期间会锁库，
// 因此只在扫描结束或用户显式请求时调用。
func Vacuum() error {
	db, err := DB()
	if err != nil {
		return err
	}
	if err := db.Exec("VACUUM").Error; err != nil {
		return fmt.Errorf("failed to vacuum database: %w", err)
	}
	return nil
}

// SizeBytes 返回主库文件与 WAL 文件的字节数；内存库或文件不存在时返回 0。
func SizeBytes() (main, wal int64) {
	path := Path()
	if path == "" || path == ":memory:" {
		return 0, 0
	}
	if st, err := os.Stat(path); err == nil {
		main = st.Size()
	}
	if st, err := os.Stat(path + "-wal"); err == nil {
		wal = st.Size()
	}
	return main, wal
}

// Info 描述本地存储的当前状态，供状态类输出使用。
type Info struct {
	Path        string // 数据库文件路径
	MainBytes   int64  // 主库文件大小
	WALBytes    int64  // WAL 日志文件大小
	JournalMode string // 当前日志模式，应为 wal
	Tables      int    // 已创建的业务表数量
}

// Stat 收集本地存储的状态信息；未打开时返回 ErrNotOpen。
func Stat() (Info, error) {
	db, err := DB()
	if err != nil {
		return Info{}, err
	}

	info := Info{Path: Path()}
	info.MainBytes, info.WALBytes = SizeBytes()

	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err == nil {
		info.JournalMode = mode
	}

	var tables int64
	if err := db.Raw(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`,
	).Scan(&tables).Error; err == nil {
		info.Tables = int(tables)
	}
	return info, nil
}

// CreateSession 新建一次扫描会话。会话名唯一，因此历史运行始终可以按名重新打开。
// 重名时返回 ErrSessionExists，调用方通常应改为载入已存在的会话。
func CreateSession(name, targetScope, language string) (*model.SessionRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	session := &model.SessionRecord{
		SessionName: name,
		TargetScope: targetScope,
		Language:    language,
		Status:      model.StatusRunning,
		StartedAt:   time.Now(),
	}

	err = db.Where("session_name = ?", name).First(&model.SessionRecord{}).Error
	switch {
	case err == nil:
		return nil, ErrSessionExists
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return nil, fmt.Errorf("failed to check session name: %w", err)
	}

	if err := db.Create(session).Error; err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	return session, nil
}

// FindSessionByName 按会话名载入历史会话，目标、漏洞与步骤一并加载。
func FindSessionByName(name string) (*model.SessionRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	session := &model.SessionRecord{}
	err = loadSession(db.Where("session_name = ?", name), session)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	return session, err
}

// OpenSession 按 id 重新打开历史会话，重新载入目标、漏洞与步骤历史，
// 让用户无需重新扫描就能查看此前的结果。
func OpenSession(id uint) (*model.SessionRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	session := &model.SessionRecord{}
	err = loadSession(db.Where("id = ?", id), session)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	return session, err
}

// loadSession 在一次查询中带出目标、漏洞与按 seq 升序排列的步骤历史。
func loadSession(scope *gorm.DB, session *model.SessionRecord) error {
	return scope.
		Preload("Targets.Vulnerabilities").
		Preload("Steps", func(tx *gorm.DB) *gorm.DB {
			return tx.Order("seq asc")
		}).
		First(session).Error
}

// ListSessions 列出历史会话，最近的在前。limit <= 0 表示不限数量。
func ListSessions(limit int) ([]model.SessionRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	var sessions []model.SessionRecord
	scope := db.Order("started_at desc")
	if limit > 0 {
		scope = scope.Limit(limit)
	}
	if err := scope.Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	return sessions, nil
}

// FinishSession 标记会话已结束（完成或中止），同时写入结束时间，
// 让后续启动知道该次运行的数据已完整保存、可以回放。
func FinishSession(id uint, status string) error {
	db, err := DB()
	if err != nil {
		return err
	}
	if status != model.StatusCompleted && status != model.StatusAborted && status != model.StatusRunning {
		return fmt.Errorf("%w: unknown status %q", ErrInvalidStatus, status)
	}

	now := time.Now()
	res := db.Model(&model.SessionRecord{}).Where("id = ?", id).Updates(map[string]any{
		"status":      status,
		"finished_at": now,
	})
	if res.Error != nil {
		return fmt.Errorf("failed to update session status: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// UpsertTarget 在会话内记录一个目标。由于 (session, host, port, protocol)
// 唯一，重复执行同一扫描步骤只会返回既有记录，不会产生重复行。
func UpsertTarget(sessionID uint, in model.TargetInput) (*model.TargetRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	target := &model.TargetRecord{}
	err = db.Where(&model.TargetRecord{
		SessionID: sessionID,
		Host:      in.Host,
		Port:      in.Port,
		Protocol:  in.Protocol,
	}).Attrs(model.TargetRecord{
		Engine:  in.Engine,
		Version: in.Version,
	}).FirstOrCreate(target).Error
	if err != nil {
		return nil, fmt.Errorf("failed to record target: %w", err)
	}
	return target, nil
}

// MarkTargetVulnerable 把目标标记为存在漏洞，用于尚未写入明细的场景。
func MarkTargetVulnerable(targetID uint) error {
	db, err := DB()
	if err != nil {
		return err
	}
	if err := db.Model(&model.TargetRecord{}).Where("id = ?", targetID).
		UpdateColumn("is_vulnerable", true).Error; err != nil {
		return fmt.Errorf("failed to flag target as vulnerable: %w", err)
	}
	return nil
}

// AddVulnerability 在同一个事务中写入漏洞并同步目标上的计数与标记，
// 保证 findings_count 与明细始终一致。
func AddVulnerability(sessionID, targetID uint, in model.VulnInput) (*model.VulnerabilityRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	vuln := &model.VulnerabilityRecord{
		TargetID:    targetID,
		SessionID:   sessionID,
		Title:       in.Title,
		Severity:    in.Severity,
		CVE:         in.CVE,
		MitreTTP:    in.MitreTTP,
		Description: in.Description,
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(vuln).Error; err != nil {
			return err
		}
		return tx.Model(&model.TargetRecord{}).Where("id = ?", targetID).Updates(map[string]any{
			"is_vulnerable":  true,
			"findings_count": gorm.Expr("findings_count + 1"),
		}).Error
	})
	if err != nil {
		return nil, fmt.Errorf("failed to record finding: %w", err)
	}
	return vuln, nil
}

// FindingsOf 返回某个会话的全部漏洞发现，按写入时间升序。
func FindingsOf(sessionID uint) ([]model.VulnerabilityRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	var vulns []model.VulnerabilityRecord
	if err := db.Where("session_id = ?", sessionID).Order("created_at asc").
		Find(&vulns).Error; err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}
	return vulns, nil
}

// RecordStep 向会话历史追加一个步骤。序号在事务内分配，
// 即使有多个扫描协程并发写入，顺序也不会错乱。
func RecordStep(sessionID uint, in model.StepInput) (*model.StepRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	step := &model.StepRecord{
		SessionID:  sessionID,
		Action:     in.Action,
		Target:     in.Target,
		Detail:     in.Detail,
		Success:    in.Success,
		StartedAt:  time.Now(),
		DurationMs: in.Duration.Milliseconds(),
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		var nextSeq int
		if err := tx.Model(&model.StepRecord{}).Where("session_id = ?", sessionID).
			Select("COALESCE(MAX(seq), 0) + 1").Scan(&nextSeq).Error; err != nil {
			return err
		}
		step.Seq = nextSeq
		return tx.Create(step).Error
	})
	if err != nil {
		return nil, fmt.Errorf("failed to record step: %w", err)
	}
	return step, nil
}

// StepsOf 按 seq 升序回放某个会话的步骤历史。limit <= 0 表示不限数量。
func StepsOf(sessionID uint, limit int) ([]model.StepRecord, error) {
	db, err := DB()
	if err != nil {
		return nil, err
	}

	var steps []model.StepRecord
	scope := db.Where("session_id = ?", sessionID).Order("seq asc")
	if limit > 0 {
		scope = scope.Limit(limit)
	}
	if err := scope.Find(&steps).Error; err != nil {
		return nil, fmt.Errorf("failed to list steps: %w", err)
	}
	return steps, nil
}

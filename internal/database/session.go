package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"vecmap/internal/model"
)

// CreateSession 创建扫描会话。
//
// 参数 session 为待持久化会话；返回会话自身的引用错误。
func (s *Store) CreateSession(session *model.Session) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}
	if session.ID == "" {
		return fmt.Errorf("session id is empty")
	}
	return s.db.Create(session).Error
}

// UpdateSession 更新会话字段与计数。
//
// 参数 session 为已存在的会话；返回更新错误。
func (s *Store) UpdateSession(session *model.Session) error {
	if session == nil || session.ID == "" {
		return fmt.Errorf("session is nil")
	}
	session.UpdatedAt = time.Now().UTC()
	return s.db.Save(session).Error
}

// GetSession 按 ID 读取会话。
//
// 参数 id 为会话主键；返回会话，未找到时返回 ErrNotFound。
func (s *Store) GetSession(id string) (*model.Session, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	var session model.Session
	if err := s.db.First(&session, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &session, nil
}

// ListSessions 分页读取会话列表。
//
// 参数 limit 与 offset 控制分页。
// 返回按创建时间倒序的会话切片与总数。
func (s *Store) ListSessions(limit, offset int) ([]*model.Session, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	var total int64
	if err := s.db.Model(&model.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var sessions []*model.Session
	if err := s.db.Order("created_at DESC").Limit(limit).Offset(offset).Find(&sessions).Error; err != nil {
		return nil, 0, err
	}
	return sessions, total, nil
}

// DeleteSession 级联删除会话及其全部关联证据。
//
// 参数 id 为会话主键；返回删除错误。
func (s *Store) DeleteSession(id string) error {
	if id == "" {
		return ErrNotFound
	}
	entities := []any{
		&model.HTTPExchange{}, &model.Endpoint{}, &model.ProbeResult{},
		&model.Record{}, &model.Collection{}, &model.Finding{},
		&model.Step{}, &model.Target{},
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, entity := range entities {
			if err := tx.Where("session_id = ?", id).Delete(entity).Error; err != nil {
				return err
			}
		}
		return tx.Delete(&model.Session{}, "id = ?", id).Error
	})
}

// SaveTargets 批量保存目标。
//
// 参数 targets 为目标切片；返回批量写入错误。
func (s *Store) SaveTargets(targets []*model.Target) error {
	if len(targets) == 0 {
		return nil
	}
	return s.db.CreateInBatches(targets, 64).Error
}

// SaveSteps 批量保存审计步骤。
//
// 参数 steps 为步骤切片；返回批量写入错误。
func (s *Store) SaveSteps(steps []*model.Step) error {
	if len(steps) == 0 {
		return nil
	}
	return s.db.CreateInBatches(steps, 128).Error
}

// SaveProbes 批量保存探测结果。
//
// 参数 probes 为探测结果切片；返回批量写入错误。
func (s *Store) SaveProbes(probes []*model.ProbeResult) error {
	if len(probes) == 0 {
		return nil
	}
	return s.db.CreateInBatches(probes, 128).Error
}

// SaveExchanges 批量保存 HTTP 证据。
//
// 参数 exchanges 为证据切片；返回批量写入错误。
func (s *Store) SaveExchanges(exchanges []*model.HTTPExchange) error {
	if len(exchanges) == 0 {
		return nil
	}
	return s.db.CreateInBatches(exchanges, 64).Error
}

// SaveFindings 批量保存风险发现。
//
// 参数 findings 为发现切片；返回批量写入错误。
func (s *Store) SaveFindings(findings []*model.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	return s.db.CreateInBatches(findings, 64).Error
}

// SaveCollections 批量保存集合快照。
//
// 参数 collections 为集合切片；返回批量写入错误。
func (s *Store) SaveCollections(collections []*model.Collection) error {
	if len(collections) == 0 {
		return nil
	}
	return s.db.CreateInBatches(collections, 64).Error
}

// SaveRecords 批量保存提取记录。
//
// 参数 records 为记录切片；返回批量写入错误。
func (s *Store) SaveRecords(records []*model.Record) error {
	if len(records) == 0 {
		return nil
	}
	return s.db.CreateInBatches(records, 128).Error
}

// SaveEndpoints 批量保存发现的端点。
//
// 参数 endpoints 为端点切片；返回批量写入错误。
func (s *Store) SaveEndpoints(endpoints []*model.Endpoint) error {
	if len(endpoints) == 0 {
		return nil
	}
	return s.db.CreateInBatches(endpoints, 128).Error
}

// UpdateSessionCounts 重新计算会话的实体计数。
//
// 参数 session 为会话；返回更新后的会话与错误。
func (s *Store) UpdateSessionCounts(session *model.Session) (*model.Session, error) {
	if session == nil || session.ID == "" {
		return nil, fmt.Errorf("session is nil")
	}
	counts := map[string]any{
		"targets":     &session.TargetCount,
		"findings":    &session.FindingCount,
		"collections": &session.CollectionCount,
		"records":     &session.RecordCount,
	}
	tables := map[string]any{
		"targets":     &model.Target{},
		"findings":    &model.Finding{},
		"collections": &model.Collection{},
		"records":     &model.Record{},
	}
	for key := range counts {
		var total int64
		if err := s.db.Model(tables[key]).Where("session_id = ?", session.ID).Count(&total).Error; err != nil {
			return nil, err
		}
		switch key {
		case "targets":
			session.TargetCount = int(total)
		case "findings":
			session.FindingCount = int(total)
		case "collections":
			session.CollectionCount = int(total)
		case "records":
			session.RecordCount = int(total)
		}
	}
	if err := s.UpdateSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

// SessionBundle 聚合会话的全部报告数据。
//
// 参数 sessionID 为会话主键；返回聚合结果，未找到时返回 ErrNotFound。
func (s *Store) SessionBundle(sessionID string) (*model.SessionBundle, error) {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	bundle := &model.SessionBundle{Session: session}
	queries := []struct {
		target any
		list   any
	}{
		{&bundle.Targets, &model.Target{}},
		{&bundle.Findings, &model.Finding{}},
		{&bundle.Collections, &model.Collection{}},
		{&bundle.Records, &model.Record{}},
		{&bundle.Probes, &model.ProbeResult{}},
		{&bundle.Steps, &model.Step{}},
		{&bundle.Endpoints, &model.Endpoint{}},
		{&bundle.Exchanges, &model.HTTPExchange{}},
	}
	for _, query := range queries {
		if err := s.db.Where("session_id = ?", sessionID).Order("created_at ASC").Find(query.target).Error; err != nil {
			return nil, err
		}
	}
	return bundle, nil
}

// Scope 返回会话的授权范围配置。
//
// 参数 session 为会话；返回解析后的范围，损坏的 JSON 返回空范围。
func SessionScope(session *model.Session) model.Scope {
	var scope model.Scope
	if session == nil || session.ScopeJSON == "" {
		return scope
	}
	_ = json.Unmarshal([]byte(session.ScopeJSON), &scope)
	return scope
}

// SetSessionScope 将会话范围序列化到持久化字段。
//
// 参数 session 为会话，scope 为范围配置；序列化失败时保留原值。
func SetSessionScope(session *model.Session, scope model.Scope) {
	payload, err := json.Marshal(scope)
	if err != nil {
		return
	}
	session.ScopeJSON = string(payload)
}

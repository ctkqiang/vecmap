package model

import (
	"encoding/json"
	"time"
)

// Field 表示向量集合或索引中的字段定义。
type Field struct {
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	DataType  string         `json:"data_type,omitempty"`
	Primary   bool           `json:"primary,omitempty"`
	Indexed   bool           `json:"indexed,omitempty"`
	Nullable  bool           `json:"nullable,omitempty"`
	Dimension int            `json:"dimension,omitempty"`
	Metric    string         `json:"metric,omitempty"`
	Params    map[string]any `json:"params,omitempty"`
}

// Index 表示向量索引及其关键参数。
type Index struct {
	Name      string         `json:"name,omitempty"`
	Type      string         `json:"type,omitempty"`
	Metric    string         `json:"metric,omitempty"`
	Dimension int            `json:"dimension,omitempty"`
	Params    map[string]any `json:"params,omitempty"`
	Field     string         `json:"field,omitempty"`
}

// Collection 表示持久化的向量集合快照。
type Collection struct {
	ID           string    `gorm:"primaryKey;size:48" json:"id"`
	SessionID    string    `gorm:"size:48;index" json:"session_id"`
	TargetID     string    `gorm:"size:48;index" json:"target_id"`
	Vendor       Vendor    `gorm:"size:32;index" json:"vendor"`
	Name         string    `gorm:"size:255;index" json:"name"`
	Namespace    string    `gorm:"size:255" json:"namespace,omitempty"`
	Status       string    `gorm:"size:48" json:"status,omitempty"`
	Dimension    int       `json:"dimension"`
	Metric       string    `gorm:"size:48" json:"metric,omitempty"`
	IndexType    string    `gorm:"size:80" json:"index_type,omitempty"`
	PointCount   int64     `json:"point_count"`
	VectorCount  int64     `json:"vector_count"`
	SegmentCount int       `json:"segment_count,omitempty"`
	AuthRequired bool      `json:"auth_required"`
	FieldsJSON   string    `gorm:"type:text" json:"-"`
	IndexesJSON  string    `gorm:"type:text" json:"-"`
	MetadataJSON string    `gorm:"type:text" json:"-"`
	SampleJSON   string    `gorm:"type:text" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// Fields 返回集合字段定义。
//
// 返回值为反序列化后的字段切片；损坏的 JSON 会返回空切片而不是中断报告。
func (c Collection) Fields() []Field {
	var fields []Field
	if c.FieldsJSON == "" {
		return fields
	}
	_ = json.Unmarshal([]byte(c.FieldsJSON), &fields)
	return fields
}

// Indexes 返回集合索引定义。
//
// 返回值为反序列化后的索引切片；损坏的 JSON 会返回空切片。
func (c Collection) Indexes() []Index {
	var indexes []Index
	if c.IndexesJSON == "" {
		return indexes
	}
	_ = json.Unmarshal([]byte(c.IndexesJSON), &indexes)
	return indexes
}

// Metadata 返回集合的扩展元数据。
//
// 返回值为反序列化后的键值映射；损坏的 JSON 会返回空映射。
func (c Collection) Metadata() map[string]any {
	metadata := map[string]any{}
	if c.MetadataJSON == "" {
		return metadata
	}
	_ = json.Unmarshal([]byte(c.MetadataJSON), &metadata)
	return metadata
}

// SetFields 将字段定义序列化到持久化字段。
//
// 参数 fields 为需要保存的字段列表；序列化失败时保留原值。
func (c *Collection) SetFields(fields []Field) {
	payload, err := json.Marshal(fields)
	if err != nil {
		return
	}
	c.FieldsJSON = string(payload)
}

// SetIndexes 将索引定义序列化到持久化字段。
//
// 参数 indexes 为需要保存的索引列表；序列化失败时保留原值。
func (c *Collection) SetIndexes(indexes []Index) {
	payload, err := json.Marshal(indexes)
	if err != nil {
		return
	}
	c.IndexesJSON = string(payload)
}

// SetMetadata 将扩展元数据序列化到持久化字段。
//
// 参数 metadata 为需要保存的键值映射；序列化失败时保留原值。
func (c *Collection) SetMetadata(metadata map[string]any) {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return
	}
	c.MetadataJSON = string(payload)
}

// Record 表示从向量集合中提取的一条记录。
//
// Payload 保存原始业务字段，Vector 保存采样向量；两者均以 JSON 文本持久化。
type Record struct {
	ID             string    `gorm:"primaryKey;size:48" json:"id"`
	SessionID      string    `gorm:"size:48;index" json:"session_id"`
	TargetID       string    `gorm:"size:48;index" json:"target_id"`
	CollectionID   string    `gorm:"size:48;index" json:"collection_id"`
	CollectionName string    `gorm:"size:255;index" json:"collection_name"`
	Namespace      string    `gorm:"size:255" json:"namespace,omitempty"`
	ExternalID     string    `gorm:"size:255;index" json:"external_id"`
	PayloadJSON    string    `gorm:"type:text" json:"-"`
	MetadataJSON   string    `gorm:"type:text" json:"-"`
	VectorJSON     string    `gorm:"type:text" json:"-"`
	VectorDim      int       `json:"vector_dim,omitempty"`
	Score          float64   `json:"score,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Payload 返回记录的业务字段。
//
// 返回值为反序列化后的键值映射；损坏的 JSON 会返回空映射。
func (r Record) Payload() map[string]any {
	payload := map[string]any{}
	if r.PayloadJSON == "" {
		return payload
	}
	_ = json.Unmarshal([]byte(r.PayloadJSON), &payload)
	return payload
}

// Vector 返回记录采样向量的原始 JSON。
//
// 返回值为空字符串表示该记录未保存向量。
func (r Record) Vector() json.RawMessage {
	if r.VectorJSON == "" {
		return nil
	}
	return json.RawMessage(r.VectorJSON)
}

// VectorSample 表示从响应中解析出的向量样本。
type VectorSample struct {
	Dimension int                  `json:"dimension"`
	Values    []float64            `json:"values,omitempty"`
	Named     map[string][]float64 `json:"named,omitempty"`
	Sparse    map[string]any       `json:"sparse,omitempty"`
}

// DumpOptions 控制只读数据枚举的深度与容量。
type DumpOptions struct {
	Collection      string `json:"collection,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	MaxRecords      int    `json:"max_records"`
	BatchSize       int    `json:"batch_size"`
	IncludeVectors  bool   `json:"include_vectors"`
	MaxVectorValues int    `json:"max_vector_values"`
	MaxPayloadBytes int    `json:"max_payload_bytes"`
	ExtractRecords  bool   `json:"extract_records"`
}

// Normalize 为枚举选项补齐安全默认值。
//
// 返回限制在合理区间内的副本，避免误配置导致超大响应或无限分页。
func (o DumpOptions) Normalize() DumpOptions {
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.BatchSize > 1000 {
		o.BatchSize = 1000
	}
	if o.MaxRecords < 0 {
		o.MaxRecords = 0
	}
	if o.MaxRecords > 100000 {
		o.MaxRecords = 100000
	}
	if o.MaxVectorValues <= 0 {
		o.MaxVectorValues = 256
	}
	if o.MaxPayloadBytes <= 0 {
		o.MaxPayloadBytes = 256 * 1024
	}
	return o
}

// DumpStats 汇总一次枚举的规模与耗时。
type DumpStats struct {
	Collections int           `json:"collections"`
	Records     int           `json:"records"`
	Vectors     int           `json:"vectors"`
	Points      int64         `json:"points"`
	Bytes       int64         `json:"bytes"`
	Duration    time.Duration `json:"duration"`
	Limited     bool          `json:"limited"`
}

// Extraction 表示厂商适配器返回的只读提取结果。
//
// 适配器不直接写数据库，由应用层统一持久化与去重。
type Extraction struct {
	Vendor      Vendor         `json:"vendor"`
	TargetID    string         `json:"target_id"`
	Collections []*Collection  `json:"collections"`
	Records     []*Record      `json:"records"`
	Endpoints   []*Endpoint    `json:"endpoints"`
	Probes      []*ProbeResult `json:"probes"`
	Stats       DumpStats      `json:"stats"`
	Errors      []string       `json:"errors,omitempty"`
}

// AddError 记录适配器的非致命错误。
//
// 参数 message 为空时忽略，避免污染报告。
func (e *Extraction) AddError(message string) {
	if message == "" {
		return
	}
	e.Errors = append(e.Errors, message)
}

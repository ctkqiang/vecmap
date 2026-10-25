package vendors

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/vecmap/internal/engine"
	"github.com/ctkqiang/vecmap/internal/model"
	"github.com/ctkqiang/vecmap/internal/utilities"
)

// Vespa 实现 Vespa 搜索容器与配置服务的只读适配器。
type Vespa struct {
	Base
}

// NewVespa 创建 Vespa 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewVespa(runtime *engine.Runtime) *Vespa {
	return &Vespa{Base: Base{VendorID: model.VendorVespa, Ports: []int{8080, 19071}, Runtime: runtime}}
}

// Fingerprint 识别 Vespa 服务。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (v *Vespa) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorVespa,
		Product:    "vespa",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
	}
	health, healthErr := v.Get(ctx, target, "/state/v1/health", options)
	if healthErr == nil && health != nil {
		if engine.IsSuccess(health.StatusCode) {
			if value, decodeErr := engine.DecodeJSONMap(health); decodeErr == nil {
				status := Map(value["status"])
				code := FirstString(status, "code")
				if code != "" {
					fingerprint.Confidence = model.ConfidenceMedium
					fingerprint.Evidence = append(fingerprint.Evidence, "health status: "+code)
				}
			}
		}
		if engine.IsAuthRequired(health.StatusCode) {
			fingerprint.AuthRequired = true
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("health returned %d", health.StatusCode))
		}
	}
	versionExchange, versionErr := v.Get(ctx, target, "/state/v1/version", options)
	if versionErr == nil && versionExchange != nil && engine.IsSuccess(versionExchange.StatusCode) {
		if value, decodeErr := engine.DecodeJSONMap(versionExchange); decodeErr == nil {
			if version := FirstString(value, "version"); version != "" {
				fingerprint.Version = version
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "version: "+version)
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		status, statusErr := v.Get(ctx, target, "/ApplicationStatus", options)
		if statusErr == nil && status != nil && engine.IsSuccess(status.StatusCode) {
			lower := strings.ToLower(status.ResponseBody)
			if strings.Contains(lower, "vespa") || strings.Contains(lower, "application status") {
				fingerprint.Confidence = model.ConfidenceMedium
				fingerprint.Evidence = append(fingerprint.Evidence, "ApplicationStatus page matched")
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		if metrics, metricsErr := v.Get(ctx, target, "/metrics/v2/values", options); metricsErr == nil && metrics != nil && engine.IsSuccess(metrics.StatusCode) {
			if _, decodeErr := engine.DecodeJSONMap(metrics); decodeErr == nil {
				fingerprint.Confidence = model.ConfidenceMedium
				fingerprint.Evidence = append(fingerprint.Evidence, "metrics v2 endpoint reachable")
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

// Enumerate 使用 Vespa 搜索 API 枚举文档并按文档类型聚合。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制记录上限与向量采样。返回按 doctype 聚合的集合与记录。
func (v *Vespa) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorVespa, TargetID: target.ID}
	collections := map[string]*model.Collection{}
	fields := map[string]map[string]model.Field{}
	offset := 0
	total := int64(0)
	for len(extraction.Records) < dump.MaxRecords {
		limit := dump.BatchSize
		if remaining := dump.MaxRecords - len(extraction.Records); remaining < limit {
			limit = remaining
		}
		if !dump.ExtractRecords {
			limit = 1
		}
		value, err := v.search(ctx, target, options, offset, limit)
		if err != nil {
			if offset == 0 {
				return extraction, err
			}
			break
		}
		root := Map(value["root"])
		rootFields := Map(root["fields"])
		if count, ok := Integer(rootFields["totalCount"]); ok && total == 0 {
			total = count
		}
		children := MapSlice(root["children"])
		if len(children) == 0 {
			break
		}
		for _, child := range children {
			documentID := FirstString(child, "id")
			doctype := vespaDoctype(documentID)
			if dump.Collection != "" && doctype != dump.Collection {
				continue
			}
			collection, exists := collections[doctype]
			if !exists {
				collection = &model.Collection{
					ID:        utilities.NewID("col"),
					TargetID:  target.ID,
					Vendor:    model.VendorVespa,
					Name:      doctype,
					Status:    "ready",
					IndexType: "vespa",
					CreatedAt: time.Now().UTC(),
				}
				collection.PointCount = total
				collections[doctype] = collection
				fields[doctype] = map[string]model.Field{}
				extraction.Collections = append(extraction.Collections, collection)
			}
			documentFields := Map(child["fields"])
			payload := map[string]any{}
			vector := VectorData{}
			vectorName := ""
			if dump.IncludeVectors {
				vectorName, vector = vespaVector(documentFields, dump.MaxVectorValues)
				if vector.Dimension > collection.Dimension {
					collection.Dimension = vector.Dimension
				}
			}
			for key, raw := range documentFields {
				if key == vectorName && !vector.Empty() {
					continue
				}
				payload[key] = raw
				field := fields[doctype][key]
				if field.Name == "" {
					fields[doctype][key] = Field(key, vespaFieldType(raw))
				}
			}
			if !dump.ExtractRecords {
				continue
			}
			record := v.Record(target, collection, documentID, payload, vector, dump.MaxPayloadBytes)
			extraction.Records = append(extraction.Records, record)
		}
		if !dump.ExtractRecords || len(children) < limit {
			break
		}
		offset += len(children)
		if total > 0 && int64(offset) >= total {
			break
		}
	}
	for name, collection := range collections {
		list := make([]model.Field, 0, len(fields[name]))
		for _, field := range fields[name] {
			if field.Dimension == 0 {
				field.Dimension = collection.Dimension
			}
			list = append(list, field)
		}
		collection.SetFields(list)
		if collection.Dimension > 0 {
			collection.SetIndexes([]model.Index{{
				Name:      "default",
				Type:      "vespa",
				Dimension: collection.Dimension,
			}})
		}
	}
	return extraction, nil
}

func (v *Vespa) search(ctx context.Context, target *model.Target, options model.ScanOptions, offset, limit int) (map[string]any, error) {
	query := url.Values{}
	query.Set("yql", "select * from sources * where true;")
	query.Set("hits", strconv.Itoa(limit))
	query.Set("offset", strconv.Itoa(offset))
	query.Set("timeout", "5s")
	exchange, err := v.Get(ctx, target, "/search/?"+query.Encode(), options)
	if err != nil {
		return nil, err
	}
	return v.JSONMap(exchange)
}

func vespaDoctype(documentID string) string {
	documentID = strings.TrimSpace(documentID)
	if !strings.HasPrefix(documentID, "id:") {
		if documentID == "" {
			return "default"
		}
		return documentID
	}
	parts := strings.SplitN(strings.TrimPrefix(documentID, "id:"), ":", 3)
	if len(parts) < 2 || parts[1] == "" {
		return "default"
	}
	return parts[1]
}

func vespaVector(fields map[string]any, maxValues int) (string, VectorData) {
	bestName := ""
	bestDimension := 0
	for name, raw := range fields {
		values, ok := raw.([]any)
		if !ok || len(values) < 2 {
			continue
		}
		vector := ParseVector(values, maxValues)
		if vector.Dimension < 2 {
			continue
		}
		priority := 0
		lower := strings.ToLower(name)
		if strings.Contains(lower, "embedding") || strings.Contains(lower, "vector") || strings.Contains(lower, "tensor") {
			priority = 1
		}
		if priority > 0 || vector.Dimension > bestDimension {
			bestName = name
			bestDimension = vector.Dimension
		}
	}
	if bestName == "" {
		return "", VectorData{}
	}
	return bestName, ParseVector(fields[bestName], maxValues)
}

func vespaFieldType(value any) string {
	switch typed := value.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case float64:
		return "number"
	case []any:
		if len(typed) > 0 {
			if _, ok := typed[0].(float64); ok {
				return "tensor"
			}
			return "array"
		}
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

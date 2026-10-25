package vendors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ctkqiang/vecmap/internal/engine"
	"github.com/ctkqiang/vecmap/internal/model"
	"github.com/ctkqiang/vecmap/internal/utilities"
)

// Typesense 实现 Typesense REST 适配器。
type Typesense struct {
	Base
}

// NewTypesense 创建 Typesense 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewTypesense(runtime *engine.Runtime) *Typesense {
	return &Typesense{Base: Base{VendorID: model.VendorTypesense, Ports: []int{8108}, Runtime: runtime}}
}

// Fingerprint 识别 Typesense 服务。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (t *Typesense) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorTypesense,
		Product:    "typesense",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
	}
	health, healthErr := t.Get(ctx, target, "/health", options)
	if healthErr == nil && health != nil {
		fingerprint.HTTP = &model.HTTPInfo{
			StatusCode:  health.StatusCode,
			ContentType: health.ContentType,
			BodyPreview: utilities.Truncate(health.ResponseBody, 300),
		}
		if engine.IsSuccess(health.StatusCode) && strings.Contains(strings.ToLower(health.ResponseBody), "\"ok\"") {
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, "health ok")
		}
		if engine.IsAuthRequired(health.StatusCode) {
			fingerprint.AuthRequired = true
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("health returned %d", health.StatusCode))
		}
	}
	debug, debugErr := t.Get(ctx, target, "/debug", options)
	if debugErr == nil && debug != nil && engine.IsSuccess(debug.StatusCode) {
		if value, decodeErr := engine.DecodeJSONMap(debug); decodeErr == nil {
			if version := FirstString(value, "version"); version != "" {
				fingerprint.Version = version
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "version: "+version)
			}
			if state, exists := value["state"]; exists {
				fingerprint.Metadata = map[string]any{"state": state}
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		collections, collectionsErr := t.Get(ctx, target, "/collections", options)
		if collectionsErr == nil && collections != nil && engine.IsSuccess(collections.StatusCode) {
			if _, decodeErr := engine.DecodeJSONArray(collections); decodeErr == nil {
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "collections array shape matched")
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

// Enumerate 枚举 Typesense 集合并提取文档。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制分页、记录上限与向量采样。返回集合、文档与统计。
func (t *Typesense) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorTypesense, TargetID: target.ID}
	exchange, err := t.Get(ctx, target, "/collections", options)
	if err != nil {
		return extraction, err
	}
	items, err := t.JSONArray(exchange)
	if err != nil {
		return extraction, err
	}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		collection, vectorFields, textFields := typesenseCollection(target, entry)
		if dump.Collection != "" && collection.Name != dump.Collection {
			continue
		}
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, searchErr := t.documents(ctx, target, collection, vectorFields, textFields, options, dump)
		if searchErr != nil {
			extraction.AddError(fmt.Sprintf("%s: %s", collection.Name, searchErr))
			continue
		}
		extraction.Records = append(extraction.Records, records...)
		if len(extraction.Records) >= dump.MaxRecords {
			extraction.Stats.Limited = true
			break
		}
	}
	return extraction, nil
}

func typesenseCollection(target *model.Target, item map[string]any) (*model.Collection, []string, []string) {
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorTypesense,
		Name:      FirstString(item, "name"),
		Status:    "ready",
		CreatedAt: time.Now().UTC(),
	}
	if count, ok := Integer(item["num_documents"]); ok {
		collection.PointCount = count
	}
	fields := make([]model.Field, 0, 12)
	indexes := make([]model.Index, 0, 2)
	vectorFields := make([]string, 0, 2)
	textFields := make([]string, 0, 8)
	for _, rawField := range MapSlice(item["fields"]) {
		fieldName := FirstString(rawField, "name")
		fieldType := FirstString(rawField, "type")
		field := Field(fieldName, fieldType)
		field.Indexed = Bool(rawField["index"])
		field.Nullable = Bool(rawField["optional"])
		if isTypesenseVectorField(fieldType) {
			vectorFields = append(vectorFields, fieldName)
			dimension := intValue(rawField["num_dim"])
			metric := FirstString(rawField, "vec_dist", "distance")
			field.Dimension = dimension
			field.Metric = metric
			if collection.Dimension == 0 {
				collection.Dimension = dimension
				collection.Metric = metric
				collection.IndexType = "hnsw"
			}
			indexes = append(indexes, model.Index{
				Name:      fieldName,
				Type:      "hnsw",
				Metric:    metric,
				Dimension: dimension,
				Field:     fieldName,
				Params: map[string]any{
					"num_dim":  rawField["num_dim"],
					"vec_dist": rawField["vec_dist"],
				},
			})
			continue
		}
		if fieldType == "string" || fieldType == "string[]" {
			textFields = append(textFields, fieldName)
		}
		fields = append(fields, field)
	}
	if collection.IndexType == "" {
		collection.IndexType = "inverted"
	}
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	collection.SetMetadata(map[string]any{
		"default_sorting_field": item["default_sorting_field"],
		"enable_nested_fields":  item["enable_nested_fields"],
		"symbols_to_index":      item["symbols_to_index"],
		"token_separators":      item["token_separators"],
		"created_at":            item["created_at"],
	})
	return collection, vectorFields, textFields
}

func isTypesenseVectorField(fieldType string) bool {
	return strings.HasPrefix(fieldType, "float[]") || strings.HasPrefix(fieldType, "int32[]") ||
		strings.EqualFold(fieldType, "vector")
}

func (t *Typesense) documents(ctx context.Context, target *model.Target, collection *model.Collection, vectorFields, textFields []string, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	queryBy := ""
	if len(textFields) > 0 {
		queryBy = textFields[0]
	}
	if queryBy == "" {
		return t.exportDocuments(ctx, target, collection, vectorFields, options, dump)
	}
	records := make([]*model.Record, 0, dump.BatchSize)
	page := 1
	for len(records) < dump.MaxRecords {
		limit := dump.BatchSize
		if remaining := dump.MaxRecords - len(records); remaining < limit {
			limit = remaining
		}
		if limit > 250 {
			limit = 250
		}
		query := url.Values{}
		query.Set("q", "*")
		query.Set("query_by", queryBy)
		query.Set("per_page", fmt.Sprintf("%d", limit))
		query.Set("page", fmt.Sprintf("%d", page))
		exchange, err := t.Get(ctx, target, "/collections/"+url.PathEscape(collection.Name)+"/documents/search?"+query.Encode(), options)
		if err != nil {
			return records, err
		}
		value, err := t.JSONMap(exchange)
		if err != nil {
			if page == 1 {
				return t.exportDocuments(ctx, target, collection, vectorFields, options, dump)
			}
			return records, err
		}
		hits := MapSlice(value["hits"])
		for _, hit := range hits {
			document := Map(hit["document"])
			vector := VectorData{}
			if dump.IncludeVectors {
				for _, field := range vectorFields {
					if raw, exists := document[field]; exists {
						vector = ParseVector(raw, dump.MaxVectorValues)
						break
					}
				}
			}
			externalID := FirstString(document, "id")
			record := t.Record(target, collection, externalID, FilterFields(document, vectorFields), vector, dump.MaxPayloadBytes)
			records = append(records, record)
		}
		if len(hits) < limit {
			break
		}
		page++
	}
	return records, nil
}

func (t *Typesense) exportDocuments(ctx context.Context, target *model.Target, collection *model.Collection, vectorFields []string, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	query := url.Values{}
	if !dump.IncludeVectors && len(vectorFields) > 0 {
		query.Set("exclude_fields", strings.Join(vectorFields, ","))
	}
	path := "/collections/" + url.PathEscape(collection.Name) + "/documents/export"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	exchange, err := t.Get(ctx, target, path, options)
	if err != nil {
		return nil, err
	}
	if err := engine.EnsureJSON(exchange); err != nil {
		return nil, err
	}
	records := make([]*model.Record, 0, dump.BatchSize)
	for _, line := range strings.Split(exchange.ResponseBody, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal([]byte(line), &document); err != nil {
			continue
		}
		vector := VectorData{}
		if dump.IncludeVectors {
			for _, field := range vectorFields {
				if raw, exists := document[field]; exists {
					vector = ParseVector(raw, dump.MaxVectorValues)
					break
				}
			}
		}
		record := t.Record(target, collection, FirstString(document, "id"), FilterFields(document, vectorFields), vector, dump.MaxPayloadBytes)
		records = append(records, record)
		if len(records) >= dump.MaxRecords {
			break
		}
	}
	return records, nil
}

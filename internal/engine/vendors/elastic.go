package vendors

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"vecmap/internal/engine"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// Elastic 实现 Elasticsearch 与 OpenSearch 的向量检索适配器。
type Elastic struct {
	Base
	OpenSearch bool
}

// NewElasticsearch 创建 Elasticsearch 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewElasticsearch(runtime *engine.Runtime) *Elastic {
	return &Elastic{Base: Base{VendorID: model.VendorElasticsearch, Ports: []int{9200, 9300}, Runtime: runtime}}
}

// NewOpenSearch 创建 OpenSearch 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewOpenSearch(runtime *engine.Runtime) *Elastic {
	return &Elastic{Base: Base{VendorID: model.VendorOpenSearch, Ports: []int{9200, 9300}, Runtime: runtime}, OpenSearch: true}
}

// Fingerprint 识别 Elasticsearch 或 OpenSearch。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (e *Elastic) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	exchange, err := e.Get(ctx, target, "/", options)
	if err != nil || exchange == nil {
		return nil, engine.ErrNotMatched
	}
	fingerprint := &model.Fingerprint{
		Vendor:     e.VendorID,
		Product:    string(e.VendorID),
		Confidence: model.ConfidenceLow,
		TLS:        exchange.TLS,
		HTTP: &model.HTTPInfo{
			StatusCode:  exchange.StatusCode,
			ContentType: exchange.ContentType,
			BodyPreview: utilities.Truncate(exchange.ResponseBody, 400),
		},
	}
	if engine.IsAuthRequired(exchange.StatusCode) {
		fingerprint.AuthRequired = true
		fingerprint.Confidence = model.ConfidenceMedium
		fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("root returned %d", exchange.StatusCode))
	}
	if engine.IsSuccess(exchange.StatusCode) {
		value, decodeErr := engine.DecodeJSONMap(exchange)
		if decodeErr == nil {
			version := Map(value["version"])
			number := FirstString(version, "number")
			distribution := FirstString(version, "distribution")
			tagline := FirstString(value, "tagline")
			clusterName := FirstString(value, "cluster_name")
			if number != "" {
				fingerprint.Version = number
			}
			if strings.EqualFold(distribution, "opensearch") || strings.Contains(strings.ToLower(tagline), "opensearch") {
				fingerprint.Vendor = model.VendorOpenSearch
				fingerprint.Product = "opensearch"
			} else if e.OpenSearch {
				fingerprint.Vendor = model.VendorOpenSearch
				fingerprint.Product = "opensearch"
			} else {
				fingerprint.Vendor = model.VendorElasticsearch
				fingerprint.Product = "elasticsearch"
			}
			if number != "" || strings.Contains(strings.ToLower(tagline), "you know, for search") {
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "version="+number)
				if tagline != "" {
					fingerprint.Evidence = append(fingerprint.Evidence, "tagline="+utilities.Truncate(tagline, 80))
				}
				if clusterName != "" {
					fingerprint.Evidence = append(fingerprint.Evidence, "cluster="+clusterName)
				}
			}
			fingerprint.Metadata = map[string]any{
				"cluster_name": clusterName,
				"cluster_uuid": FirstString(value, "cluster_uuid"),
				"tagline":      tagline,
				"version":      version,
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		if health, healthErr := e.Get(ctx, target, "/_cluster/health", options); healthErr == nil && health != nil {
			if engine.IsSuccess(health.StatusCode) || engine.IsAuthRequired(health.StatusCode) {
				fingerprint.Confidence = model.ConfidenceMedium
				fingerprint.AuthRequired = engine.IsAuthRequired(health.StatusCode)
				fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("cluster health returned %d", health.StatusCode))
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

// Enumerate 枚举索引、映射并提取文档样本。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制记录上限与向量采样。返回索引、文档与统计。
func (e *Elastic) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: e.VendorID, TargetID: target.ID}
	names, err := e.indices(ctx, target, options)
	if err != nil {
		return extraction, err
	}
	if dump.Collection != "" {
		names = filterNames(names, dump.Collection)
	}
	for _, name := range names {
		collection, vectorFields, err := e.describe(ctx, target, name, options)
		if err != nil {
			extraction.AddError(fmt.Sprintf("%s: %s", name, err))
			continue
		}
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, searchErr := e.search(ctx, target, collection, vectorFields, options, dump)
		if searchErr != nil {
			extraction.AddError(fmt.Sprintf("%s search: %s", name, searchErr))
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

func (e *Elastic) indices(ctx context.Context, target *model.Target, options model.ScanOptions) ([]string, error) {
	exchange, err := e.Get(ctx, target, "/_cat/indices?format=json&bytes=b&h=index,docs.count,store.size,status,health", options)
	if err != nil {
		return nil, err
	}
	items, err := engine.DecodeJSONArray(exchange)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if name := FirstString(entry, "index"); name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func (e *Elastic) describe(ctx context.Context, target *model.Target, name string, options model.ScanOptions) (*model.Collection, []string, error) {
	exchange, err := e.Get(ctx, target, "/"+url.PathEscape(name)+"/_mapping", options)
	if err != nil {
		return nil, nil, err
	}
	value, err := e.JSONMap(exchange)
	if err != nil {
		return nil, nil, err
	}
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    e.VendorID,
		Name:      name,
		Status:    "open",
		CreatedAt: time.Now().UTC(),
	}
	fields := make([]model.Field, 0, 12)
	indexes := make([]model.Index, 0, 4)
	vectorFields := make([]string, 0, 2)
	for _, indexValue := range value {
		mappings := Map(Map(indexValue)["mappings"])
		for fieldName, rawProperty := range Map(mappings["properties"]) {
			property := Map(rawProperty)
			dataType := FirstString(property, "type")
			field := Field(fieldName, dataType)
			field.Indexed = true
			if dimension := elasticDimension(property); dimension > 0 {
				field.Dimension = dimension
				if collection.Dimension == 0 {
					collection.Dimension = dimension
				}
			}
			if strings.Contains(strings.ToLower(dataType), "vector") {
				vectorFields = append(vectorFields, fieldName)
				method := Map(property["method"])
				metric := utilities.FirstNonEmpty(FirstString(property, "similarity"), FirstString(method, "space_type"))
				indexType := utilities.FirstNonEmpty(FirstString(property, "index_type"), FirstString(method, "name"))
				if indexType == "" {
					indexType = "vector"
				}
				field.Metric = metric
				if collection.Metric == "" {
					collection.Metric = metric
				}
				if collection.IndexType == "" {
					collection.IndexType = indexType
				}
				indexes = append(indexes, model.Index{
					Name:      fieldName,
					Type:      indexType,
					Metric:    metric,
					Dimension: field.Dimension,
					Field:     fieldName,
					Params:    property,
				})
			}
			fields = append(fields, field)
		}
	}
	if collection.IndexType == "" {
		collection.IndexType = "lucene"
	}
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	collection.SetMetadata(map[string]any{"mapping": value})
	return collection, vectorFields, nil
}

func elasticDimension(property map[string]any) int {
	for _, key := range []string{"dims", "dimension", "dim"} {
		if dimension, ok := Integer(property[key]); ok && dimension > 0 {
			return int(dimension)
		}
	}
	return 0
}

func (e *Elastic) search(ctx context.Context, target *model.Target, collection *model.Collection, vectorFields []string, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	records := make([]*model.Record, 0, dump.BatchSize)
	offset := 0
	for len(records) < dump.MaxRecords {
		limit := dump.BatchSize
		if remaining := dump.MaxRecords - len(records); remaining < limit {
			limit = remaining
		}
		body := map[string]any{
			"from":  offset,
			"size":  limit,
			"query": map[string]any{"match_all": map[string]any{}},
		}
		path := "/" + url.PathEscape(collection.Name) + "/_search?track_total_hits=true"
		exchange, err := e.PostJSON(ctx, target, path, body, options)
		if err != nil {
			return records, err
		}
		value, err := e.JSONMap(exchange)
		if err != nil {
			return records, err
		}
		hits := Map(value["hits"])
		total := Map(hits["total"])
		if count, ok := Integer(total["value"]); ok && collection.PointCount == 0 {
			collection.PointCount = count
		}
		items := MapSlice(hits["hits"])
		for _, hit := range items {
			source := Map(hit["_source"])
			vector := VectorData{}
			if dump.IncludeVectors {
				for _, field := range vectorFields {
					if raw, exists := source[field]; exists {
						vector = ParseVector(raw, dump.MaxVectorValues)
						break
					}
				}
			}
			payload := FilterFields(source, vectorFields)
			record := e.Record(target, collection, FirstString(hit, "_id"), payload, vector, dump.MaxPayloadBytes)
			records = append(records, record)
		}
		if len(items) < limit {
			break
		}
		offset += len(items)
	}
	return records, nil
}

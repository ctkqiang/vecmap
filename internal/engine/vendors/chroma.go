package vendors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"vecmap/internal/engine"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// Chroma 实现 Chroma / ChromaDB v1 与 v2 REST 适配器。
type Chroma struct {
	Base
}

// NewChroma 创建 Chroma 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewChroma(runtime *engine.Runtime) *Chroma {
	return &Chroma{Base: Base{VendorID: model.VendorChroma, Ports: []int{8000}, Runtime: runtime}}
}

// Fingerprint 识别 Chroma 服务。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (c *Chroma) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorChroma,
		Product:    "chromadb",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
	}
	heartbeat, heartbeatErr := c.Get(ctx, target, "/api/v1/heartbeat", options)
	if heartbeatErr == nil && heartbeat != nil {
		if engine.IsSuccess(heartbeat.StatusCode) && strings.Contains(strings.ToLower(heartbeat.ResponseBody), "heartbeat") {
			fingerprint.Confidence = model.ConfidenceHigh
			fingerprint.Evidence = append(fingerprint.Evidence, "v1 heartbeat shape matched")
		}
		if engine.IsAuthRequired(heartbeat.StatusCode) {
			fingerprint.AuthRequired = true
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("v1 heartbeat returned %d", heartbeat.StatusCode))
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		heartbeat, heartbeatErr = c.Get(ctx, target, "/api/v2/heartbeat", options)
		if heartbeatErr == nil && heartbeat != nil && engine.IsSuccess(heartbeat.StatusCode) && strings.Contains(strings.ToLower(heartbeat.ResponseBody), "heartbeat") {
			fingerprint.Confidence = model.ConfidenceHigh
			fingerprint.Evidence = append(fingerprint.Evidence, "v2 heartbeat shape matched")
		}
	}
	version, versionErr := c.Get(ctx, target, "/api/v1/version", options)
	if versionErr == nil && version != nil && engine.IsSuccess(version.StatusCode) {
		if value, decodeErr := engine.DecodeJSONMap(version); decodeErr == nil {
			if parsed := FirstString(value, "version"); parsed != "" {
				fingerprint.Version = parsed
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "version: "+parsed)
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		collections, collectionsErr := c.Get(ctx, target, "/api/v1/collections", options)
		if collectionsErr == nil && collections != nil && engine.IsSuccess(collections.StatusCode) {
			if _, decodeErr := engine.DecodeJSONArray(collections); decodeErr == nil {
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "v1 collections array shape matched")
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

// Enumerate 枚举 Chroma 集合与记录。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制分页、向量采样与命名空间。返回集合、记录与统计。
func (c *Chroma) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorChroma, TargetID: target.ID}
	collections, basePath, foundV2, err := c.listCollections(ctx, target, options)
	if err != nil {
		return extraction, err
	}
	for _, item := range collections {
		collection := chromaCollection(target, item, foundV2)
		if dump.Namespace != "" && collection.Namespace != dump.Namespace {
			continue
		}
		if dump.Collection != "" && collection.Name != dump.Collection {
			continue
		}
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		if count, countErr := c.count(ctx, target, basePath, collection, options); countErr == nil {
			collection.PointCount = count
		}
		records, listErr := c.records(ctx, target, basePath, collection, options, dump)
		if listErr != nil {
			extraction.AddError(fmt.Sprintf("%s: %s", collection.Name, listErr))
		}
		extraction.Records = append(extraction.Records, records...)
		if len(extraction.Records) >= dump.MaxRecords {
			extraction.Stats.Limited = true
			break
		}
	}
	return extraction, nil
}

func (c *Chroma) listCollections(ctx context.Context, target *model.Target, options model.ScanOptions) ([]map[string]any, string, bool, error) {
	v1, v1Err := c.Get(ctx, target, "/api/v1/collections", options)
	if v1Err == nil && v1 != nil {
		if items, decodeErr := engine.DecodeJSONArray(v1); decodeErr == nil {
			result := make([]map[string]any, 0, len(items))
			for _, item := range items {
				if entry, ok := item.(map[string]any); ok {
					result = append(result, entry)
				}
			}
			return result, "/api/v1/collections", false, nil
		}
	}
	tenant := utilities.FirstNonEmpty(options.Credentials.Database, "default_tenant")
	database := "default_database"
	if strings.Contains(options.Credentials.Database, "/") {
		parts := strings.SplitN(options.Credentials.Database, "/", 2)
		tenant = parts[0]
		database = parts[1]
	}
	path := fmt.Sprintf("/api/v2/tenants/%s/databases/%s/collections", url.PathEscape(tenant), url.PathEscape(database))
	v2, v2Err := c.Get(ctx, target, path, options)
	if v2Err != nil || v2 == nil {
		if v1Err != nil {
			return nil, "", false, v1Err
		}
		return nil, "", false, v2Err
	}
	items, decodeErr := engine.DecodeJSONArray(v2)
	if decodeErr != nil {
		return nil, "", false, decodeErr
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			entry["_tenant"] = tenant
			entry["_database"] = database
			result = append(result, entry)
		}
	}
	return result, fmt.Sprintf("/api/v2/tenants/%s/databases/%s/collections", url.PathEscape(tenant), url.PathEscape(database)), true, nil
}

func chromaCollection(target *model.Target, item map[string]any, v2 bool) *model.Collection {
	name := FirstString(item, "name")
	metadata := Map(item["metadata"])
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorChroma,
		Name:      name,
		Status:    "ready",
		IndexType: "hnsw",
		Metric:    FirstString(metadata, "hnsw:space"),
		CreatedAt: time.Now().UTC(),
	}
	if v2 {
		tenant := FirstString(item, "_tenant", "tenant")
		database := FirstString(item, "_database", "database")
		collection.Namespace = strings.Trim(strings.Join([]string{tenant, database}, "/"), "/")
	}
	if dimension, ok := Integer(metadata["dimension"]); ok {
		collection.Dimension = int(dimension)
	}
	fields := []model.Field{
		{Name: "id", Type: "string", DataType: "string", Primary: true},
		{Name: "document", Type: "string", DataType: "string"},
		{Name: "metadata", Type: "object", DataType: "object"},
		{Name: "embedding", Type: "vector", DataType: "vector", Dimension: collection.Dimension},
	}
	collection.SetFields(fields)
	collection.SetIndexes([]model.Index{{
		Name:      "hnsw",
		Type:      "hnsw",
		Metric:    collection.Metric,
		Field:     "embedding",
		Dimension: collection.Dimension,
		Params:    metadata,
	}})
	collection.SetMetadata(map[string]any{
		"collection_id": item["id"],
		"metadata":      metadata,
		"tenant":        item["tenant"],
		"database":      item["database"],
	})
	return collection
}

func (c *Chroma) count(ctx context.Context, target *model.Target, basePath string, collection *model.Collection, options model.ScanOptions) (int64, error) {
	collectionID := chromaCollectionID(collection)
	path := basePath + "/" + url.PathEscape(collectionID) + "/count"
	exchange, err := c.Get(ctx, target, path, options)
	if err != nil {
		return 0, err
	}
	if !engine.IsSuccess(exchange.StatusCode) {
		return 0, engine.StatusError("count", exchange.StatusCode, exchange.ResponseBody)
	}
	value, ok := Integer(strings.TrimSpace(exchange.ResponseBody))
	if ok {
		return value, nil
	}
	var decoded any
	if decodeErr := json.Unmarshal([]byte(exchange.ResponseBody), &decoded); decodeErr == nil {
		if number, numberOK := Integer(decoded); numberOK {
			return number, nil
		}
	}
	return 0, fmt.Errorf("count response is not an integer: %s", utilities.Truncate(exchange.ResponseBody, 120))
}

func (c *Chroma) records(ctx context.Context, target *model.Target, basePath string, collection *model.Collection, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	records := make([]*model.Record, 0, dump.BatchSize)
	offset := 0
	for len(records) < dump.MaxRecords {
		limit := dump.BatchSize
		if remaining := dump.MaxRecords - len(records); remaining < limit {
			limit = remaining
		}
		collectionID := chromaCollectionID(collection)
		path := basePath + "/" + url.PathEscape(collectionID) + "/get"
		payload := map[string]any{
			"limit":   limit,
			"offset":  offset,
			"include": []string{"documents", "metadatas", "embeddings"},
		}
		exchange, err := c.PostJSON(ctx, target, path, payload, options)
		if err != nil {
			return records, err
		}
		value, err := c.JSONMap(exchange)
		if err != nil {
			return records, err
		}
		ids := chromaList(value["ids"])
		documents := chromaList(value["documents"])
		metadatas := chromaList(value["metadatas"])
		embeddings := chromaList(value["embeddings"])
		if len(ids) == 0 {
			break
		}
		for index, idValue := range ids {
			payloadMap := map[string]any{}
			if index < len(documents) && documents[index] != nil {
				payloadMap["document"] = documents[index]
			}
			if index < len(metadatas) && metadatas[index] != nil {
				payloadMap["metadata"] = metadatas[index]
			}
			vector := VectorData{}
			if index < len(embeddings) {
				vector = ParseVector(embeddings[index], dump.MaxVectorValues)
				if vector.Dimension > collection.Dimension {
					collection.Dimension = vector.Dimension
				}
			}
			if !dump.IncludeVectors {
				vector = VectorData{}
			}
			record := c.Record(target, collection, String(idValue), payloadMap, vector, dump.MaxPayloadBytes)
			if !dump.IncludeVectors && collection.Dimension > 0 {
				record.VectorDim = collection.Dimension
			}
			records = append(records, record)
		}
		if len(ids) < limit {
			break
		}
		offset += len(ids)
	}
	return records, nil
}

func chromaCollectionID(collection *model.Collection) string {
	metadata := collection.Metadata()
	if id := String(metadata["collection_id"]); id != "" {
		return id
	}
	return collection.Name
}

func chromaList(value any) []any {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	if len(items) == 1 {
		if nested, ok := items[0].([]any); ok {
			return nested
		}
	}
	return items
}

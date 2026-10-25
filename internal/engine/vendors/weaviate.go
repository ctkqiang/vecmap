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

// Weaviate 实现 Weaviate REST 适配器。
type Weaviate struct {
	Base
}

// NewWeaviate 创建 Weaviate 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewWeaviate(runtime *engine.Runtime) *Weaviate {
	return &Weaviate{Base: Base{VendorID: model.VendorWeaviate, Ports: []int{8080, 50051}, Runtime: runtime}}
}

// Fingerprint 识别 Weaviate 服务。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (w *Weaviate) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	if target.Scheme == "grpc" {
		return w.grpcFingerprint(ctx, target)
	}
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorWeaviate,
		Product:    "weaviate",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
	}
	exchange, err := w.Get(ctx, target, "/v1/meta", options)
	if err == nil && exchange != nil {
		fingerprint.HTTP = &model.HTTPInfo{
			StatusCode:  exchange.StatusCode,
			ContentType: exchange.ContentType,
			BodyPreview: utilities.Truncate(exchange.ResponseBody, 400),
		}
		if engine.IsSuccess(exchange.StatusCode) {
			if value, decodeErr := engine.DecodeJSONMap(exchange); decodeErr == nil {
				version := FirstString(value, "version")
				if version != "" {
					fingerprint.Version = version
					fingerprint.Confidence = model.ConfidenceHigh
					fingerprint.Evidence = append(fingerprint.Evidence, "meta version: "+version)
				}
			}
		}
		if engine.IsAuthRequired(exchange.StatusCode) {
			fingerprint.AuthRequired = true
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("meta returned %d", exchange.StatusCode))
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		ready, readyErr := w.Get(ctx, target, "/v1/.well-known/ready", options)
		if readyErr == nil && ready != nil && engine.IsSuccess(ready.StatusCode) {
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, "readiness endpoint reachable")
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		schema, schemaErr := w.Get(ctx, target, "/v1/schema", options)
		if schemaErr == nil && schema != nil && engine.IsSuccess(schema.StatusCode) {
			if value, decodeErr := engine.DecodeJSONMap(schema); decodeErr == nil {
				if _, ok := value["classes"].([]any); ok {
					fingerprint.Confidence = model.ConfidenceHigh
					fingerprint.Evidence = append(fingerprint.Evidence, "schema classes shape matched")
				}
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

func (w *Weaviate) grpcFingerprint(ctx context.Context, target *model.Target) (*model.Fingerprint, error) {
	info, _ := w.Runtime.GRPC.Probe(ctx, engine.TargetAddress(*target), target.TLS)
	if info == nil || !info.Reachable {
		return nil, engine.ErrNotMatched
	}
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorWeaviate,
		Product:    "weaviate",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
		GRPC:       info,
	}
	for _, service := range info.Services {
		name := strings.ToLower(service.Name)
		if strings.Contains(name, "weaviate") {
			fingerprint.Confidence = model.ConfidenceHigh
			fingerprint.Evidence = append(fingerprint.Evidence, "gRPC service: "+service.Name)
			break
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

// Enumerate 枚举 Weaviate 类与对象。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制分页与向量采样。返回集合、记录与统计。
func (w *Weaviate) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorWeaviate, TargetID: target.ID}
	exchange, err := w.Get(ctx, target, "/v1/schema", options)
	if err != nil {
		return extraction, err
	}
	value, err := w.JSONMap(exchange)
	if err != nil {
		return extraction, err
	}
	classes := MapSlice(value["classes"])
	for _, class := range classes {
		collection := weaviateCollection(target, class)
		if dump.Collection != "" && collection.Name != dump.Collection {
			continue
		}
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, listErr := w.objects(ctx, target, collection, options, dump)
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

func weaviateCollection(target *model.Target, class map[string]any) *model.Collection {
	name := FirstString(class, "class")
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorWeaviate,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	collection.IndexType = FirstString(class, "vectorIndexType")
	indexConfig := Map(class["vectorIndexConfig"])
	collection.Metric = FirstString(indexConfig, "distance")
	fields := make([]model.Field, 0, len(MapSlice(class["properties"])))
	for _, property := range MapSlice(class["properties"]) {
		fieldName := FirstString(property, "name")
		dataTypes := Strings(property["dataType"])
		field := Field(fieldName, strings.Join(dataTypes, "|"))
		field.Indexed = true
		field.Params = map[string]any{"tokenization": property["tokenization"], "description": property["description"]}
		fields = append(fields, field)
	}
	indexes := make([]model.Index, 0, 2)
	if collection.IndexType != "" || collection.Metric != "" {
		indexes = append(indexes, model.Index{
			Name:   "default",
			Type:   collection.IndexType,
			Metric: collection.Metric,
			Params: indexConfig,
		})
	}
	if vectorConfig := Map(class["vectorConfig"]); len(vectorConfig) > 0 {
		for vectorName, item := range vectorConfig {
			config := Map(item)
			indexes = append(indexes, model.Index{
				Name:   vectorName,
				Type:   FirstString(config, "vectorIndexType"),
				Metric: FirstString(Map(config["vectorIndexConfig"]), "distance"),
				Field:  vectorName,
				Params: Map(config["vectorIndexConfig"]),
			})
		}
	}
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	collection.SetMetadata(map[string]any{
		"description":   class["description"],
		"vectorizer":    class["vectorizer"],
		"module_config": class["moduleConfig"],
		"vector_config": class["vectorConfig"],
		"replication":   class["replicationConfig"],
		"sharding":      class["shardingConfig"],
	})
	return collection
}

func (w *Weaviate) objects(ctx context.Context, target *model.Target, collection *model.Collection, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	records := make([]*model.Record, 0, dump.BatchSize)
	after := ""
	for len(records) < dump.MaxRecords {
		limit := dump.BatchSize
		if remaining := dump.MaxRecords - len(records); remaining < limit {
			limit = remaining
		}
		query := url.Values{}
		query.Set("class", collection.Name)
		query.Set("limit", fmt.Sprintf("%d", limit))
		if after != "" {
			query.Set("after", after)
		}
		if dump.IncludeVectors {
			query.Set("include", "vector")
		}
		exchange, err := w.Get(ctx, target, "/v1/objects?"+query.Encode(), options)
		if err != nil {
			return records, err
		}
		value, err := w.JSONMap(exchange)
		if err != nil {
			return records, err
		}
		objects := MapSlice(value["objects"])
		for _, object := range objects {
			vectorValue := object["vector"]
			if vectorValue == nil {
				if vectors := Map(object["vectors"]); len(vectors) > 0 {
					vectorValue = vectors
				}
			}
			vector := VectorData{}
			if dump.IncludeVectors {
				vector = ParseVector(vectorValue, dump.MaxVectorValues)
				if vector.Dimension > collection.Dimension {
					collection.Dimension = vector.Dimension
				}
			}
			properties := Map(object["properties"])
			externalID := FirstString(object, "id")
			record := w.Record(target, collection, externalID, properties, vector, dump.MaxPayloadBytes)
			records = append(records, record)
			after = externalID
		}
		if count, ok := Integer(value["totalResults"]); ok && collection.PointCount == 0 {
			collection.PointCount = count
		}
		if len(objects) < limit || after == "" {
			break
		}
	}
	if collection.PointCount == 0 {
		collection.PointCount = int64(len(records))
	}
	return records, nil
}

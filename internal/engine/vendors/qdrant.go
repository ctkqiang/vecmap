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

// Qdrant 实现 Qdrant REST 与 gRPC 适配器。
type Qdrant struct {
	Base
}

// NewQdrant 创建 Qdrant 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewQdrant(runtime *engine.Runtime) *Qdrant {
	return &Qdrant{Base: Base{VendorID: model.VendorQdrant, Ports: []int{6333, 6334}, Runtime: runtime}}
}

// Fingerprint 识别 Qdrant 服务。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (q *Qdrant) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	if target.Scheme == "grpc" {
		return q.grpcFingerprint(ctx, target)
	}
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorQdrant,
		Product:    "qdrant",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
	}
	exchange, err := q.Get(ctx, target, "/", options)
	if err != nil && exchange == nil {
		return nil, engine.ErrNotMatched
	}
	if exchange != nil {
		fingerprint.AuthRequired = engine.IsAuthRequired(exchange.StatusCode)
		fingerprint.HTTP = &model.HTTPInfo{
			StatusCode:  exchange.StatusCode,
			ContentType: exchange.ContentType,
			BodyPreview: utilities.Truncate(exchange.ResponseBody, 400),
		}
		if engine.IsSuccess(exchange.StatusCode) {
			if value, decodeErr := engine.DecodeJSONMap(exchange); decodeErr == nil {
				title := String(value["title"])
				version := String(value["version"])
				if strings.Contains(strings.ToLower(title), "qdrant") || strings.Contains(strings.ToLower(exchange.ResponseBody), "qdrant") {
					fingerprint.Vendor = model.VendorQdrant
					fingerprint.Product = utilities.FirstNonEmpty(title, "qdrant")
					fingerprint.Version = version
					fingerprint.Confidence = model.ConfidenceHigh
					fingerprint.Evidence = append(fingerprint.Evidence, "root title: "+utilities.Truncate(title, 120))
					if version != "" {
						fingerprint.Evidence = append(fingerprint.Evidence, "version: "+version)
					}
				}
			}
		}
		if engine.IsAuthRequired(exchange.StatusCode) {
			fingerprint.AuthRequired = true
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		health, healthErr := q.Get(ctx, target, "/healthz", options)
		if healthErr == nil && engine.IsSuccess(health.StatusCode) && strings.Contains(strings.ToLower(health.ResponseBody), "healthz check passed") {
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, "healthz check passed")
		}
		collections, collectionsErr := q.Get(ctx, target, "/collections", options)
		if collectionsErr == nil && engine.IsSuccess(collections.StatusCode) {
			if value, decodeErr := engine.DecodeJSONMap(collections); decodeErr == nil {
				if result, ok := value["result"].(map[string]any); ok {
					if _, ok := result["collections"].([]any); ok {
						fingerprint.Confidence = model.ConfidenceHigh
						fingerprint.AuthRequired = false
						fingerprint.Evidence = append(fingerprint.Evidence, "collections result shape matched")
					}
				}
			}
		}
	}
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

func (q *Qdrant) grpcFingerprint(ctx context.Context, target *model.Target) (*model.Fingerprint, error) {
	address := engine.TargetAddress(*target)
	info, _ := q.Runtime.GRPC.Probe(ctx, address, target.TLS)
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorQdrant,
		Product:    "qdrant",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
		GRPC:       info,
	}
	if info == nil || !info.Reachable {
		return nil, engine.ErrNotMatched
	}
	if stringsFound, err := q.Runtime.GRPC.ProbeRawStrings(ctx, address, "/qdrant.Qdrant/HealthCheck", nil, target.TLS); err == nil {
		for _, value := range stringsFound {
			lower := strings.ToLower(value)
			if strings.Contains(lower, "qdrant") {
				fingerprint.Vendor = model.VendorQdrant
				fingerprint.Product = "qdrant"
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "gRPC health: "+utilities.Truncate(value, 120))
				continue
			}
			if fingerprint.Version == "" && looksLikeVersion(value) {
				fingerprint.Version = value
				fingerprint.Evidence = append(fingerprint.Evidence, "gRPC version: "+value)
			}
		}
	}
	for _, service := range info.Services {
		if strings.HasPrefix(strings.ToLower(service.Name), "qdrant") {
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

// Enumerate 枚举 Qdrant 集合并只读滚动提取记录。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制记录上限、批大小与向量采样。
// 返回集合、记录与统计；单个集合失败会记录为非致命错误。
func (q *Qdrant) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorQdrant, TargetID: target.ID}
	if target.Scheme == "grpc" {
		q.enumerateGRPC(ctx, target, dump, extraction)
		return extraction, nil
	}
	exchange, err := q.Get(ctx, target, "/collections", options)
	if err != nil {
		return extraction, err
	}
	value, err := q.JSONMap(exchange)
	if err != nil {
		return extraction, err
	}
	result := Map(value["result"])
	names := make([]string, 0, 8)
	for _, item := range MapSlice(result["collections"]) {
		if name := FirstString(item, "name"); name != "" {
			names = append(names, name)
		}
	}
	if dump.Collection != "" {
		names = filterNames(names, dump.Collection)
	}
	if len(names) == 0 {
		extraction.AddError("no collections returned")
		return extraction, nil
	}
	for _, name := range names {
		collection, describeErr := q.describe(ctx, target, name, options)
		if describeErr != nil {
			extraction.AddError(fmt.Sprintf("%s: %s", name, describeErr))
			continue
		}
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, scrollErr := q.scroll(ctx, target, collection, options, dump)
		if scrollErr != nil {
			extraction.AddError(fmt.Sprintf("%s scroll: %s", name, scrollErr))
		}
		extraction.Records = append(extraction.Records, records...)
		if len(extraction.Records) >= dump.MaxRecords {
			extraction.Stats.Limited = true
			break
		}
	}
	return extraction, nil
}

func (q *Qdrant) describe(ctx context.Context, target *model.Target, name string, options model.ScanOptions) (*model.Collection, error) {
	path := "/collections/" + url.PathEscape(name)
	exchange, err := q.Get(ctx, target, path, options)
	if err != nil {
		return nil, err
	}
	value, err := q.JSONMap(exchange)
	if err != nil {
		return nil, err
	}
	return qdrantCollection(target, name, Map(value["result"])), nil
}

func qdrantCollection(target *model.Target, name string, result map[string]any) *model.Collection {
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorQdrant,
		Name:      name,
		Status:    FirstString(result, "status"),
		CreatedAt: time.Now().UTC(),
	}
	points, _ := Integer(result["points_count"])
	collection.PointCount = points
	vectors, _ := Integer(result["vectors_count"])
	collection.VectorCount = vectors
	segments, _ := Integer(result["segments_count"])
	collection.SegmentCount = int(segments)
	config := Map(result["config"])
	params := Map(config["params"])
	vectorsConfig := Map(params["vectors"])
	fields := make([]model.Field, 0, 8)
	indexes := make([]model.Index, 0, 4)
	if _, isSingle := vectorsConfig["size"]; isSingle {
		size, _ := Integer(vectorsConfig["size"])
		collection.Dimension = int(size)
		collection.Metric = FirstString(vectorsConfig, "distance")
		indexes = append(indexes, model.Index{
			Name:      "default",
			Type:      "hnsw",
			Dimension: int(size),
			Metric:    collection.Metric,
			Params:    VectorParams(vectorsConfig),
		})
	} else {
		for vectorName, item := range vectorsConfig {
			vectorMap := Map(item)
			size, _ := Integer(vectorMap["size"])
			if collection.Dimension == 0 {
				collection.Dimension = int(size)
				collection.Metric = FirstString(vectorMap, "distance")
			}
			indexes = append(indexes, model.Index{
				Name:      vectorName,
				Type:      "hnsw",
				Dimension: int(size),
				Metric:    FirstString(vectorMap, "distance"),
				Field:     vectorName,
				Params:    VectorParams(vectorMap),
			})
		}
	}
	for fieldName, schema := range Map(result["payload_schema"]) {
		schemaMap := Map(schema)
		dataType := FirstString(schemaMap, "data_type", "type")
		fields = append(fields, model.Field{Name: fieldName, Type: dataType, DataType: dataType, Indexed: true})
	}
	if collection.IndexType == "" {
		collection.IndexType = "hnsw"
	}
	collection.SetMetadata(map[string]any{
		"optimizer_status":      result["optimizer_status"],
		"vectors_count":         result["vectors_count"],
		"indexed_vectors_count": result["indexed_vectors_count"],
		"shard_number":          params["shard_number"],
		"replication_factor":    params["replication_factor"],
		"on_disk_payload":       params["on_disk_payload"],
	})
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	return collection
}

// VectorParams 提取向量索引相关参数。
//
// 参数 values 为向量配置映射；返回常见索引参数的子集。
func VectorParams(values map[string]any) map[string]any {
	result := map[string]any{}
	for _, key := range []string{"size", "distance", "on_disk", "hnsw_config", "quantization_config", "datatype", "multivector_config"} {
		if value, exists := values[key]; exists {
			result[key] = value
		}
	}
	return result
}

func (q *Qdrant) scroll(ctx context.Context, target *model.Target, collection *model.Collection, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	records := make([]*model.Record, 0, dump.BatchSize)
	var offset any
	for len(records) < dump.MaxRecords {
		remaining := dump.MaxRecords - len(records)
		limit := dump.BatchSize
		if remaining < limit {
			limit = remaining
		}
		if limit <= 0 {
			break
		}
		payload := map[string]any{
			"limit":        limit,
			"with_payload": true,
			"with_vector":  dump.IncludeVectors,
		}
		if offset != nil {
			payload["offset"] = offset
		}
		path := "/collections/" + url.PathEscape(collection.Name) + "/points/scroll"
		exchange, err := q.PostJSON(ctx, target, path, payload, options)
		if err != nil {
			return records, err
		}
		value, err := q.JSONMap(exchange)
		if err != nil {
			return records, err
		}
		result := Map(value["result"])
		points := MapSlice(result["points"])
		for _, point := range points {
			externalID := pointID(point["id"])
			payloadMap := Map(point["payload"])
			vector := VectorData{}
			if dump.IncludeVectors {
				vector = ParseVector(point["vector"], dump.MaxVectorValues)
			}
			records = append(records, q.Record(target, collection, externalID, payloadMap, vector, dump.MaxPayloadBytes))
		}
		offset = result["next_page_offset"]
		if offset == nil || len(points) == 0 {
			break
		}
	}
	return records, nil
}

func (q *Qdrant) enumerateGRPC(ctx context.Context, target *model.Target, dump model.DumpOptions, extraction *model.Extraction) {
	address := engine.TargetAddress(*target)
	listPayload, err := q.Runtime.GRPC.InvokeDynamic(ctx, address, "qdrant.Collections", "List", map[string]any{}, target.TLS)
	if err != nil {
		extraction.AddError("gRPC List: " + err.Error())
		return
	}
	listValue := map[string]any{}
	if err := json.Unmarshal(listPayload, &listValue); err != nil {
		extraction.AddError("gRPC List decode: " + err.Error())
		return
	}
	names := make([]string, 0, 8)
	for _, item := range MapSlice(listValue["collections"]) {
		if name := FirstString(item, "name"); name != "" {
			names = append(names, name)
		}
	}
	if dump.Collection != "" {
		names = filterNames(names, dump.Collection)
	}
	for _, name := range names {
		describePayload, describeErr := q.Runtime.GRPC.InvokeDynamic(ctx, address, "qdrant.Collections", "Get", map[string]any{"collection_name": name}, target.TLS)
		if describeErr != nil {
			extraction.AddError(fmt.Sprintf("%s gRPC Get: %s", name, describeErr))
			continue
		}
		describeValue := map[string]any{}
		if err := json.Unmarshal(describePayload, &describeValue); err != nil {
			extraction.AddError(fmt.Sprintf("%s gRPC Get decode: %s", name, err))
			continue
		}
		collection := qdrantCollection(target, name, Map(describeValue["result"]))
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		var offset any
		for len(extraction.Records) < dump.MaxRecords {
			request := map[string]any{
				"collection_name": name,
				"limit":           dump.BatchSize,
				"with_payload":    true,
				"with_vector":     dump.IncludeVectors,
			}
			if offset != nil {
				request["offset"] = offset
			}
			payload, invokeErr := q.Runtime.GRPC.InvokeDynamic(ctx, address, "qdrant.Points", "Scroll", request, target.TLS)
			if invokeErr != nil {
				extraction.AddError(fmt.Sprintf("%s gRPC Scroll: %s", name, invokeErr))
				break
			}
			value := map[string]any{}
			if err := json.Unmarshal(payload, &value); err != nil {
				extraction.AddError(fmt.Sprintf("%s gRPC Scroll decode: %s", name, err))
				break
			}
			result := Map(value["result"])
			points := MapSlice(result["points"])
			for _, point := range points {
				vector := VectorData{}
				if dump.IncludeVectors {
					vector = ParseVector(point["vector"], dump.MaxVectorValues)
				}
				extraction.Records = append(extraction.Records, q.Record(target, collection, pointID(point["id"]), Map(point["payload"]), vector, dump.MaxPayloadBytes))
			}
			offset = result["next_page_offset"]
			if offset == nil || len(points) == 0 {
				break
			}
		}
	}
}

func pointID(value any) string {
	if entry, ok := value.(map[string]any); ok {
		if id := FirstString(entry, "uuid", "num"); id != "" {
			return id
		}
	}
	return String(value)
}

func filterNames(names []string, filter string) []string {
	if strings.TrimSpace(filter) == "" {
		return names
	}
	result := make([]string, 0, 1)
	for _, name := range names {
		if name == filter {
			result = append(result, name)
		}
	}
	return result
}

func looksLikeVersion(value string) bool {
	value = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(value), "v"))
	if value == "" {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

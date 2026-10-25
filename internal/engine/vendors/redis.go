package vendors

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/vecmap/internal/engine"
	"github.com/ctkqiang/vecmap/internal/model"
	"github.com/ctkqiang/vecmap/internal/utilities"
)

// Redis 实现 Redis / RediSearch 向量索引适配器。
//
// 该适配器仅使用 PING、INFO、MODULE LIST、FT._LIST、FT.INFO 与 FT.SEARCH
// 等只读命令，不会写入、删除或重建任何键或索引。
type Redis struct {
	Base
}

// NewRedis 创建 Redis 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewRedis(runtime *engine.Runtime) *Redis {
	return &Redis{Base: Base{VendorID: model.VendorRedis, Ports: []int{6379, 6380}, Runtime: runtime}}
}

// Fingerprint 识别 Redis 与 RediSearch 模块。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；目标不是 Redis 时返回 engine.ErrNotMatched。
func (r *Redis) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	client, err := r.dial(ctx, target, options)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "noauth") {
			return &model.Fingerprint{
				Vendor:       model.VendorRedis,
				Product:      "redis",
				Confidence:   model.ConfidenceHigh,
				AuthRequired: true,
				TLS:          target.TLS,
				Evidence:     []string{"PING returned NOAUTH"},
			}, nil
		}
		return nil, engine.ErrNotMatched
	}
	defer func() { _ = client.Close() }()
	info, infoErr := client.Info(ctx, "server")
	if infoErr != nil {
		if strings.Contains(strings.ToLower(infoErr.Error()), "noauth") {
			return &model.Fingerprint{
				Vendor:       model.VendorRedis,
				Product:      "redis",
				Confidence:   model.ConfidenceHigh,
				AuthRequired: true,
				TLS:          target.TLS,
				Evidence:     []string{"INFO returned NOAUTH"},
			}, nil
		}
		return nil, engine.ErrNotMatched
	}
	version := redisInfoValue(info, "redis_version")
	if version == "" {
		return nil, engine.ErrNotMatched
	}
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorRedis,
		Product:    "redis",
		Version:    version,
		Confidence: model.ConfidenceHigh,
		TLS:        target.TLS,
		Evidence:   []string{"redis_version=" + version},
	}
	if mode := redisInfoValue(info, "redis_mode"); mode != "" {
		fingerprint.Metadata = map[string]any{"redis_mode": mode}
		fingerprint.Evidence = append(fingerprint.Evidence, "redis_mode="+mode)
	}
	if modules, modulesErr := client.Modules(ctx); modulesErr == nil {
		names := make([]string, 0, len(modules))
		for _, module := range modules {
			name := module["name"]
			if name == "" {
				continue
			}
			names = append(names, name)
			if strings.EqualFold(name, "search") {
				fingerprint.Product = "redisearch"
				fingerprint.Evidence = append(fingerprint.Evidence, "module: search "+module["ver"])
			}
			if strings.EqualFold(name, "vectorset") {
				fingerprint.Evidence = append(fingerprint.Evidence, "module: vectorset")
			}
		}
		if len(names) > 0 {
			fingerprint.Evidence = append(fingerprint.Evidence, "modules: "+strings.Join(names, ","))
		}
	}
	if indexes, indexesErr := client.SearchIndexes(ctx); indexesErr == nil {
		fingerprint.Product = "redisearch"
		fingerprint.Metadata = map[string]any{"search_indexes": len(indexes)}
		fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("search indexes: %d", len(indexes)))
	}
	return fingerprint, nil
}

// Enumerate 枚举 RediSearch 索引并执行只读分页查询。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制记录上限与字段返回。返回索引、文档与统计；
// 未加载 RediSearch 时返回带说明的非致命错误。
func (r *Redis) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorRedis, TargetID: target.ID}
	client, err := r.dial(ctx, target, options)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "noauth") {
			return extraction, engine.ErrUnauthorized
		}
		return extraction, err
	}
	defer func() { _ = client.Close() }()
	indexes, err := client.SearchIndexes(ctx)
	if err != nil {
		extraction.AddError("FT._LIST: " + err.Error())
		return extraction, nil
	}
	for _, name := range indexes {
		if dump.Collection != "" && name != dump.Collection {
			continue
		}
		info, infoErr := client.SearchInfo(ctx, name)
		if infoErr != nil {
			extraction.AddError(fmt.Sprintf("%s: %s", name, infoErr))
			continue
		}
		collection, vectorFields, textFields := redisCollection(target, name, info)
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, searchErr := r.search(ctx, client, target, collection, vectorFields, textFields, dump)
		if searchErr != nil {
			extraction.AddError(fmt.Sprintf("%s FT.SEARCH: %s", name, searchErr))
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

func (r *Redis) dial(ctx context.Context, target *model.Target, options model.ScanOptions) (*engine.RespClient, error) {
	if target == nil {
		return nil, fmt.Errorf("target is nil")
	}
	return engine.DialRESP(ctx, engine.TargetAddress(*target), engine.RespOptions{
		Timeout:  options.Timeout,
		TLS:      target.TLS,
		Insecure: options.Insecure,
		Username: options.Credentials.Username,
		Password: options.Credentials.Password,
		Database: redisDatabase(options.Credentials.Database),
	})
}

func redisDatabase(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func (r *Redis) search(ctx context.Context, client *engine.RespClient, target *model.Target, collection *model.Collection, vectorFields, textFields []string, dump model.DumpOptions) ([]*model.Record, error) {
	records := make([]*model.Record, 0, dump.BatchSize)
	offset := 0
	returnFields := append([]string(nil), textFields...)
	if dump.IncludeVectors {
		returnFields = append(returnFields, vectorFields...)
	}
	for len(records) < dump.MaxRecords {
		limit := dump.BatchSize
		if remaining := dump.MaxRecords - len(records); remaining < limit {
			limit = remaining
		}
		documents, total, err := client.Search(ctx, collection.Name, "*", offset, limit, returnFields)
		if err != nil {
			return records, err
		}
		if collection.PointCount == 0 {
			collection.PointCount = total
		}
		for _, document := range documents {
			payload := map[string]any{}
			vector := VectorData{}
			for key, value := range document.Fields {
				if isRedisVectorField(key, vectorFields) {
					if dump.IncludeVectors && vector.Empty() {
						vector = redisVector(value, collection.Dimension, dump.MaxVectorValues)
					}
					continue
				}
				payload[key] = redisPayloadValue(value)
			}
			externalID := document.ID
			if externalID == "" {
				externalID = fmt.Sprintf("offset-%d", offset+len(records))
			}
			records = append(records, r.Record(target, collection, externalID, payload, vector, dump.MaxPayloadBytes))
		}
		if len(documents) < limit {
			break
		}
		offset += len(documents)
	}
	return records, nil
}

func redisCollection(target *model.Target, name string, info map[string]any) (*model.Collection, []string, []string) {
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorRedis,
		Name:      name,
		Status:    "ready",
		IndexType: FirstString(info, "index_type"),
		CreatedAt: time.Now().UTC(),
	}
	if count, ok := Integer(info["num_docs"]); ok {
		collection.PointCount = count
	}
	fields := make([]model.Field, 0, 8)
	indexes := make([]model.Index, 0, 2)
	vectorFields := make([]string, 0, 2)
	textFields := make([]string, 0, 8)
	for _, attribute := range MapSlice(info["attributes"]) {
		fieldName := FirstString(attribute, "attribute", "identifier")
		if fieldName == "" {
			continue
		}
		dataType := FirstString(attribute, "type")
		field := Field(fieldName, dataType)
		field.Indexed = true
		field.Params = map[string]any{
			"algorithm":       attribute["algorithm"],
			"data_type":       attribute["data_type"],
			"sortable":        attribute["sortable"],
			"no_index":        attribute["no_index"],
			"distance_metric": attribute["distance_metric"],
		}
		if strings.EqualFold(dataType, "VECTOR") {
			vectorFields = append(vectorFields, fieldName)
			dimension := intValue(attribute["dim"])
			metric := FirstString(attribute, "distance_metric")
			field.Dimension = dimension
			field.Metric = metric
			if collection.Dimension == 0 {
				collection.Dimension = dimension
				collection.Metric = metric
			}
			indexType := strings.ToLower(FirstString(attribute, "algorithm"))
			if indexType == "" {
				indexType = "vector"
			}
			if collection.IndexType == "" {
				collection.IndexType = indexType
			}
			indexes = append(indexes, model.Index{
				Name:      fieldName,
				Type:      indexType,
				Metric:    metric,
				Dimension: dimension,
				Field:     fieldName,
				Params:    field.Params,
			})
			continue
		}
		textFields = append(textFields, fieldName)
		fields = append(fields, field)
	}
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	collection.SetMetadata(map[string]any{
		"index_definition":       info["index_definition"],
		"index_options":          info["index_options"],
		"num_terms":              info["num_terms"],
		"num_records":            info["num_records"],
		"hash_indexing_failures": info["hash_indexing_failures"],
	})
	return collection, vectorFields, textFields
}

func redisInfoValue(info, key string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), key) {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func isRedisVectorField(name string, vectorFields []string) bool {
	for _, field := range vectorFields {
		if name == field {
			return true
		}
	}
	return false
}

func redisPayloadValue(value string) any {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return value
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var decoded any
		if err := json.Unmarshal([]byte(trimmed), &decoded); err == nil {
			return decoded
		}
	}
	return value
}

func redisVector(value string, dimension, maxValues int) VectorData {
	if len(value) == 0 {
		return VectorData{}
	}
	if dimension > 0 && len(value) == dimension*4 {
		values := make([]float64, 0, dimension)
		for offset := 0; offset+4 <= len(value); offset += 4 {
			bits := binary.LittleEndian.Uint32([]byte(value[offset : offset+4]))
			number := float64(math.Float32frombits(bits))
			if math.IsNaN(number) || math.IsInf(number, 0) {
				continue
			}
			if len(values) < maxValues {
				values = append(values, number)
			}
		}
		if len(values) > 0 {
			return buildVector(values)
		}
	}
	return ParseVector(value, maxValues)
}

func intValue(value any) int {
	number, ok := Integer(value)
	if !ok {
		return 0
	}
	return int(number)
}

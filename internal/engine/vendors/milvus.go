package vendors

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ctkqiang/vecmap/internal/engine"
	"github.com/ctkqiang/vecmap/internal/model"
	"github.com/ctkqiang/vecmap/internal/utilities"
)

// Milvus 实现 Milvus REST v2、gRPC 反射与原始 RPC 适配器。
type Milvus struct {
	Base
}

// NewMilvus 创建 Milvus 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewMilvus(runtime *engine.Runtime) *Milvus {
	return &Milvus{Base: Base{VendorID: model.VendorMilvus, Ports: []int{19530, 9091}, Runtime: runtime}}
}

// Fingerprint 识别 Milvus 服务。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (m *Milvus) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorMilvus,
		Product:    "milvus",
		Confidence: model.ConfidenceLow,
		TLS:        target.TLS,
	}
	if target.Scheme == "grpc" {
		m.grpcEvidence(ctx, target, fingerprint)
		if fingerprint.Confidence == model.ConfidenceLow {
			return nil, engine.ErrNotMatched
		}
		return fingerprint, nil
	}
	health, healthErr := m.Get(ctx, target, "/healthz", options)
	if healthErr == nil && health != nil {
		if engine.IsAuthRequired(health.StatusCode) {
			fingerprint.AuthRequired = true
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("healthz returned %d", health.StatusCode))
		}
		if engine.IsSuccess(health.StatusCode) {
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, "healthz reachable")
		}
	}
	listExchange, listErr := m.PostJSON(ctx, target, "/v2/vectordb/collections/list", map[string]any{"dbName": "default"}, options)
	if listErr == nil && listExchange != nil {
		if engine.IsAuthRequired(listExchange.StatusCode) {
			fingerprint.AuthRequired = true
			fingerprint.Confidence = model.ConfidenceMedium
			fingerprint.Evidence = append(fingerprint.Evidence, "collections API requires authentication")
		}
		if value, decodeErr := engine.DecodeJSONMap(listExchange); decodeErr == nil {
			if code, exists := Integer(value["code"]); exists && code == 0 {
				if _, hasData := value["data"]; hasData {
					fingerprint.Confidence = model.ConfidenceHigh
					fingerprint.AuthRequired = false
					fingerprint.Evidence = append(fingerprint.Evidence, "REST v2 collections response shape matched")
				}
			}
		}
	}
	if target.Port == 9091 && fingerprint.Confidence == model.ConfidenceLow {
		root, rootErr := m.Get(ctx, target, "/", options)
		if rootErr == nil && root != nil && engine.IsSuccess(root.StatusCode) {
			body := strings.ToLower(root.ResponseBody)
			if strings.Contains(body, "milvus") {
				fingerprint.Confidence = model.ConfidenceMedium
				fingerprint.Evidence = append(fingerprint.Evidence, "management port banner")
			}
		}
	}
	m.grpcEvidence(ctx, target, fingerprint)
	if fingerprint.Confidence == model.ConfidenceLow {
		return nil, engine.ErrNotMatched
	}
	return fingerprint, nil
}

func (m *Milvus) grpcEvidence(ctx context.Context, target *model.Target, fingerprint *model.Fingerprint) {
	if target.Scheme != "grpc" && target.Port != 19530 && target.Port != 9091 {
		return
	}
	address := engine.TargetAddress(*target)
	info, _ := m.Runtime.GRPC.Probe(ctx, address, target.TLS)
	if info != nil {
		fingerprint.GRPC = info
		if info.Reachable {
			fingerprint.Evidence = append(fingerprint.Evidence, "gRPC health reachable")
		}
		for _, service := range info.Services {
			if strings.HasPrefix(strings.ToLower(service.Name), "milvus") {
				fingerprint.Confidence = model.ConfidenceHigh
				fingerprint.Evidence = append(fingerprint.Evidence, "gRPC service: "+service.Name)
				break
			}
		}
	}
	values, err := m.Runtime.GRPC.ProbeRawStrings(ctx, address, "/milvus.proto.milvus.MilvusService/GetVersion", nil, target.TLS)
	if err != nil {
		return
	}
	for _, value := range values {
		if looksLikeVersion(value) && fingerprint.Version == "" {
			fingerprint.Version = value
			fingerprint.Confidence = model.ConfidenceHigh
			fingerprint.Evidence = append(fingerprint.Evidence, "gRPC version: "+value)
		}
		if strings.Contains(strings.ToLower(value), "milvus") {
			fingerprint.Confidence = model.ConfidenceHigh
			fingerprint.Evidence = append(fingerprint.Evidence, "gRPC banner: "+utilities.Truncate(value, 120))
		}
	}
}

// Enumerate 枚举 Milvus 集合并提取记录。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制提取上限。优先使用 REST v2；失败时回退到 gRPC 反射。
// 返回集合、记录与统计。
func (m *Milvus) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorMilvus, TargetID: target.ID}
	if target.Scheme != "grpc" {
		names, err := m.restCollections(ctx, target, options)
		if err == nil && len(names) > 0 {
			m.restExtract(ctx, target, options, dump, names, extraction)
			return extraction, nil
		}
		if err != nil {
			extraction.AddError("REST enumeration: " + err.Error())
		}
	}
	m.grpcExtract(ctx, target, dump, extraction)
	return extraction, nil
}

func (m *Milvus) restCollections(ctx context.Context, target *model.Target, options model.ScanOptions) ([]string, error) {
	exchange, err := m.PostJSON(ctx, target, "/v2/vectordb/collections/list", map[string]any{"dbName": "default"}, options)
	if err != nil {
		return nil, err
	}
	value, err := m.JSONMap(exchange)
	if err != nil {
		return nil, err
	}
	if code, _ := Integer(value["code"]); code != 0 {
		return nil, fmt.Errorf("%s", utilities.FirstNonEmpty(FirstString(value, "message", "error"), "list failed"))
	}
	names := make([]string, 0, 8)
	for _, item := range Slice(value["data"]) {
		switch typed := item.(type) {
		case string:
			names = append(names, typed)
		case map[string]any:
			if name := FirstString(typed, "collectionName", "collection_name", "name"); name != "" {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

func (m *Milvus) restExtract(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions, names []string, extraction *model.Extraction) {
	if dump.Collection != "" {
		names = filterNames(names, dump.Collection)
	}
	for _, name := range names {
		collection, primaryField, primaryType, vectorFields, describeErr := m.restDescribe(ctx, target, name, options)
		if describeErr != nil {
			extraction.AddError(fmt.Sprintf("%s: %s", name, describeErr))
			continue
		}
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, queryErr := m.restQuery(ctx, target, options, dump, collection, primaryField, primaryType, vectorFields)
		if queryErr != nil && len(records) == 0 {
			extraction.AddError(fmt.Sprintf("%s query: %s", name, queryErr))
			continue
		}
		extraction.Records = append(extraction.Records, records...)
		if len(extraction.Records) >= dump.MaxRecords {
			extraction.Stats.Limited = true
			break
		}
	}
}

func (m *Milvus) restDescribe(ctx context.Context, target *model.Target, name string, options model.ScanOptions) (*model.Collection, string, string, []string, error) {
	exchange, err := m.PostJSON(ctx, target, "/v2/vectordb/collections/describe", map[string]any{
		"dbName":         "default",
		"collectionName": name,
	}, options)
	if err != nil {
		return nil, "", "", nil, err
	}
	value, err := m.JSONMap(exchange)
	if err != nil {
		return nil, "", "", nil, err
	}
	if code, _ := Integer(value["code"]); code != 0 {
		return nil, "", "", nil, fmt.Errorf("%s", utilities.FirstNonEmpty(FirstString(value, "message", "error"), "describe failed"))
	}
	data := Map(value["data"])
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorMilvus,
		Name:      utilities.FirstNonEmpty(FirstString(data, "collectionName", "collection_name"), name),
		Status:    FirstString(data, "loadState", "load_state", "state"),
		CreatedAt: time.Now().UTC(),
	}
	fields := make([]model.Field, 0, 8)
	indexes := make([]model.Index, 0, 4)
	primaryField := ""
	primaryType := ""
	vectorFields := make([]string, 0, 2)
	for _, item := range MapSlice(data["fields"]) {
		fieldName := FirstString(item, "name")
		fieldType := milvusType(item["type"], item["dataType"])
		field := Field(fieldName, fieldType)
		field.Primary = Bool(item["isPrimary"]) || Bool(item["is_primary_field"])
		field.Params = milvusFieldParams(item)
		if dimension, ok := Integer(field.Params["dim"]); ok && dimension > 0 {
			field.Dimension = int(dimension)
			if collection.Dimension == 0 {
				collection.Dimension = int(dimension)
			}
		}
		if field.Primary {
			primaryField = fieldName
			primaryType = fieldType
		}
		if isMilvusVectorType(fieldType) {
			vectorFields = append(vectorFields, fieldName)
			indexes = append(indexes, model.Index{Name: fieldName, Type: "milvus", Field: fieldName, Dimension: field.Dimension})
		}
		fields = append(fields, field)
	}
	collection.Metric = FirstString(data, "metricType", "metric_type")
	if collection.Metric == "" {
		for _, item := range MapSlice(data["indexes"]) {
			metric := FirstString(item, "metricType", "metric_type")
			indexName := FirstString(item, "indexName", "index_name", "fieldName")
			indexType := FirstString(item, "indexType", "index_type")
			collection.Metric = utilities.FirstNonEmpty(collection.Metric, metric)
			if indexName != "" {
				index := Index(indexName, utilities.FirstNonEmpty(indexType, "milvus"))
				index.Metric = metric
				indexes = append(indexes, index)
			}
		}
	}
	if dimension, ok := Integer(data["dimension"]); ok {
		collection.Dimension = int(dimension)
	}
	if count, ok := Integer(data["numEntities"]); ok {
		collection.PointCount = count
	}
	if len(indexes) > 0 {
		collection.IndexType = indexes[0].Type
	}
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	collection.SetMetadata(map[string]any{
		"collection_id":     data["collectionID"],
		"consistency_level": data["consistencyLevel"],
		"num_shards":        data["numShards"],
		"num_partitions":    data["numPartitions"],
		"description":       data["description"],
	})
	return collection, primaryField, primaryType, vectorFields, nil
}

func (m *Milvus) restQuery(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions, collection *model.Collection, primaryField, primaryType string, vectorFields []string) ([]*model.Record, error) {
	records := make([]*model.Record, 0, dump.BatchSize)
	offset := 0
	filters := milvusFilters(primaryField, primaryType)
	var lastErr error
	for _, filter := range filters {
		records = records[:0]
		offset = 0
		for len(records) < dump.MaxRecords {
			limit := dump.BatchSize
			if remaining := dump.MaxRecords - len(records); remaining < limit {
				limit = remaining
			}
			outputFields := []string{"*"}
			payload := map[string]any{
				"dbName":         "default",
				"collectionName": collection.Name,
				"filter":         filter,
				"outputFields":   outputFields,
				"limit":          limit,
				"offset":         offset,
			}
			exchange, err := m.PostJSON(ctx, target, "/v2/vectordb/entities/query", payload, options)
			if err != nil {
				lastErr = err
				break
			}
			value, err := m.JSONMap(exchange)
			if err != nil {
				lastErr = err
				break
			}
			if code, _ := Integer(value["code"]); code != 0 {
				lastErr = fmt.Errorf("%s", utilities.FirstNonEmpty(FirstString(value, "message", "error"), "query failed"))
				break
			}
			rows := MapSlice(value["data"])
			for _, row := range rows {
				vector := VectorData{}
				if dump.IncludeVectors {
					for _, field := range vectorFields {
						if fieldValue, exists := row[field]; exists {
							vector = ParseVector(fieldValue, dump.MaxVectorValues)
							break
						}
					}
				}
				externalID := String(row[primaryField])
				if externalID == "" {
					externalID = fmt.Sprintf("offset-%d", offset+len(records))
				}
				records = append(records, m.Record(target, collection, externalID, FilterFields(row, vectorFields), vector, dump.MaxPayloadBytes))
			}
			if len(rows) < limit {
				break
			}
			offset += len(rows)
		}
		if lastErr == nil && len(records) > 0 {
			return records, nil
		}
		if lastErr == nil && filter == "" {
			return records, nil
		}
	}
	if lastErr != nil {
		return records, lastErr
	}
	return records, nil
}

func (m *Milvus) grpcExtract(ctx context.Context, target *model.Target, dump model.DumpOptions, extraction *model.Extraction) {
	address := engine.TargetAddress(*target)
	payload, err := m.Runtime.GRPC.InvokeDynamic(ctx, address, "milvus.proto.milvus.MilvusService", "ShowCollections", map[string]any{"db_name": "default"}, target.TLS)
	if err != nil {
		extraction.AddError("gRPC ShowCollections: " + err.Error())
		return
	}
	value := map[string]any{}
	if err := json.Unmarshal(payload, &value); err != nil {
		extraction.AddError("gRPC ShowCollections decode: " + err.Error())
		return
	}
	names := Strings(value["collection_names"])
	if dump.Collection != "" {
		names = filterNames(names, dump.Collection)
	}
	for _, name := range names {
		describePayload, describeErr := m.Runtime.GRPC.InvokeDynamic(ctx, address, "milvus.proto.milvus.MilvusService", "DescribeCollection", map[string]any{
			"db_name":         "default",
			"collection_name": name,
		}, target.TLS)
		if describeErr != nil {
			extraction.AddError(fmt.Sprintf("%s gRPC DescribeCollection: %s", name, describeErr))
			continue
		}
		describeValue := map[string]any{}
		if err := json.Unmarshal(describePayload, &describeValue); err != nil {
			extraction.AddError(fmt.Sprintf("%s gRPC DescribeCollection decode: %s", name, err))
			continue
		}
		collection, schema := milvusCollectionFromGRPC(target, name, describeValue)
		extraction.Collections = append(extraction.Collections, collection)
		if !dump.ExtractRecords {
			continue
		}
		records, queryErr := m.grpcQuery(ctx, address, target, collection, schema, dump)
		if queryErr != nil {
			extraction.AddError(fmt.Sprintf("%s gRPC Query: %s", name, queryErr))
			continue
		}
		extraction.Records = append(extraction.Records, records...)
		if len(extraction.Records) >= dump.MaxRecords {
			extraction.Stats.Limited = true
			break
		}
	}
}

type milvusSchema struct {
	primaryField string
	primaryType  string
	vectorFields []string
	fieldTypes   map[string]string
}

func milvusCollectionFromGRPC(target *model.Target, name string, value map[string]any) (*model.Collection, milvusSchema) {
	schemaValue := Map(value["schema"])
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorMilvus,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	if count, ok := Integer(value["num_rows"]); ok {
		collection.PointCount = count
	}
	fields := make([]model.Field, 0, 8)
	indexes := make([]model.Index, 0, 2)
	schema := milvusSchema{fieldTypes: map[string]string{}}
	for _, item := range MapSlice(schemaValue["fields"]) {
		fieldName := FirstString(item, "name")
		fieldType := milvusType(item["data_type"], item["dataType"])
		field := Field(fieldName, fieldType)
		field.Primary = Bool(item["is_primary_field"]) || Bool(item["isPrimary"])
		field.Params = milvusGRPCFieldParams(item)
		if dimension, ok := Integer(field.Params["dim"]); ok {
			field.Dimension = int(dimension)
			if dimension > int64(collection.Dimension) {
				collection.Dimension = int(dimension)
			}
		}
		if field.Primary {
			schema.primaryField = fieldName
			schema.primaryType = fieldType
		}
		schema.fieldTypes[fieldName] = fieldType
		if isMilvusVectorType(fieldType) {
			schema.vectorFields = append(schema.vectorFields, fieldName)
			indexes = append(indexes, model.Index{Name: fieldName, Type: "milvus", Field: fieldName, Dimension: field.Dimension})
		}
		fields = append(fields, field)
	}
	collection.SetFields(fields)
	collection.SetIndexes(indexes)
	collection.SetMetadata(map[string]any{"collection_id": value["collectionID"], "schema": schemaValue})
	return collection, schema
}

func (m *Milvus) grpcQuery(ctx context.Context, address string, target *model.Target, collection *model.Collection, schema milvusSchema, dump model.DumpOptions) ([]*model.Record, error) {
	if schema.primaryField == "" {
		return nil, fmt.Errorf("primary field is unknown")
	}
	filters := milvusFilters(schema.primaryField, schema.primaryType)
	outputFields := make([]any, 0, len(schema.fieldTypes))
	for name, fieldType := range schema.fieldTypes {
		if !dump.IncludeVectors && isMilvusVectorType(fieldType) {
			continue
		}
		outputFields = append(outputFields, name)
	}
	var lastErr error
	for _, filter := range filters {
		records := make([]*model.Record, 0, dump.BatchSize)
		offset := 0
		success := false
		for len(records) < dump.MaxRecords {
			limit := dump.BatchSize
			if remaining := dump.MaxRecords - len(records); remaining < limit {
				limit = remaining
			}
			payload, err := m.Runtime.GRPC.InvokeDynamic(ctx, address, "milvus.proto.milvus.MilvusService", "Query", map[string]any{
				"db_name":         "default",
				"collection_name": collection.Name,
				"expr":            filter,
				"output_fields":   outputFields,
				"limit":           limit,
				"offset":          offset,
			}, target.TLS)
			if err != nil {
				lastErr = err
				break
			}
			value := map[string]any{}
			if err := json.Unmarshal(payload, &value); err != nil {
				lastErr = err
				break
			}
			rows := milvusRows(value["fields_data"], schema)
			for index, row := range rows {
				vector := VectorData{}
				if dump.IncludeVectors {
					for _, field := range schema.vectorFields {
						if fieldValue, exists := row[field]; exists {
							vector = ParseVector(fieldValue, dump.MaxVectorValues)
							break
						}
					}
				}
				externalID := String(row[schema.primaryField])
				if externalID == "" {
					externalID = fmt.Sprintf("offset-%d", offset+index)
				}
				records = append(records, m.Record(target, collection, externalID, FilterFields(row, schema.vectorFields), vector, dump.MaxPayloadBytes))
			}
			success = true
			if len(rows) < limit {
				break
			}
			offset += len(rows)
		}
		if success {
			return records, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("query did not succeed")
}

func milvusRows(value any, schema milvusSchema) []map[string]any {
	columns := MapSlice(value)
	if len(columns) == 0 {
		return nil
	}
	rowCount := 0
	longData := map[string][]any{}
	stringData := map[string][]any{}
	boolData := map[string][]any{}
	doubleData := map[string][]any{}
	jsonData := map[string][]any{}
	vectorFlat := map[string][]float64{}
	vectorDims := map[string]int{}
	for _, column := range columns {
		fieldName := FirstString(column, "field_name", "fieldName")
		if fieldName == "" {
			continue
		}
		fieldType := schema.fieldTypes[fieldName]
		if isMilvusVectorType(fieldType) {
			vectors := Map(column["vectors"])
			floatVector := Map(vectors["float_vector"])
			floatValues := floatsOf(Slice(floatVector["data"]))
			if len(floatValues) == 0 {
				continue
			}
			dimension := 0
			if dim, ok := Integer(floatVector["dim"]); ok && dim > 0 {
				dimension = int(dim)
			}
			vectorFlat[fieldName] = floatValues
			vectorDims[fieldName] = dimension
			continue
		}
		scalars := Map(column["scalars"])
		if values := Slice(Map(scalars["long_data"])["data"]); len(values) > 0 {
			longData[fieldName] = values
			rowCount = maxInt(rowCount, len(values))
		}
		if values := Slice(Map(scalars["string_data"])["data"]); len(values) > 0 {
			stringData[fieldName] = values
			rowCount = maxInt(rowCount, len(values))
		}
		if values := Slice(Map(scalars["bool_data"])["data"]); len(values) > 0 {
			boolData[fieldName] = values
			rowCount = maxInt(rowCount, len(values))
		}
		if values := Slice(Map(scalars["double_data"])["data"]); len(values) > 0 {
			doubleData[fieldName] = values
			rowCount = maxInt(rowCount, len(values))
		}
		if values := Slice(Map(scalars["json_data"])["data"]); len(values) > 0 {
			jsonData[fieldName] = values
			rowCount = maxInt(rowCount, len(values))
		}
	}
	vectorData := map[string][][]float64{}
	for field, values := range vectorFlat {
		dimension := vectorDims[field]
		if dimension == 0 && rowCount > 0 {
			dimension = guessDimension(len(values), rowCount)
		}
		if dimension <= 0 {
			continue
		}
		split := splitVectors(values, dimension)
		if len(split) == 0 {
			continue
		}
		vectorData[field] = split
		if rowCount == 0 {
			rowCount = len(split)
		}
	}
	if rowCount == 0 {
		return nil
	}
	rows := make([]map[string]any, rowCount)
	for index := 0; index < rowCount; index++ {
		row := map[string]any{}
		fillRow(row, index, longData)
		fillRow(row, index, stringData)
		fillRow(row, index, boolData)
		fillRow(row, index, doubleData)
		fillRow(row, index, jsonData)
		for field, vectors := range vectorData {
			if index < len(vectors) {
				row[field] = vectors[index]
			}
		}
		rows[index] = row
	}
	return rows
}

func fillRow(row map[string]any, index int, columns map[string][]any) {
	for field, values := range columns {
		if index < len(values) {
			row[field] = values[index]
		}
	}
}

func decodeJSONBytes(value any) any {
	text := String(value)
	if text == "" {
		return value
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err == nil {
		return decoded
	}
	return value
}

func floatsOf(values []any) []float64 {
	result := make([]float64, 0, len(values))
	for _, value := range values {
		number, ok := Number(value)
		if !ok {
			return nil
		}
		result = append(result, number)
	}
	return result
}

func splitVectors(values []float64, dimension int) [][]float64 {
	if dimension <= 0 || len(values)%dimension != 0 {
		return nil
	}
	result := make([][]float64, 0, len(values)/dimension)
	for start := 0; start+dimension <= len(values); start += dimension {
		result = append(result, values[start:start+dimension])
	}
	return result
}

func guessDimension(total, rows int) int {
	if rows <= 0 || total%rows != 0 {
		return 0
	}
	return total / rows
}

func milvusFilters(primaryField, primaryType string) []string {
	result := make([]string, 0, 3)
	if primaryField != "" {
		lower := strings.ToLower(primaryType)
		switch {
		case strings.Contains(lower, "int"):
			result = append(result, primaryField+" >= 0")
			result = append(result, primaryField+" != 0")
		case strings.Contains(lower, "var") || strings.Contains(lower, "string"):
			result = append(result, primaryField+` != ""`)
		}
	}
	result = append(result, "")
	return result
}

func milvusType(values ...any) string {
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case float64:
			return milvusTypeName(int64(typed))
		case int64:
			return milvusTypeName(typed)
		case json.Number:
			number, _ := typed.Int64()
			return milvusTypeName(number)
		}
	}
	return ""
}

func milvusTypeName(value int64) string {
	switch value {
	case 1:
		return "Bool"
	case 2:
		return "Int8"
	case 3:
		return "Int16"
	case 4:
		return "Int32"
	case 5:
		return "Int64"
	case 10:
		return "Float"
	case 11:
		return "Double"
	case 20:
		return "String"
	case 21:
		return "VarChar"
	case 22:
		return "Array"
	case 23:
		return "JSON"
	case 100:
		return "BinaryVector"
	case 101:
		return "FloatVector"
	case 102:
		return "Float16Vector"
	case 103:
		return "BFloat16Vector"
	case 104:
		return "SparseFloatVector"
	case 105:
		return "Int8Vector"
	default:
		return fmt.Sprintf("Type%d", value)
	}
}

func isMilvusVectorType(value string) bool {
	return strings.Contains(strings.ToLower(value), "vector")
}

func milvusFieldParams(field map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range Map(field["params"]) {
		result[key] = value
	}
	if len(result) == 0 {
		result = milvusGRPCFieldParams(field)
	}
	return result
}

func milvusGRPCFieldParams(field map[string]any) map[string]any {
	result := map[string]any{}
	for _, item := range MapSlice(field["type_params"]) {
		key := FirstString(item, "key")
		if key == "" {
			continue
		}
		result[key] = item["value"]
	}
	if _, exists := result["dim"]; !exists {
		if dim, ok := Integer(field["dim"]); ok {
			result["dim"] = dim
		}
	}
	return result
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

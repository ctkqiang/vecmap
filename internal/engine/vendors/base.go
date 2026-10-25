package vendors

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"vecmap/internal/engine"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// Base 提供厂商适配器共用的端口、探测、认证与 JSON 辅助能力。
//
// 每个厂商适配器通过嵌入 Base 复用基础行为，并覆盖指纹与枚举逻辑。
type Base struct {
	VendorID model.Vendor
	Ports    []int
	Runtime  *engine.Runtime
}

// Vendor 返回适配器厂商标识。
//
// 返回嵌入的 VendorID。
func (b *Base) Vendor() model.Vendor {
	return b.VendorID
}

// DefaultPorts 返回厂商常见端口。
//
// 返回端口切片副本；调用方可安全修改。
func (b *Base) DefaultPorts() []int {
	result := make([]int, len(b.Ports))
	copy(result, b.Ports)
	return result
}

// Probe 执行厂商只读探测目录。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置。
// 返回探测结果；目录执行失败时返回错误。
func (b *Base) Probe(ctx context.Context, target *model.Target, options model.ScanOptions) ([]*model.ProbeResult, error) {
	if b.Runtime == nil {
		return nil, fmt.Errorf("vendor runtime is not initialized")
	}
	fuzzer := engine.NewFuzzer(b.Runtime)
	return fuzzer.Run(ctx, target, b.VendorID, options, engine.ProbeCatalog(b.VendorID))
}

// Auth 返回当前厂商的认证请求头。
//
// 参数 options 为扫描配置；返回可合并到 HTTP 请求的头映射。
func (b *Base) Auth(options model.ScanOptions) map[string]string {
	return engine.AuthHeaders(b.VendorID, options.Credentials)
}

// Get 发起带厂商认证的 GET 请求。
//
// 参数 ctx 控制请求超时，target 为目标，path 为相对路径。
// 返回 HTTP 证据与网络错误。
func (b *Base) Get(ctx context.Context, target *model.Target, path string, options model.ScanOptions) (*model.HTTPExchange, error) {
	return b.GetWithHeaders(ctx, target, path, options, nil)
}

// GetWithHeaders 发起带附加请求头的 GET 请求。
//
// 参数 headers 为额外头；返回 HTTP 证据与网络错误。
func (b *Base) GetWithHeaders(ctx context.Context, target *model.Target, path string, options model.ScanOptions, headers map[string]string) (*model.HTTPExchange, error) {
	if b.Runtime == nil || b.Runtime.HTTP == nil {
		return nil, fmt.Errorf("http runtime is not initialized")
	}
	return b.Runtime.HTTP.Get(ctx, engine.TargetURL(*target, path), engine.MergeHeaders(b.Auth(options), headers))
}

// PostJSON 发起带厂商认证的 JSON POST 请求。
//
// 参数 payload 为待序列化对象；返回 HTTP 证据与错误。
// 仅可调用服务端的只读列表、描述、查询与搜索接口。
func (b *Base) PostJSON(ctx context.Context, target *model.Target, path string, payload any, options model.ScanOptions) (*model.HTTPExchange, error) {
	if b.Runtime == nil || b.Runtime.HTTP == nil {
		return nil, fmt.Errorf("http runtime is not initialized")
	}
	return b.Runtime.HTTP.PostJSON(ctx, engine.TargetURL(*target, path), payload, b.Auth(options))
}

// JSONMap 解析对象响应。
//
// 参数 exchange 为 HTTP 证据；返回对象映射与解析或状态错误。
func (b *Base) JSONMap(exchange *model.HTTPExchange) (map[string]any, error) {
	if err := engine.EnsureJSON(exchange); err != nil {
		return nil, err
	}
	return engine.DecodeJSONMap(exchange)
}

// JSONArray 解析数组响应。
//
// 参数 exchange 为 HTTP 证据；返回数组与解析或状态错误。
func (b *Base) JSONArray(exchange *model.HTTPExchange) ([]any, error) {
	if err := engine.EnsureJSON(exchange); err != nil {
		return nil, err
	}
	return engine.DecodeJSONArray(exchange)
}

// Collection 创建集合快照骨架。
//
// 参数 target 为目标，name 为集合名；返回带本地 ID 与时间戳的集合。
func (b *Base) Collection(target *model.Target, name string) *model.Collection {
	return &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    b.VendorID,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
}

// Record 创建提取记录。
//
// 参数 target 为目标，collection 为所属集合，externalID 为服务端记录 ID，
// payload 为业务字段，vector 为解析后的向量样本。
// 返回可持久化记录。
func (b *Base) Record(target *model.Target, collection *model.Collection, externalID string, payload map[string]any, vector VectorData, maxPayload int) *model.Record {
	record := &model.Record{
		ID:             utilities.NewID("rec"),
		TargetID:       target.ID,
		CollectionID:   collection.ID,
		CollectionName: collection.Name,
		Namespace:      collection.Namespace,
		ExternalID:     externalID,
		PayloadJSON:    MarshalPayload(payload, maxPayload),
		VectorJSON:     vector.JSON,
		VectorDim:      vector.Dimension,
		CreatedAt:      time.Now().UTC(),
	}
	return record
}

// VectorData 表示归一化后的向量样本。
type VectorData struct {
	Dimension int
	Values    []float64
	Named     map[string][]float64
	JSON      string
}

// Empty 判断向量样本是否为空。
//
// 返回 true 表示没有可持久化的向量值。
func (v VectorData) Empty() bool {
	return v.JSON == "" || (len(v.Values) == 0 && len(v.Named) == 0)
}

// ParseVector 将常见向量表示解析为归一化样本。
//
// 参数 value 可为数字数组、命名向量映射、JSON 文本或 Vespa 张量文本，
// maxValues 限制单条向量保存的分量数。
// 返回向量维度、采样值和可持久化 JSON；无法识别时返回空样本。
func ParseVector(value any, maxValues int) VectorData {
	if maxValues <= 0 {
		maxValues = 256
	}
	switch typed := value.(type) {
	case []any:
		values, ok := floatsFromArray(typed, maxValues)
		if !ok {
			return VectorData{}
		}
		return buildVector(values)
	case []float64:
		return buildVector(trimFloats(typed, maxValues))
	case map[string]any:
		named := map[string][]float64{}
		dimension := 0
		for name, item := range typed {
			values, ok := floatsFromAny(item, maxValues)
			if !ok || len(values) == 0 {
				continue
			}
			named[name] = values
			if dimension == 0 {
				dimension = len(values)
			}
		}
		if len(named) == 0 {
			return VectorData{}
		}
		sample := model.VectorSample{Dimension: dimension, Named: named}
		payload, err := json.Marshal(sample)
		if err != nil {
			return VectorData{}
		}
		return VectorData{Dimension: dimension, Named: named, JSON: string(payload)}
	case string:
		values := parseVectorString(typed, maxValues)
		if len(values) == 0 {
			return VectorData{}
		}
		return buildVector(values)
	default:
		return VectorData{}
	}
}

func buildVector(values []float64) VectorData {
	if len(values) == 0 {
		return VectorData{}
	}
	sample := model.VectorSample{Dimension: len(values), Values: values}
	payload, err := json.Marshal(sample)
	if err != nil {
		return VectorData{}
	}
	return VectorData{Dimension: len(values), Values: values, JSON: string(payload)}
}

func floatsFromAny(value any, maxValues int) ([]float64, bool) {
	switch typed := value.(type) {
	case []any:
		return floatsFromArray(typed, maxValues)
	case []float64:
		return trimFloats(typed, maxValues), true
	case string:
		values := parseVectorString(typed, maxValues)
		return values, len(values) > 0
	default:
		return nil, false
	}
}

func floatsFromArray(values []any, maxValues int) ([]float64, bool) {
	result := make([]float64, 0, len(values))
	for _, item := range values {
		number, ok := toFloat(item)
		if !ok {
			return nil, false
		}
		if len(result) < maxValues {
			result = append(result, number)
		}
	}
	if len(result) == 0 {
		return nil, false
	}
	return result, true
}

func trimFloats(values []float64, maxValues int) []float64 {
	if len(values) > maxValues {
		return append([]float64(nil), values[:maxValues]...)
	}
	return append([]float64(nil), values...)
}

func parseVectorString(value string, maxValues int) []float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	start := strings.LastIndex(value, "[")
	end := strings.LastIndex(value, "]")
	if start >= 0 && end > start {
		value = value[start+1 : end]
	}
	value = strings.NewReplacer(";", ",", " ", ",").Replace(value)
	parts := strings.Split(value, ",")
	result := make([]float64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		number, err := strconv.ParseFloat(part, 64)
		if err != nil {
			continue
		}
		if len(result) < maxValues {
			result = append(result, number)
		}
	}
	return result
}

// String 读取映射中的字符串字段。
//
// 参数 value 为通用值；返回字符串表示，缺失时返回空字符串。
func String(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		if typed == math.Trunc(typed) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// FirstString 返回映射中首个非空字符串字段。
//
// 参数 values 为对象映射，keys 为候选字段顺序；返回首个非空值。
func FirstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if result := String(values[key]); result != "" {
			return result
		}
	}
	return ""
}

// Number 读取映射中的数值字段。
//
// 参数 value 为通用值；返回 float64，无法转换时返回 0 与 false。
func Number(value any) (float64, bool) {
	return toFloat(value)
}

// Integer 读取映射中的整数字段。
//
// 参数 value 为通用值；返回 int64，无法转换时返回 0 与 false。
func Integer(value any) (int64, bool) {
	number, ok := toFloat(value)
	if !ok {
		return 0, false
	}
	return int64(number), true
}

// Bool 读取映射中的布尔字段。
//
// 参数 value 为通用值；返回布尔值，无法转换时返回 false。
func Bool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, _ := strconv.ParseBool(typed)
		return parsed
	case float64:
		return typed != 0
	case int64:
		return typed != 0
	default:
		return false
	}
}

// Slice 读取映射中的数组字段。
//
// 参数 value 为通用值；返回 []any，类型不符时返回 nil。
func Slice(value any) []any {
	result, _ := value.([]any)
	return result
}

// Map 读取映射中的对象字段。
//
// 参数 value 为通用值；返回 map[string]any，类型不符时返回空映射。
func Map(value any) map[string]any {
	result, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return result
}

// MapSlice 将数组字段转换为对象切片。
//
// 参数 value 为通用数组；返回仅包含对象项的切片。
func MapSlice(value any) []map[string]any {
	items := Slice(value)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			result = append(result, entry)
		}
	}
	return result
}

// Strings 将数组字段转换为字符串切片。
//
// 参数 value 为通用数组；返回非空字符串项。
func Strings(value any) []string {
	items := Slice(value)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text := String(item); text != "" {
			result = append(result, text)
		}
	}
	return result
}

// MarshalPayload 将业务字段序列化为受容量限制的 JSON。
//
// 参数 payload 为原始字段，maxBytes 为最大字节数。
// 返回合法 JSON 文本；超限时会截断长字符串并在 JSON 中标记 truncated。
func MarshalPayload(payload map[string]any, maxBytes int) string {
	if len(payload) == 0 {
		return "{}"
	}
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}
	trimmed := trimPayload(payload, maxBytes)
	trimmed["_truncated"] = payloadExceeds(payload, maxBytes)
	encoded, err := json.Marshal(trimmed)
	if err != nil {
		return "{}"
	}
	if len(encoded) <= maxBytes {
		return string(encoded)
	}
	preview := utilities.Truncate(string(encoded), maxBytes/2)
	fallback, err := json.Marshal(map[string]any{"_truncated": true, "preview": preview})
	if err != nil {
		return "{}"
	}
	return string(fallback)
}

func trimPayload(payload map[string]any, maxBytes int) map[string]any {
	result := make(map[string]any, len(payload))
	for key, value := range payload {
		switch typed := value.(type) {
		case string:
			if len(typed) > 4096 {
				result[key] = utilities.Truncate(typed, 2048)
				continue
			}
			result[key] = typed
		case []any:
			if len(typed) > 64 {
				result[key] = typed[:64]
				continue
			}
			result[key] = typed
		default:
			result[key] = value
		}
	}
	if payloadExceeds(result, maxBytes) {
		return map[string]any{"_truncated": true, "keys": utilities.SortedKeys(result)}
	}
	return result
}

func payloadExceeds(payload map[string]any, maxBytes int) bool {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return true
	}
	return len(encoded) > maxBytes
}

// FilterFields 从对象中移除指定字段。
//
// 参数 payload 为原始对象，fields 为需要移除的字段名。
// 返回不包含指定字段的新映射。
func FilterFields(payload map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return payload
	}
	excluded := map[string]struct{}{}
	for _, field := range fields {
		excluded[strings.ToLower(strings.TrimSpace(field))] = struct{}{}
	}
	result := make(map[string]any, len(payload))
	for key, value := range payload {
		if _, skip := excluded[strings.ToLower(key)]; skip {
			continue
		}
		result[key] = value
	}
	return result
}

// Field 创建字段定义。
//
// 参数 name、dataType 为字段名与类型；返回字段模型。
func Field(name, dataType string) model.Field {
	return model.Field{Name: name, Type: dataType, DataType: dataType}
}

// Index 创建索引定义。
//
// 参数 name、indexType 为索引名与类型；返回索引模型。
func Index(name, indexType string) model.Index {
	return model.Index{Name: name, Type: indexType}
}

func toFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return 0, false
		}
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	case string:
		number, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return number, err == nil
	default:
		return 0, false
	}
}

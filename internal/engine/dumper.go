package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"vecmap/internal/constant"
	"vecmap/internal/model"
)

// DumpOptions 控制 Schema 枚举的取样规模。
// 所有请求都是只读的，取样上限也由这里兜底，避免对生产库造成压力。
type DumpOptions struct {
	SampleLimit int  // 每个集合最多读取的记录数
	Sweep       bool // 是否执行 k-NN 检索验证
}

// DefaultDumpOptions 返回保守的默认值。
func DefaultDumpOptions() DumpOptions {
	return DumpOptions{SampleLimit: 5, Sweep: true}
}

// normalized 修正越界参数，SampleLimit 上限固定为 100。
func (o DumpOptions) normalized() DumpOptions {
	if o.SampleLimit <= 0 {
		o.SampleLimit = DefaultDumpOptions().SampleLimit
	}
	if o.SampleLimit > 100 {
		o.SampleLimit = 100
	}
	return o
}

// Dumper 在指纹识别之后枚举集合、字段与维度，并做非破坏性取样。
type Dumper struct {
	*httpProber
}

// NewDumper 创建枚举器。
func NewDumper(opts Options) *Dumper {
	return &Dumper{httpProber: newHTTPProber(opts.normalized())}
}

// Dump 按厂商分派枚举逻辑。单个集合失败只记录错误，不中断整体流程。
func (d *Dumper) Dump(ctx context.Context, fp model.Fingerprint, opts DumpOptions) model.DumpResult {
	opts = opts.normalized()
	result := model.DumpResult{
		Endpoint: fp.Endpoint,
		Vendor:   fp.Vendor,
	}

	switch constant.Vendor(NormalizeVendor(fp.Vendor)) {
	case constant.VendorWeaviate:
		d.dumpWeaviate(ctx, fp, opts, &result)
	case constant.VendorQdrant:
		d.dumpQdrant(ctx, fp, opts, &result)
	case constant.VendorChroma:
		d.dumpChroma(ctx, fp, opts, &result)
	case constant.VendorMilvus:
		d.dumpMilvus(ctx, fp, opts, &result)
	default:
		result.Errors = append(result.Errors,
			fmt.Sprintf("vendor %q is not supported by the dumper", fp.Vendor))
	}
	result.Evidence = summarizeDump(&result)
	return result
}

// dumpEndpoint 按指纹阶段确认的协议构造端点，避免每个请求都重新试探 TLS。
func dumpEndpoint(fp model.Fingerprint) model.Endpoint {
	ep := fp.Endpoint
	if strings.EqualFold(fp.Scheme, "https") {
		ep.Protocol = "HTTPS"
	}
	return ep
}

// dumpWeaviate 读取 /v1/schema，按 class 取样对象并用 GraphQL 聚合取总数。
func (d *Dumper) dumpWeaviate(ctx context.Context, fp model.Fingerprint, opts DumpOptions, result *model.DumpResult) {
	ep := dumpEndpoint(fp)

	res, _, err := d.fetch(ctx, ep, http.MethodGet, "/v1/schema", nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("GET /v1/schema: %v", err))
		return
	}
	if res.Status != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("GET /v1/schema -> HTTP %d", res.Status))
		return
	}

	var schema struct {
		Classes []struct {
			Class             string `json:"class"`
			Vectorizer        string `json:"vectorizer"`
			VectorIndexConfig struct {
				Distance string `json:"distance"`
			} `json:"vectorIndexConfig"`
			Properties []struct {
				Name     string   `json:"name"`
				DataType []string `json:"dataType"`
			} `json:"properties"`
		} `json:"classes"`
	}
	if err := json.Unmarshal(res.Body, &schema); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("decode /v1/schema: %v", err))
		return
	}
	result.Anonymous = true

	for _, class := range schema.Classes {
		collection := model.Collection{
			ID:     class.Class,
			Name:   class.Class,
			Metric: strings.ToLower(class.VectorIndexConfig.Distance),
		}
		for _, property := range class.Properties {
			collection.Fields = append(collection.Fields, model.Field{
				Name: property.Name,
				Type: strings.Join(property.DataType, "|"),
			})
		}

		collection.Points = d.weaviateCount(ctx, ep, class.Class)
		path := "/v1/objects?limit=" + strconv.Itoa(opts.SampleLimit) +
			"&class=" + url.QueryEscape(class.Class) + "&include=vector"

		objects, _, err := d.fetch(ctx, ep, http.MethodGet, path, nil)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("GET %s: %v", path, err))
			result.Collections = append(result.Collections, collection)
			continue
		}
		if objects.Status != http.StatusOK {
			result.Errors = append(result.Errors, fmt.Sprintf("GET %s -> HTTP %d", path, objects.Status))
			result.Collections = append(result.Collections, collection)
			continue
		}

		var payload struct {
			Objects []struct {
				Vector     []float64                  `json:"vector"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"objects"`
		}
		if err := json.Unmarshal(objects.Body, &payload); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("decode %s: %v", path, err))
			result.Collections = append(result.Collections, collection)
			continue
		}

		result.Samples += len(payload.Objects)
		for _, object := range payload.Objects {
			if collection.Dimension == 0 && len(object.Vector) > 0 {
				collection.Dimension = len(object.Vector)
			}
		}
		result.Collections = append(result.Collections, collection)
	}
}

// weaviateCount 用聚合查询取 class 的对象总数，失败时返回 0（未知）。
// 查询中只允许字母、数字与下划线，防止把 schema 中的类名直接拼进 GraphQL。
func (d *Dumper) weaviateCount(ctx context.Context, ep model.Endpoint, class string) int64 {
	if !safeGraphQLName(class) {
		return 0
	}

	query, err := json.Marshal(map[string]string{
		"query": fmt.Sprintf("{ Aggregate { %s { meta { count } } } }", class),
	})
	if err != nil {
		return 0
	}

	res, _, err := d.fetch(ctx, ep, http.MethodPost, "/v1/graphql", query)
	if err != nil || res.Status != http.StatusOK {
		return 0
	}

	var out struct {
		Data struct {
			Aggregate map[string][]struct {
				Meta struct {
					Count int64 `json:"count"`
				} `json:"meta"`
			} `json:"Aggregate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return 0
	}
	for _, entries := range out.Data.Aggregate {
		if len(entries) > 0 {
			return entries[0].Meta.Count
		}
	}
	return 0
}

// safeGraphQLName 校验标识符是否只包含 GraphQL 名称允许的字符。
func safeGraphQLName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// dumpQdrant 读取集合列表与配置，再用 scroll 取样、search 验证 k-NN。
func (d *Dumper) dumpQdrant(ctx context.Context, fp model.Fingerprint, opts DumpOptions, result *model.DumpResult) {
	ep := dumpEndpoint(fp)

	res, _, err := d.fetch(ctx, ep, http.MethodGet, "/collections", nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("GET /collections: %v", err))
		return
	}
	if res.Status != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("GET /collections -> HTTP %d", res.Status))
		return
	}

	var list struct {
		Result struct {
			Collections []struct {
				Name string `json:"name"`
			} `json:"collections"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res.Body, &list); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("decode /collections: %v", err))
		return
	}
	result.Anonymous = true

	for _, item := range list.Result.Collections {
		collection := model.Collection{ID: item.Name, Name: item.Name}
		basePath := "/collections/" + url.PathEscape(item.Name)

		info, _, err := d.fetch(ctx, ep, http.MethodGet, basePath, nil)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("GET %s: %v", basePath, err))
			result.Collections = append(result.Collections, collection)
			continue
		}
		if info.Status != http.StatusOK {
			result.Errors = append(result.Errors, fmt.Sprintf("GET %s -> HTTP %d", basePath, info.Status))
			result.Collections = append(result.Collections, collection)
			continue
		}

		var detail struct {
			Result struct {
				PointsCount int64 `json:"points_count"`
				Config      struct {
					Params struct {
						Vectors json.RawMessage `json:"vectors"`
					} `json:"params"`
				} `json:"config"`
			} `json:"result"`
		}
		if err := json.Unmarshal(info.Body, &detail); err == nil {
			collection.Points = detail.Result.PointsCount
			collection.Dimension, collection.Metric = parseQdrantVectors(detail.Result.Config.Params.Vectors)
		}

		if err := d.sampleQdrant(ctx, ep, basePath, opts, &collection, result); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
		result.Collections = append(result.Collections, collection)
	}
}

// sampleQdrant 用 scroll 读取少量记录，并在维度已知时执行一次 k-NN 检索。
func (d *Dumper) sampleQdrant(ctx context.Context, ep model.Endpoint, basePath string, opts DumpOptions, collection *model.Collection, result *model.DumpResult) error {
	body, err := json.Marshal(map[string]any{
		"limit":        opts.SampleLimit,
		"with_payload": true,
		"with_vector":  false,
	})
	if err != nil {
		return fmt.Errorf("encode scroll request: %w", err)
	}

	path := basePath + "/points/scroll"
	res, _, err := d.fetch(ctx, ep, http.MethodPost, path, body)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	if res.Status != http.StatusOK {
		return fmt.Errorf("POST %s -> HTTP %d", path, res.Status)
	}

	var scroll struct {
		Result struct {
			Points []struct {
				Payload map[string]any `json:"payload"`
			} `json:"points"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res.Body, &scroll); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}

	result.Samples += len(scroll.Result.Points)
	keys := make([]string, 0, 8)
	for _, point := range scroll.Result.Points {
		for key := range point.Payload {
			keys = append(keys, key)
		}
	}
	collection.Fields = mergeFields(collection.Fields, keys)

	if !opts.Sweep || collection.Dimension <= 0 {
		return nil
	}
	return d.searchQdrant(ctx, ep, basePath, collection, result)
}

// searchQdrant 用零向量做一次只读 k-NN 检索；零向量不包含任何用户数据。
func (d *Dumper) searchQdrant(ctx context.Context, ep model.Endpoint, basePath string, collection *model.Collection, result *model.DumpResult) error {
	vector := make([]float64, collection.Dimension)
	body, err := json.Marshal(map[string]any{
		"vector":       vector,
		"limit":        1,
		"with_payload": true,
	})
	if err != nil {
		return fmt.Errorf("encode search request: %w", err)
	}

	path := basePath + "/points/search"
	res, _, err := d.fetch(ctx, ep, http.MethodPost, path, body)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}

	if res.Status == http.StatusNotFound {
		// 新版本改用 /points/query，请求体字段名也从 vector 变为 query。
		body, err = json.Marshal(map[string]any{
			"query":        vector,
			"limit":        1,
			"with_payload": true,
		})
		if err != nil {
			return fmt.Errorf("encode query request: %w", err)
		}
		path = basePath + "/points/query"
		res, _, err = d.fetch(ctx, ep, http.MethodPost, path, body)
		if err != nil {
			return fmt.Errorf("POST %s: %w", path, err)
		}
	}
	if res.Status != http.StatusOK {
		return fmt.Errorf("POST %s -> HTTP %d", path, res.Status)
	}

	result.Searched = true
	var hits struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(res.Body, &hits); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}

	var list []json.RawMessage
	if err := json.Unmarshal(hits.Result, &list); err == nil {
		result.KnnHits += len(list)
		return nil
	}

	var wrapped struct {
		Points []json.RawMessage `json:"points"`
	}
	if err := json.Unmarshal(hits.Result, &wrapped); err == nil {
		result.KnnHits += len(wrapped.Points)
	}
	return nil
}

// parseQdrantVectors 兼容单向量与命名向量两种配置结构。
func parseQdrantVectors(raw json.RawMessage) (dimension int, metric string) {
	if len(raw) == 0 {
		return 0, ""
	}

	var single struct {
		Size     int    `json:"size"`
		Distance string `json:"distance"`
	}
	if err := json.Unmarshal(raw, &single); err == nil && single.Size > 0 {
		return single.Size, strings.ToLower(single.Distance)
	}

	var named map[string]struct {
		Size     int    `json:"size"`
		Distance string `json:"distance"`
	}
	if err := json.Unmarshal(raw, &named); err != nil {
		return 0, ""
	}
	names := make([]string, 0, len(named))
	for name := range named {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if vector := named[name]; vector.Size > 0 {
			return vector.Size, strings.ToLower(vector.Distance)
		}
	}
	return 0, ""
}

// dumpChroma 读取集合列表，按集合 UUID 取数量与样本。
// Chroma 不暴露向量维度，因此 Dimension 保持 0。
func (d *Dumper) dumpChroma(ctx context.Context, fp model.Fingerprint, opts DumpOptions, result *model.DumpResult) {
	ep := dumpEndpoint(fp)
	base := fp.APIBase
	if base == "" {
		base = "/api/v1"
	}

	listPath := chromaCollectionsPath(base)
	res, _, err := d.fetch(ctx, ep, http.MethodGet, listPath, nil)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("GET %s: %v", listPath, err))
		return
	}
	if res.Status != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("GET %s -> HTTP %d", listPath, res.Status))
		return
	}

	var items []struct {
		ID       string         `json:"id"`
		Name     string         `json:"name"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(res.Body, &items); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("decode %s: %v", listPath, err))
		return
	}
	result.Anonymous = true

	for _, item := range items {
		id := item.ID
		if id == "" {
			id = item.Name
		}
		collection := model.Collection{ID: id, Name: item.Name}
		collectionPath := base + "/collections/" + url.PathEscape(id)

		countRes, _, err := d.fetch(ctx, ep, http.MethodGet, collectionPath+"/count", nil)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("GET %s/count: %v", collectionPath, err))
		} else if countRes.Status == http.StatusOK {
			if count, err := strconv.ParseInt(strings.TrimSpace(string(countRes.Body)), 10, 64); err == nil {
				collection.Points = count
			}
		}

		body, err := json.Marshal(map[string]any{
			"limit":   opts.SampleLimit,
			"include": []string{"documents", "metadatas"},
		})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("encode %s/get: %v", collectionPath, err))
			result.Collections = append(result.Collections, collection)
			continue
		}

		getRes, _, err := d.fetch(ctx, ep, http.MethodPost, collectionPath+"/get", body)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("POST %s/get: %v", collectionPath, err))
			result.Collections = append(result.Collections, collection)
			continue
		}
		if getRes.Status != http.StatusOK {
			result.Errors = append(result.Errors, fmt.Sprintf("POST %s/get -> HTTP %d", collectionPath, getRes.Status))
			result.Collections = append(result.Collections, collection)
			continue
		}

		var sample struct {
			IDs       []string         `json:"ids"`
			Metadatas []map[string]any `json:"metadatas"`
		}
		if err := json.Unmarshal(getRes.Body, &sample); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("decode %s/get: %v", collectionPath, err))
			result.Collections = append(result.Collections, collection)
			continue
		}

		result.Samples += len(sample.IDs)
		keys := make([]string, 0, 8)
		for _, metadata := range sample.Metadatas {
			for key := range metadata {
				keys = append(keys, key)
			}
		}
		collection.Fields = mergeFields(collection.Fields, keys)
		result.Collections = append(result.Collections, collection)
	}
}

// dumpMilvus 通过 REST v2 枚举集合、字段与索引，并按主键查询取样。
func (d *Dumper) dumpMilvus(ctx context.Context, fp model.Fingerprint, opts DumpOptions, result *model.DumpResult) {
	ep := dumpEndpoint(fp)

	res, _, err := d.fetch(ctx, ep, http.MethodPost, "/v2/vectordb/collections/list", []byte("{}"))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("POST /v2/vectordb/collections/list: %v", err))
		return
	}
	if res.Status != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("POST /v2/vectordb/collections/list -> HTTP %d", res.Status))
		return
	}

	var list struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &list); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("decode collections/list: %v", err))
		return
	}
	if list.Code != 0 {
		result.Errors = append(result.Errors, fmt.Sprintf("collections/list returned code %d: %s", list.Code, list.Message))
		return
	}
	result.Anonymous = true

	for _, name := range parseMilvusNames(list.Data) {
		collection := model.Collection{ID: name, Name: name}
		vectorField := d.describeMilvus(ctx, ep, name, &collection, result)
		d.sampleMilvus(ctx, ep, name, vectorField, opts, &collection, result)
		result.Collections = append(result.Collections, collection)
	}
}

// parseMilvusNames 兼容 ["c1"] 与 {"collectionNames":["c1"]} 两种返回结构。
func parseMilvusNames(raw json.RawMessage) []string {
	var names []string
	if err := json.Unmarshal(raw, &names); err == nil {
		return names
	}

	var wrapped struct {
		CollectionNames []string `json:"collectionNames"`
		Collections     []string `json:"collections"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil
	}
	if len(wrapped.CollectionNames) > 0 {
		return wrapped.CollectionNames
	}
	return wrapped.Collections
}

// describeMilvus 读取集合结构，填充字段、维度与度量，返回向量字段名。
func (d *Dumper) describeMilvus(ctx context.Context, ep model.Endpoint, name string, collection *model.Collection, result *model.DumpResult) string {
	body, err := json.Marshal(map[string]any{"collectionName": name})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("encode describe %s: %v", name, err))
		return ""
	}

	res, _, err := d.fetch(ctx, ep, http.MethodPost, "/v2/vectordb/collections/describe", body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("POST describe %s: %v", name, err))
		return ""
	}
	if res.Status != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("POST describe %s -> HTTP %d", name, res.Status))
		return ""
	}

	var detail struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Fields []struct {
				Name   string `json:"name"`
				Type   string `json:"type"`
				Params []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"params"`
			} `json:"fields"`
			Indexes []struct {
				FieldName  string `json:"fieldName"`
				MetricType string `json:"metricType"`
			} `json:"indexes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &detail); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("decode describe %s: %v", name, err))
		return ""
	}
	if detail.Code != 0 {
		result.Errors = append(result.Errors, fmt.Sprintf("describe %s returned code %d: %s", name, detail.Code, detail.Message))
		return ""
	}

	vectorField := ""
	for _, field := range detail.Data.Fields {
		fieldType := strings.ToLower(field.Type)
		collection.Fields = append(collection.Fields, model.Field{Name: field.Name, Type: field.Type})
		if !strings.Contains(fieldType, "vector") {
			continue
		}
		if vectorField == "" {
			vectorField = field.Name
		}
		for _, param := range field.Params {
			if param.Key != "dim" {
				continue
			}
			if dim, err := strconv.Atoi(param.Value); err == nil && dim > 0 {
				collection.Dimension = dim
			}
		}
	}

	for _, index := range detail.Data.Indexes {
		if index.FieldName == vectorField && index.MetricType != "" {
			collection.Metric = strings.ToLower(index.MetricType)
			break
		}
	}
	return vectorField
}

// sampleMilvus 用空过滤条件查询少量记录；部分版本要求非空过滤，
// 因此失败后用 id >= 0 再试一次。
func (d *Dumper) sampleMilvus(ctx context.Context, ep model.Endpoint, name, vectorField string, opts DumpOptions, collection *model.Collection, result *model.DumpResult) {
	queries := []map[string]any{
		{"collectionName": name, "filter": "", "limit": opts.SampleLimit, "outputFields": []string{"*"}},
		{"collectionName": name, "filter": "id >= 0", "limit": opts.SampleLimit, "outputFields": []string{"*"}},
	}

	var rows []map[string]any
	for _, query := range queries {
		body, err := json.Marshal(query)
		if err != nil {
			continue
		}
		res, _, err := d.fetch(ctx, ep, http.MethodPost, "/v2/vectordb/entities/query", body)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("POST query %s: %v", name, err))
			break
		}
		if res.Status != http.StatusOK {
			continue
		}
		var out struct {
			Code    int              `json:"code"`
			Message string           `json:"message"`
			Data    []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(res.Body, &out); err != nil || out.Code != 0 {
			continue
		}
		rows = out.Data
		break
	}

	result.Samples += len(rows)
	keys := make([]string, 0, 8)
	for _, row := range rows {
		for key := range row {
			keys = append(keys, key)
		}
	}
	collection.Fields = mergeFields(collection.Fields, keys)

	if !opts.Sweep || collection.Dimension <= 0 || vectorField == "" {
		return
	}
	d.searchMilvus(ctx, ep, name, vectorField, collection, result)
}

// searchMilvus 用零向量执行一次只读检索，确认索引是否可被匿名查询。
func (d *Dumper) searchMilvus(ctx context.Context, ep model.Endpoint, name, vectorField string, collection *model.Collection, result *model.DumpResult) {
	vector := make([]float64, collection.Dimension)
	body, err := json.Marshal(map[string]any{
		"collectionName": name,
		"data":           [][]float64{vector},
		"annsField":      vectorField,
		"limit":          1,
		"outputFields":   []string{"*"},
	})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("encode search %s: %v", name, err))
		return
	}

	res, _, err := d.fetch(ctx, ep, http.MethodPost, "/v2/vectordb/entities/search", body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("POST search %s: %v", name, err))
		return
	}
	if res.Status != http.StatusOK {
		return
	}

	var out struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil || out.Code != 0 {
		return
	}
	result.Searched = true
	result.KnnHits += len(out.Data)
}

// mergeFields 把取样得到的 payload 键并入字段列表，保持名称唯一且有序。
func mergeFields(fields []model.Field, keys []string) []model.Field {
	if len(keys) == 0 {
		return fields
	}

	seen := make(map[string]struct{}, len(fields)+len(keys))
	for _, field := range fields {
		seen[field.Name] = struct{}{}
	}

	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		fields = append(fields, model.Field{Name: key, Type: "payload"})
	}
	return fields
}

// summarizeDump 生成报告与日志共用的单行摘要。
func summarizeDump(result *model.DumpResult) string {
	parts := []string{fmt.Sprintf("%d collection(s)", len(result.Collections))}
	if result.Anonymous {
		parts = append(parts, "enumerated without credentials")
	}
	if result.Samples > 0 {
		parts = append(parts, fmt.Sprintf("%d sample(s) read", result.Samples))
	}
	if result.Searched {
		parts = append(parts, fmt.Sprintf("kNN executed, %d hit(s)", result.KnnHits))
	}
	if len(result.Errors) > 0 {
		parts = append(parts, fmt.Sprintf("%d error(s)", len(result.Errors)))
	}
	return strings.Join(parts, "; ")
}

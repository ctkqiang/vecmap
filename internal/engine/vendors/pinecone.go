package vendors

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"vecmap/internal/engine"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// Pinecone 实现 Pinecone 数据平面与控制平面的只读适配器。
type Pinecone struct {
	Base
}

// NewPinecone 创建 Pinecone 适配器。
//
// 参数 runtime 为共享协议客户端；返回已配置端口与厂商标识的适配器。
func NewPinecone(runtime *engine.Runtime) *Pinecone {
	return &Pinecone{Base: Base{VendorID: model.VendorPinecone, Ports: []int{443}, Runtime: runtime}}
}

// Fingerprint 识别 Pinecone 数据平面或控制平面。
//
// 参数 ctx 控制探测超时，target 为目标，options 为扫描配置。
// 返回指纹；未识别时返回 engine.ErrNotMatched。
func (p *Pinecone) Fingerprint(ctx context.Context, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	exchange, err := p.PostJSON(ctx, target, "/describe_index_stats", map[string]any{}, options)
	if exchange == nil && err != nil {
		return nil, engine.ErrNotMatched
	}
	if exchange != nil {
		if engine.IsSuccess(exchange.StatusCode) {
			value, decodeErr := engine.DecodeJSONMap(exchange)
			if decodeErr != nil || value["dimension"] == nil {
				return nil, engine.ErrNotMatched
			}
			dimension, _ := Integer(value["dimension"])
			namespaces := Map(value["namespaces"])
			fingerprint := &model.Fingerprint{
				Vendor:     model.VendorPinecone,
				Product:    "pinecone",
				Confidence: model.ConfidenceHigh,
				TLS:        true,
				HTTP:       &model.HTTPInfo{StatusCode: exchange.StatusCode, ContentType: exchange.ContentType},
				Metadata:   map[string]any{"dimension": dimension, "namespaces": len(namespaces)},
				Evidence:   []string{"describe_index_stats: dimension=" + fmt.Sprintf("%d", dimension)},
			}
			if count, ok := Integer(value["totalVectorCount"]); ok {
				fingerprint.Metadata["totalVectorCount"] = count
				fingerprint.Evidence = append(fingerprint.Evidence, fmt.Sprintf("totalVectorCount=%d", count))
			}
			return fingerprint, nil
		}
		if engine.IsAuthRequired(exchange.StatusCode) {
			return &model.Fingerprint{
				Vendor:       model.VendorPinecone,
				Product:      "pinecone",
				Confidence:   model.ConfidenceMedium,
				AuthRequired: true,
				TLS:          true,
				Evidence:     []string{fmt.Sprintf("describe_index_stats returned %d", exchange.StatusCode)},
			}, nil
		}
	}
	indexes, indexesErr := p.Get(ctx, target, "/indexes", options)
	if indexesErr == nil && indexes != nil && engine.IsSuccess(indexes.StatusCode) {
		if value, decodeErr := engine.DecodeJSONMap(indexes); decodeErr == nil {
			if _, ok := value["indexes"].([]any); ok {
				return &model.Fingerprint{
					Vendor:     model.VendorPinecone,
					Product:    "pinecone",
					Confidence: model.ConfidenceHigh,
					TLS:        true,
					Evidence:   []string{"control plane /indexes shape matched"},
				}, nil
			}
		}
	}
	return nil, engine.ErrNotMatched
}

// Enumerate 枚举 Pinecone 索引；数据平面按命名空间提取向量。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，
// dump 控制记录上限与向量采样。返回索引、记录与统计。
func (p *Pinecone) Enumerate(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	dump = dump.Normalize()
	extraction := &model.Extraction{Vendor: model.VendorPinecone, TargetID: target.ID}
	exchange, err := p.PostJSON(ctx, target, "/describe_index_stats", map[string]any{}, options)
	if err == nil && exchange != nil && engine.IsSuccess(exchange.StatusCode) {
		return p.dataPlane(ctx, target, options, dump, extraction, exchange)
	}
	if exchange != nil && engine.IsAuthRequired(exchange.StatusCode) {
		return extraction, engine.ErrUnauthorized
	}
	return p.controlPlane(ctx, target, options, dump, extraction)
}

func (p *Pinecone) dataPlane(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions, extraction *model.Extraction, statsExchange *model.HTTPExchange) (*model.Extraction, error) {
	value, err := p.JSONMap(statsExchange)
	if err != nil {
		return extraction, err
	}
	collection := &model.Collection{
		ID:        utilities.NewID("col"),
		TargetID:  target.ID,
		Vendor:    model.VendorPinecone,
		Name:      target.Host,
		Status:    "ready",
		IndexType: "pinecone",
		CreatedAt: time.Now().UTC(),
	}
	if dimension, ok := Integer(value["dimension"]); ok {
		collection.Dimension = int(dimension)
	}
	if count, ok := Integer(value["totalVectorCount"]); ok {
		collection.PointCount = count
	}
	namespaces := Map(value["namespaces"])
	namespaceNames := make([]string, 0, len(namespaces))
	for name := range namespaces {
		namespaceNames = append(namespaceNames, name)
	}
	if dump.Namespace != "" {
		namespaceNames = filterNames(namespaceNames, dump.Namespace)
	}
	collection.SetFields([]model.Field{{Name: "id", Type: "string", DataType: "string", Primary: true}})
	collection.SetMetadata(map[string]any{
		"indexFullness":    value["indexFullness"],
		"dimension":        value["dimension"],
		"totalVectorCount": value["totalVectorCount"],
		"namespaces":       namespaces,
	})
	extraction.Collections = append(extraction.Collections, collection)
	if !dump.ExtractRecords {
		return extraction, nil
	}
	for _, namespace := range namespaceNames {
		records, extractErr := p.namespaceVectors(ctx, target, collection, namespace, options, dump)
		if extractErr != nil {
			extraction.AddError(fmt.Sprintf("namespace %s: %s", namespace, extractErr))
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

func (p *Pinecone) controlPlane(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions, extraction *model.Extraction) (*model.Extraction, error) {
	exchange, err := p.Get(ctx, target, "/indexes", options)
	if err != nil {
		return extraction, err
	}
	value, err := p.JSONMap(exchange)
	if err != nil {
		return extraction, err
	}
	for _, item := range MapSlice(value["indexes"]) {
		name := FirstString(item, "name")
		if name == "" {
			continue
		}
		if dump.Collection != "" && name != dump.Collection {
			continue
		}
		collection := &model.Collection{
			ID:        utilities.NewID("col"),
			TargetID:  target.ID,
			Vendor:    model.VendorPinecone,
			Name:      name,
			Status:    FirstString(Map(item["status"]), "state", "ready"),
			IndexType: "pinecone",
			CreatedAt: time.Now().UTC(),
		}
		if dimension, ok := Integer(item["dimension"]); ok {
			collection.Dimension = int(dimension)
		}
		collection.Metric = FirstString(item, "metric")
		collection.SetMetadata(map[string]any{
			"host":   item["host"],
			"spec":   item["spec"],
			"status": item["status"],
		})
		extraction.Collections = append(extraction.Collections, collection)
	}
	return extraction, nil
}

func (p *Pinecone) namespaceVectors(ctx context.Context, target *model.Target, collection *model.Collection, namespace string, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	records := make([]*model.Record, 0, dump.BatchSize)
	ids, err := p.listIDs(ctx, target, namespace, options, dump.MaxRecords)
	if err != nil {
		return records, err
	}
	if len(ids) == 0 {
		return records, nil
	}
	for offset := 0; offset < len(ids); offset += 100 {
		batch := ids[offset:]
		if len(batch) > 100 {
			batch = batch[:100]
		}
		fetched, fetchErr := p.fetch(ctx, target, collection, namespace, batch, options, dump)
		if fetchErr != nil {
			return records, fetchErr
		}
		records = append(records, fetched...)
		if len(records) >= dump.MaxRecords {
			break
		}
	}
	return records, nil
}

func (p *Pinecone) listIDs(ctx context.Context, target *model.Target, namespace string, options model.ScanOptions, limit int) ([]string, error) {
	ids := make([]string, 0, 128)
	token := ""
	for len(ids) < limit {
		query := url.Values{}
		query.Set("limit", "100")
		if namespace != "" {
			query.Set("namespace", namespace)
		}
		if token != "" {
			query.Set("paginationToken", token)
		}
		exchange, err := p.Get(ctx, target, "/vectors/list?"+query.Encode(), options)
		if err != nil {
			return ids, err
		}
		value, err := p.JSONMap(exchange)
		if err != nil {
			return ids, err
		}
		for _, item := range MapSlice(value["vectors"]) {
			if id := FirstString(item, "id"); id != "" {
				ids = append(ids, id)
				if len(ids) >= limit {
					break
				}
			}
		}
		pagination := Map(value["pagination"])
		next := FirstString(pagination, "next", "nextPaginationToken", "next_pagination_token")
		if next == "" {
			break
		}
		token = next
	}
	return ids, nil
}

func (p *Pinecone) fetch(ctx context.Context, target *model.Target, collection *model.Collection, namespace string, ids []string, options model.ScanOptions, dump model.DumpOptions) ([]*model.Record, error) {
	body := map[string]any{"ids": ids}
	if namespace != "" {
		body["namespace"] = namespace
	}
	exchange, err := p.PostJSON(ctx, target, "/vectors/fetch", body, options)
	if err != nil {
		return nil, err
	}
	value, err := p.JSONMap(exchange)
	if err != nil {
		return nil, err
	}
	records := make([]*model.Record, 0, len(ids))
	for _, raw := range Map(value["vectors"]) {
		vectorItem := Map(raw)
		vector := VectorData{}
		if dump.IncludeVectors {
			vector = ParseVector(vectorItem["values"], dump.MaxVectorValues)
		}
		metadata := Map(vectorItem["metadata"])
		records = append(records, p.Record(target, collection, FirstString(vectorItem, "id"), metadata, vector, dump.MaxPayloadBytes))
	}
	return records, nil
}

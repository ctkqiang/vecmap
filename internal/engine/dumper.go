package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ctkqiang/vecmap/internal/model"
)

// Dumper 协调厂商适配器执行集合枚举与只读记录提取。
type Dumper struct {
	registry *Registry
	runtime  *Runtime
}

// NewDumper 创建提取协调器。
//
// 参数 registry 为厂商注册表，runtime 为共享协议客户端。
// 返回可复用的提取器。
func NewDumper(registry *Registry, runtime *Runtime) *Dumper {
	return &Dumper{registry: registry, runtime: runtime}
}

// Dump 对单个目标执行集合枚举与记录提取。
//
// 参数 ctx 控制生命周期，target 为目标，options 为扫描配置，dump 为提取上限。
// 返回提取结果；未识别厂商或适配器不支持时返回错误。
func (d *Dumper) Dump(ctx context.Context, target *model.Target, options model.ScanOptions, dump model.DumpOptions) (*model.Extraction, error) {
	if d == nil || d.registry == nil {
		return nil, fmt.Errorf("dumper is not initialized")
	}
	if target == nil {
		return nil, fmt.Errorf("target is nil")
	}
	dump = dump.Normalize()
	adapter, exists := d.registry.Get(target.Vendor)
	if !exists {
		identified, err := Identify(ctx, d.registry, d.runtime, target, options)
		if err != nil {
			return nil, err
		}
		adapter = identified.Adapter
	}
	if adapter == nil {
		return nil, fmt.Errorf("%w: no adapter for %s", ErrNotSupported, target.Vendor)
	}
	started := time.Now()
	extraction, err := adapter.Enumerate(ctx, target, options, dump)
	if err != nil {
		return extraction, err
	}
	if extraction == nil {
		extraction = &model.Extraction{}
	}
	if extraction.TargetID == "" {
		extraction.TargetID = target.ID
	}
	if extraction.Vendor == "" {
		extraction.Vendor = adapter.Vendor()
	}
	extraction.Records = dedupeRecords(extraction.Records, dump.MaxRecords)
	extraction.Stats.Collections = len(extraction.Collections)
	extraction.Stats.Records = len(extraction.Records)
	vectors := 0
	bytes := int64(0)
	for _, record := range extraction.Records {
		if strings.TrimSpace(record.VectorJSON) != "" {
			vectors++
		}
		bytes += int64(len(record.PayloadJSON) + len(record.VectorJSON))
	}
	extraction.Stats.Vectors = vectors
	extraction.Stats.Bytes = bytes
	if extraction.Stats.Duration == 0 {
		extraction.Stats.Duration = time.Since(started)
	}
	return extraction, nil
}

func dedupeRecords(records []*model.Record, maxRecords int) []*model.Record {
	if maxRecords <= 0 {
		maxRecords = 200
	}
	seen := map[string]struct{}{}
	result := make([]*model.Record, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		key := record.CollectionName + "|" + record.Namespace + "|" + record.ExternalID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, record)
		if len(result) >= maxRecords {
			break
		}
	}
	return result
}

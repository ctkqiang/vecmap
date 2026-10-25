package constant

import (
	"time"

	"vecmap/internal/model"
)

const (
	// Name 是工具名称。
	Name = "vecmap"
	// Version 是当前发布版本。
	Version = "1.0.0"
	// Tagline 是命令行与报告使用的简短定位。
	Tagline = "Vector database attack-surface assessment framework"
	// DefaultTimeout 是单次网络操作的默认超时。
	DefaultTimeout = 8 * time.Second
	// DefaultConcurrency 是目标级默认并发数。
	DefaultConcurrency = 8
	// DefaultPortConcurrency 是端口发现默认并发数。
	DefaultPortConcurrency = 64
	// DefaultMaxRecords 是深度提取默认记录上限。
	DefaultMaxRecords = 200
	// DefaultBatchSize 是分页读取默认批大小。
	DefaultBatchSize = 100
	// DefaultRateLimit 是默认请求速率；0 表示仅受超时约束。
	DefaultRateLimit = 20
	// DefaultMaxBody 是单次 HTTP 响应最大采集字节数。
	DefaultMaxBody = 4 << 20
	// DefaultUserAgent 是默认请求标识。
	DefaultUserAgent = "vecmap/" + Version
	// DefaultTenant 是 Chroma 默认租户名。
	DefaultTenant = "default_tenant"
	// DefaultChromaDatabase 是 Chroma 默认数据库名。
	DefaultChromaDatabase = "default_database"
	// DefaultMilvusDatabase 是 Milvus 默认数据库名。
	DefaultMilvusDatabase = "default"
	// DefaultDatabaseFile 是本地 SQLite 文件名。
	DefaultDatabaseFile = "vecmap.db"
)

// DefaultPorts 返回内置支持的默认探测端口集合。
//
// 返回值为去重后的端口切片，供发现命令在未显式指定端口时使用。
func DefaultPorts() []int {
	seen := map[int]struct{}{}
	ports := make([]int, 0, 24)
	for _, vendor := range AllVendors() {
		for _, port := range VendorPorts[vendor] {
			if _, exists := seen[port]; exists {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	return ports
}

// AllVendors 返回内置适配器支持的厂商列表。
//
// 返回顺序稳定，便于生成帮助信息与报告清单。
func AllVendors() []model.Vendor {
	return []model.Vendor{
		model.VendorQdrant,
		model.VendorMilvus,
		model.VendorWeaviate,
		model.VendorChroma,
		model.VendorRedis,
		model.VendorElasticsearch,
		model.VendorOpenSearch,
		model.VendorPgVector,
		model.VendorTypesense,
		model.VendorPinecone,
		model.VendorVespa,
	}
}

// VendorPorts 定义各厂商常见服务端口。
var VendorPorts = map[model.Vendor][]int{
	model.VendorQdrant:        {6333, 6334},
	model.VendorMilvus:        {19530, 9091},
	model.VendorWeaviate:      {8080, 50051},
	model.VendorChroma:        {8000},
	model.VendorRedis:         {6379, 6380},
	model.VendorElasticsearch: {9200, 9300},
	model.VendorOpenSearch:    {9200, 9300},
	model.VendorPgVector:      {5432},
	model.VendorTypesense:     {8108},
	model.VendorPinecone:      {443},
	model.VendorVespa:         {8080, 19071},
}

// VendorSchemes 定义各厂商默认 URL 方案。
var VendorSchemes = map[model.Vendor]string{
	model.VendorQdrant:        "http",
	model.VendorMilvus:        "http",
	model.VendorWeaviate:      "http",
	model.VendorChroma:        "http",
	model.VendorRedis:         "redis",
	model.VendorElasticsearch: "http",
	model.VendorOpenSearch:    "http",
	model.VendorPgVector:      "postgres",
	model.VendorTypesense:     "http",
	model.VendorPinecone:      "https",
	model.VendorVespa:         "http",
}

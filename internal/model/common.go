package model

import "strings"

// Severity 表示漏洞或暴露面的风险等级。
//
// 取值遵循 CVSS 与漏洞披露平台的通用分级，便于报告与工单系统对接。
type Severity string

const (
	// SeverityCritical 表示可直接导致数据泄露、接管或远程代码执行的风险。
	SeverityCritical Severity = "critical"
	// SeverityHigh 表示可导致显著数据暴露或权限提升的风险。
	SeverityHigh Severity = "high"
	// SeverityMedium 表示需要特定条件但仍具备实际利用价值的风险。
	SeverityMedium Severity = "medium"
	// SeverityLow 表示信息泄露、配置弱点或利用条件较高的风险。
	SeverityLow Severity = "low"
	// SeverityInfo 表示仅用于资产画像、版本识别或加固建议的信息。
	SeverityInfo Severity = "info"
)

// Rank 返回风险等级的可比较权重。
//
// 返回 critical=5、high=4、medium=3、low=2、info=1、未知=0。
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid 判断风险等级是否属于受支持的取值。
//
// 返回 true 表示可直接用于持久化与报告排序。
func (s Severity) Valid() bool {
	return s.Rank() > 0
}

// Label 返回按语言本地化的风险等级文本。
//
// 参数 language 为 en 或 zh；zh 返回 严重/高危/中危/低危/信息。
// 未知等级返回原始字符串。
func (s Severity) Label(language string) string {
	if language == "zh" {
		switch s {
		case SeverityCritical:
			return "严重"
		case SeverityHigh:
			return "高危"
		case SeverityMedium:
			return "中危"
		case SeverityLow:
			return "低危"
		case SeverityInfo:
			return "信息"
		}
	}
	return string(s)
}

// ParseSeverity 将外部文本转换为标准风险等级。
//
// 参数 raw 为大小写不敏感的等级文本。
// 返回标准等级；未知文本回退为 info，避免报告阶段丢失发现。
func ParseSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "crit", "严重":
		return SeverityCritical
	case "high", "高":
		return SeverityHigh
	case "medium", "moderate", "中":
		return SeverityMedium
	case "low", "低":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// SeverityForScore 根据 CVSS 分值推导风险等级。
//
// 参数 score 为 0 到 10 之间的 CVSS 分值。
// 返回对应的标准风险等级。
func SeverityForScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Confidence 表示指纹、版本或漏洞匹配结果的可信度。
type Confidence string

const (
	// ConfidenceLow 表示基于单一弱特征或启发式推断。
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium 表示基于多个响应特征或未精确的版本信息。
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh 表示基于明确产品标识、精确版本或直接证据。
	ConfidenceHigh Confidence = "high"
)

// Rank 返回可信度的可比较权重。
//
// 返回 high=3、medium=2、low=1、未知=0。
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// Label 返回按语言本地化的可信度文本。
//
// 参数 language 为 en 或 zh；zh 返回 高/中/低。
// 未知可信度返回原始字符串。
func (c Confidence) Label(language string) string {
	if language == "zh" {
		switch c {
		case ConfidenceHigh:
			return "高"
		case ConfidenceMedium:
			return "中"
		case ConfidenceLow:
			return "低"
		}
	}
	return string(c)
}

// Protocol 表示目标暴露的传输协议。
type Protocol string

const (
	// ProtocolTCP 表示仅完成 TCP 连通性探测。
	ProtocolTCP Protocol = "tcp"
	// ProtocolHTTP 表示明文 HTTP。
	ProtocolHTTP Protocol = "http"
	// ProtocolHTTPS 表示 TLS 加密的 HTTP。
	ProtocolHTTPS Protocol = "https"
	// ProtocolGRPC 表示 gRPC over HTTP/2。
	ProtocolGRPC Protocol = "grpc"
	// ProtocolRESP 表示 Redis RESP 协议。
	ProtocolRESP Protocol = "resp"
	// ProtocolPostgres 表示 PostgreSQL 线协议。
	ProtocolPostgres Protocol = "postgres"
	// ProtocolUnknown 表示尚未识别的协议。
	ProtocolUnknown Protocol = "unknown"
)

// Vendor 表示向量数据库或相关检索基础设施的厂商标识。
type Vendor string

const (
	// VendorQdrant 表示 Qdrant。
	VendorQdrant Vendor = "qdrant"
	// VendorMilvus 表示 Milvus 及其兼容发行版。
	VendorMilvus Vendor = "milvus"
	// VendorWeaviate 表示 Weaviate。
	VendorWeaviate Vendor = "weaviate"
	// VendorChroma 表示 Chroma / ChromaDB。
	VendorChroma Vendor = "chroma"
	// VendorRedis 表示 Redis 与 RediSearch 向量索引。
	VendorRedis Vendor = "redis"
	// VendorElasticsearch 表示 Elasticsearch。
	VendorElasticsearch Vendor = "elasticsearch"
	// VendorOpenSearch 表示 OpenSearch。
	VendorOpenSearch Vendor = "opensearch"
	// VendorPgVector 表示 PostgreSQL 的 pgvector 扩展。
	VendorPgVector Vendor = "pgvector"
	// VendorTypesense 表示 Typesense。
	VendorTypesense Vendor = "typesense"
	// VendorPinecone 表示 Pinecone 托管向量数据库。
	VendorPinecone Vendor = "pinecone"
	// VendorVespa 表示 Vespa。
	VendorVespa Vendor = "vespa"
	// VendorApache 表示 Apache 组件依赖，例如 Log4j2。
	VendorApache Vendor = "apache"
	// VendorUnknown 表示未能识别的厂商。
	VendorUnknown Vendor = "unknown"
)

// DisplayName 返回适合报告展示的厂商名称。
//
// 返回稳定的英文产品名称；未知厂商返回 Unknown。
// 需要本地化文本时请使用 DisplayNameIn。
func (v Vendor) DisplayName() string {
	return v.DisplayNameIn("en")
}

// DisplayNameIn 返回按语言本地化的厂商名称。
//
// 参数 language 为 en 或 zh；品牌名保持原文，仅描述性部分本地化。
// 未知厂商英文返回 Unknown，中文返回 未知。
func (v Vendor) DisplayNameIn(language string) string {
	if language == "zh" {
		switch v {
		case VendorQdrant:
			return "Qdrant"
		case VendorMilvus:
			return "Milvus"
		case VendorWeaviate:
			return "Weaviate"
		case VendorChroma:
			return "Chroma"
		case VendorRedis:
			return "Redis / RediSearch"
		case VendorElasticsearch:
			return "Elasticsearch"
		case VendorOpenSearch:
			return "OpenSearch"
		case VendorPgVector:
			return "PostgreSQL pgvector 扩展"
		case VendorTypesense:
			return "Typesense"
		case VendorPinecone:
			return "Pinecone"
		case VendorVespa:
			return "Vespa"
		case VendorApache:
			return "Apache"
		default:
			return "未知"
		}
	}
	switch v {
	case VendorQdrant:
		return "Qdrant"
	case VendorMilvus:
		return "Milvus"
	case VendorWeaviate:
		return "Weaviate"
	case VendorChroma:
		return "Chroma"
	case VendorRedis:
		return "Redis / RediSearch"
	case VendorElasticsearch:
		return "Elasticsearch"
	case VendorOpenSearch:
		return "OpenSearch"
	case VendorPgVector:
		return "PostgreSQL pgvector"
	case VendorTypesense:
		return "Typesense"
	case VendorPinecone:
		return "Pinecone"
	case VendorVespa:
		return "Vespa"
	case VendorApache:
		return "Apache"
	default:
		return "Unknown"
	}
}

// ParseVendor 将用户输入或指纹文本转换为厂商标识。
//
// 参数 raw 为产品名、别名或标识。
// 返回标准厂商标识；无法识别时返回 VendorUnknown。
func ParseVendor(raw string) Vendor {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "qdrant":
		return VendorQdrant
	case "milvus", "zilliz":
		return VendorMilvus
	case "weaviate":
		return VendorWeaviate
	case "chroma", "chromadb":
		return VendorChroma
	case "redis", "redisearch", "redis-stack":
		return VendorRedis
	case "elasticsearch", "elastic":
		return VendorElasticsearch
	case "opensearch":
		return VendorOpenSearch
	case "pgvector", "postgres", "postgresql", "pgsql":
		return VendorPgVector
	case "typesense":
		return VendorTypesense
	case "pinecone":
		return VendorPinecone
	case "vespa":
		return VendorVespa
	case "apache", "log4j", "log4j2":
		return VendorApache
	default:
		return VendorUnknown
	}
}

// AuthType 表示目标暴露面使用的认证方式。
type AuthType string

const (
	// AuthUnknown 表示尚未确认认证要求。
	AuthUnknown AuthType = "unknown"
	// AuthNone 表示接口无需认证即可访问。
	AuthNone AuthType = "none"
	// AuthAPIKey 表示使用 API Key 认证。
	AuthAPIKey AuthType = "api_key"
	// AuthBearer 表示使用 Bearer Token 认证。
	AuthBearer AuthType = "bearer"
	// AuthBasic 表示使用 HTTP Basic 认证。
	AuthBasic AuthType = "basic"
	// AuthPassword 表示数据库用户名密码认证。
	AuthPassword AuthType = "password"
)

// Reference 表示漏洞公告或技术文档来源。
type Reference struct {
	Title  string `json:"title"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// MITRETechnique 表示 MITRE ATT&CK 技术条目。
//
// Name/Tactic 为英文名，NameZH/TacticZH 为中文本地化名，
// 报告层根据界面语言选择对应文本。
type MITRETechnique struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	NameZH   string `json:"name_zh,omitempty"`
	Tactic   string `json:"tactic"`
	TacticZH string `json:"tactic_zh,omitempty"`
	URL      string `json:"url"`
}

// CVSS 表示通用漏洞评分系统信息。
type CVSS struct {
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
	Version string  `json:"version"`
}

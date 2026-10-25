// Package model 中的本文件存放扫描相关的数据对象（DTO），只有类型，不含函数。
// 端口发现、指纹识别、Schema 枚举与报告都通过这些结构传递结果。
package model

import "time"

// Endpoint 表示一个待探测的 host:port 端点。
type Endpoint struct {
	Host     string // 主机名或 IP
	Port     int    // 端口
	Protocol string // 传输协议：TCP / HTTP / GRPC
	Vendor   string // 预判的向量库厂商，空表示交由指纹阶段自动识别
}

// DiscoveryResult 是一次 TCP 探活的结果。
type DiscoveryResult struct {
	Endpoint Endpoint
	Open     bool          // 端口是否开放
	Latency  time.Duration // 建连耗时
	Err      error         // 连接失败原因，Open 为 true 时为空
}

// Fingerprint 是 HTTP / gRPC / TCP 探测得到的服务指纹。
type Fingerprint struct {
	Endpoint        Endpoint
	Vendor          string    // 识别出的产品，例如 Weaviate / Qdrant
	Version         string    // 版本号，无法判断时为空
	Product         string    // 产品名或接口类型
	Scheme          string    // 探测成功的传输协议：http / https / tcp
	APIBase         string    // 已确认的 REST 接口前缀，例如 /api/v2；用于后续枚举
	AnonymousAccess bool      // 未携带凭证即可访问受保护接口
	Confidence      string    // high / medium / low
	Evidence        []string  // 判定依据，例如命中的接口与响应片段
	ProbedAt        time.Time // 探测时间
}

// Field 是集合中的一个字段（列）。
type Field struct {
	Name string // 字段名
	Type string // 字段类型
}

// Collection 是一个集合（Weaviate 的 class、Qdrant 的 collection 等）。
type Collection struct {
	ID        string  // 服务端标识；Chroma 使用 UUID，其余通常与 Name 相同
	Name      string  // 集合名
	Dimension int     // 向量维度，未知为 0
	Metric    string  // 距离度量，例如 cosine / l2
	Points    int64   // 记录数，未知为 0
	Fields    []Field // 标量字段
}

// DumpResult 是一次 Schema 枚举与非破坏性取样的结果。
type DumpResult struct {
	Endpoint    Endpoint
	Vendor      string
	Anonymous   bool         // 枚举过程未使用任何凭证
	Collections []Collection // 枚举到的集合
	Samples     int          // 实际读取到的样本条数
	Searched    bool         // 是否执行过 kNN 检索验证
	KnnHits     int          // kNN 检索返回的记录数
	Evidence    string       // 关键响应摘要
	Errors      []string     // 单个集合失败不终止整体枚举，错误记录在此
}

// FindingKind 标记发现的类别，报告层据此映射 MITRE ATT&CK。
type FindingKind string

const (
	FindingDiscovery     FindingKind = "discovery"     // 端口与服务发现
	FindingExposure      FindingKind = "exposure"      // 未授权访问
	FindingVulnerability FindingKind = "vulnerability" // 已知 CVE
	FindingExfiltration  FindingKind = "exfiltration"  // 数据可被读取
)

// 非 CVE 发现的代码，写入 VulnerabilityRecord.Code。
// 回放历史会话时据此按当前界面语言重新生成标题与说明。
const (
	FindingCodeAnonymous    = "finding.anonymous"
	FindingCodeMetadata     = "finding.metadata"
	FindingCodeExfiltration = "finding.exfiltration"
)

// FindingData 是非 CVE 发现的参数，由 CLI 序列化后存入
// VulnerabilityRecord.Data，报告层再按当前语言还原文案。
type FindingData struct {
	Vendor      string `json:"vendor,omitempty"`
	Collections int    `json:"collections,omitempty"`
	Samples     int    `json:"samples,omitempty"`
	KnnHits     int    `json:"knn_hits,omitempty"`
}

package constant

// CVEEntry 描述一条与向量数据库相关的公开漏洞。
//
// 数据来源均为厂商公告、GitHub Security Advisory 或 NVD，
// 每一条都必须在 Reference 中给出可核查的链接。
// 版本匹配由 internal/engine 完成，本包只存静态数据。
type CVEEntry struct {
	ID            string         // CVE 或 GHSA 编号
	Vendor        Vendor         // 受影响的向量库
	Title         string         // 英文标题
	TitleZH       string         // 中文标题
	Severity      string         // CRITICAL / HIGH / MEDIUM / LOW
	CVSS          float64        // CVSS 3.1 或 4.0 分值
	Affected      string         // 受影响版本的可读描述
	Fixed         string         // 修复版本，空表示暂无修复
	Description   string         // 英文说明
	DescriptionZH string         // 中文说明
	TTP           string         // 对应的 MITRE ATT&CK 技术编号
	Reference     string         // 可核查来源
	Ranges        []VersionRange // 机器可读的受影响区间
}

// VersionRange 是左闭右闭的版本区间，空字符串表示该侧无边界。
type VersionRange struct {
	Min string // 例如 "1.30.0"
	Max string // 例如 "1.30.19"
}

// LookupCVE 按编号查找内置公告，供报告层按当前语言重新取词。
func LookupCVE(id string) (CVEEntry, bool) {
	for _, entry := range CVEs {
		if entry.ID == id {
			return entry, true
		}
	}
	return CVEEntry{}, false
}

// CVEs 是内置的漏洞种子库。新增条目必须附来源链接，
// 禁止凭印象填写编号或影响范围。
var CVEs = []CVEEntry{
	{
		ID:       "CVE-2025-67818",
		Vendor:   VendorWeaviate,
		Title:    "Path traversal in backup restore (ZipSlip)",
		TitleZH:  "备份恢复路径穿越（ZipSlip）",
		Severity: "HIGH",
		CVSS:     7.2,
		Affected: "<= 1.30.19, 1.31.x <= 1.31.18, 1.32.x <= 1.32.15, 1.33.x <= 1.33.3",
		Fixed:    "1.30.20 / 1.31.19 / 1.32.16 / 1.33.4",
		Description: "An attacker with permission to create objects can use symlinks, absolute paths " +
			"or .. segments to escape the restore root and create or overwrite arbitrary files " +
			"with the privileges of the server process.",
		DescriptionZH: "具备写入对象权限的攻击者可在备份条目中使用符号链接、绝对路径或 .. 逃逸恢复根目录，" +
			"在服务进程权限范围内创建或覆盖任意文件。",
		TTP:       "T1190",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2025-67818",
		Ranges: []VersionRange{
			{Max: "1.30.19"},
			{Min: "1.31.0", Max: "1.31.18"},
			{Min: "1.32.0", Max: "1.32.15"},
			{Min: "1.33.0", Max: "1.33.3"},
		},
	},
	{
		ID:       "CVE-2025-67819",
		Vendor:   VendorWeaviate,
		Title:    "Path traversal in shard movement (arbitrary file read)",
		TitleZH:  "分片迁移接口路径穿越（任意文件读取）",
		Severity: "HIGH",
		CVSS:     8.7,
		Affected: "1.30.0 up to 1.30.19 / 1.31.18 / 1.32.15 / 1.33.3",
		Fixed:    "1.30.20 / 1.31.19 / 1.32.16 / 1.33.4",
		Description: "The GetFile endpoint does not validate the fileName parameter, allowing ../ " +
			"or absolute paths to read any file the server process can access. " +
			"The Shard Movement API is disabled by default.",
		DescriptionZH: "GetFile 接口未校验 fileName 参数，攻击者可利用 ../ 或绝对路径读取服务进程可访问的任意文件。" +
			"Shard Movement API 默认关闭。",
		TTP:       "T1005",
		Reference: "https://github.com/advisories/GHSA-hmmh-292h-3364",
		Ranges: []VersionRange{
			{Min: "1.30.0", Max: "1.30.19"},
			{Min: "1.31.0", Max: "1.31.18"},
			{Min: "1.32.0", Max: "1.32.15"},
			{Min: "1.33.0", Max: "1.33.3"},
		},
	},
	{
		ID:       "CVE-2026-11500",
		Vendor:   VendorWeaviate,
		Title:    "Static API key validation flaw leads to authorization bypass",
		TitleZH:  "静态 API Key 校验缺陷导致越权",
		Severity: "MEDIUM",
		CVSS:     5.0,
		Affected: "<= 1.37.7",
		Fixed:    "1.38.0-rc.0",
		Description: "validateConfig in apikey/client.go mishandles StaticApiKey and can allow an " +
			"authorization bypass. Exploitation requires an authenticated low-privilege account.",
		DescriptionZH: "apikey/client.go 的 validateConfig 对 StaticApiKey 处理不当，可导致授权绕过。" +
			"利用条件较苛刻，需要较低的已认证权限。",
		TTP:       "T1078",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-11500",
		Ranges:    []VersionRange{{Max: "1.37.7"}},
	},
	{
		ID:       "CVE-2024-3829",
		Vendor:   VendorQdrant,
		Title:    "Arbitrary file read/write via snapshot restore",
		TitleZH:  "快照恢复任意文件读写",
		Severity: "CRITICAL",
		CVSS:     9.8,
		Affected: "< 1.9.0",
		Fixed:    "1.9.0",
		Description: "Snapshot restore does not restrict symlinks; a crafted snapshot allows arbitrary " +
			"file read and write and may lead to host takeover.",
		DescriptionZH: "快照恢复过程未限制符号链接，攻击者可构造快照实现任意文件读取与写入，进而可能接管主机。",
		TTP:           "T1190",
		Reference:     "https://github.com/advisories/GHSA-7m75-x27w-r52r",
		Ranges:        []VersionRange{{Max: "1.8.9"}},
	},
	{
		ID:       "CVE-2026-25628",
		Vendor:   VendorQdrant,
		Title:    "Arbitrary file append via /logger endpoint",
		TitleZH:  "/logger 接口任意文件追加写入",
		Severity: "HIGH",
		CVSS:     8.8,
		Affected: ">= 1.9.3, < 1.16.0",
		Fixed:    "1.16.0",
		Description: "The /logger endpoint accepts an attacker-controlled on_disk.log_file path. " +
			"Read-only access is enough to append to arbitrary files, rewrite configuration " +
			"and escalate privileges.",
		DescriptionZH: "/logger 接口接受攻击者可控的 on_disk.log_file 路径，只读权限即可向任意文件追加内容，" +
			"可改写配置并提升权限。",
		TTP:       "T1190",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-25628",
		Ranges:    []VersionRange{{Min: "1.9.3", Max: "1.15.5"}},
	},
	{
		ID:       "GHSA-frc7-44gm-99qq",
		Vendor:   VendorQdrant,
		Title:    "Unauthenticated internal gRPC in distributed mode",
		TitleZH:  "分布式模式下内部 gRPC 无鉴权",
		Severity: "CRITICAL",
		CVSS:     9.8,
		Affected: "< 1.20.0 (internal port when cluster.enabled)",
		Fixed:    "1.20.0",
		Description: "In distributed deployments the internal gRPC port does not require " +
			"authentication by default; an attacker can call AddPeerToKnown, read shard data " +
			"or change cluster state. Single-node deployments do not expose it.",
		DescriptionZH: "分布式部署时内部 gRPC 端口默认不要求鉴权，可调用 AddPeerToKnown 加入集群、" +
			"读取分片数据或修改集群状态。单机部署不启动该端口。",
		TTP:       "T1190",
		Reference: "https://github.com/qdrant/qdrant/security/advisories/GHSA-frc7-44gm-99qq",
		Ranges:    []VersionRange{{Max: "1.19.9"}},
	},
	{
		ID:       "GHSA-3gph-6c29-p29v",
		Vendor:   VendorQdrant,
		Title:    "Internal gRPC accepts read-only keys and JWTs",
		TitleZH:  "内部 gRPC 接受只读 Key 与 JWT",
		Severity: "HIGH",
		CVSS:     8.3,
		Affected: ">= 1.18.0, < 1.19.2",
		Fixed:    "1.19.2",
		Description: "Even with enforce_internal_auth enabled the internal port accepts read-only " +
			"API keys and arbitrary JWTs, so a read-only credential can perform internal " +
			"write operations.",
		DescriptionZH: "启用 enforce_internal_auth 后，内部端口仍接受只读 API Key 与任意 JWT，" +
			"持有只读凭证即可执行内部写操作。",
		TTP:       "T1078",
		Reference: "https://github.com/qdrant/qdrant/security/advisories/GHSA-3gph-6c29-p29v",
		Ranges:    []VersionRange{{Min: "1.18.0", Max: "1.19.1"}},
	},
	{
		ID:       "CVE-2025-64513",
		Vendor:   VendorMilvus,
		Title:    "Milvus Proxy authentication bypass",
		TitleZH:  "Proxy 组件认证绕过",
		Severity: "CRITICAL",
		CVSS:     9.3,
		Affected: "< 2.4.24, 2.5.x < 2.5.21, 2.6.x < 2.6.5",
		Fixed:    "2.4.24 / 2.5.21 / 2.6.5",
		Description: "An unauthenticated attacker can bypass every authentication mechanism in the " +
			"Milvus Proxy and gain administrative access to read, modify or delete data. " +
			"Mitigation: strip the sourceID header at the gateway.",
		DescriptionZH: "未认证攻击者可绕过 Milvus Proxy 的全部认证机制获得管理权限，可读写删除数据并执行管理与集合操作。" +
			"缓解方式是移除 sourceID 请求头。",
		TTP:       "T1190",
		Reference: "https://github.com/milvus-io/milvus/security/advisories/GHSA-mhjq-8c7m-3f7p",
		Ranges: []VersionRange{
			{Max: "2.4.23"},
			{Min: "2.5.0", Max: "2.5.20"},
			{Min: "2.6.0", Max: "2.6.4"},
		},
	},
	{
		ID:       "CVE-2026-26190",
		Vendor:   VendorMilvus,
		Title:    "Default-exposed port 9091 bypasses authentication",
		TitleZH:  "9091 端口默认暴露导致认证绕过",
		Severity: "CRITICAL",
		CVSS:     9.8,
		Affected: "< 2.5.27, 2.6.x < 2.6.10",
		Fixed:    "2.5.27 / 2.6.10",
		Description: "Milvus exposes port 9091 by default and the authentication middleware does not " +
			"cover its endpoints, allowing REST API authentication to be bypassed.",
		DescriptionZH: "Milvus 默认开放 9091 端口，认证中间件未覆盖该端口上的接口，攻击者可绕过 REST API 鉴权。",
		TTP:           "T1190",
		Reference:     "https://nvd.nist.gov/vuln/detail/CVE-2026-26190",
		Ranges: []VersionRange{
			{Max: "2.5.26"},
			{Min: "2.6.0", Max: "2.6.9"},
		},
	},
	{
		ID:       "CVE-2026-69111",
		Vendor:   VendorMilvus,
		Title:    "Unauthenticated management endpoint denial of service",
		TitleZH:  "9091 管理接口未鉴权拒绝服务",
		Severity: "HIGH",
		CVSS:     7.5,
		Affected: "<= 2.6.22 and 3.0.0",
		Fixed:    "None (after 2.6.23)",
		Description: "The /management/stop endpoint on port 9091 is not protected by the REST " +
			"authentication middleware; an attacker can pass a role parameter to stop proxy, " +
			"datanode or querynode.",
		DescriptionZH: "管理服务 9091 的 /management/stop 未受 REST 鉴权中间件保护，" +
			"攻击者可传入 role 参数停止 proxy、datanode 或 querynode。",
		TTP:       "T1190",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-69111",
		Ranges:    []VersionRange{{Max: "2.6.22"}, {Min: "3.0.0", Max: "3.0.0"}},
	},
	{
		ID:       "CVE-2026-45829",
		Vendor:   VendorChroma,
		Title:    "Pre-authentication code injection via trust_remote_code",
		TitleZH:  "预认证代码注入（trust_remote_code）",
		Severity: "CRITICAL",
		CVSS:     9.3,
		Affected: ">= 1.0.0, <= 1.5.9",
		Fixed:    "None",
		Description: "An unauthenticated attacker can supply a malicious model repository with " +
			"trust_remote_code enabled when creating a collection and execute arbitrary code " +
			"on the server.",
		DescriptionZH: "未认证攻击者可在创建集合时传入恶意模型仓库并令 trust_remote_code 为 true，" +
			"在服务端执行任意代码。",
		TTP:       "T1190",
		Reference: "https://github.com/advisories/GHSA-f4j7-r4q5-qw2c",
		Ranges:    []VersionRange{{Min: "1.0.0", Max: "1.5.9"}},
	},
	{
		ID:       "CVE-2026-45831",
		Vendor:   VendorChroma,
		Title:    "RBAC does not verify tenant and collection ownership",
		TitleZH:  "RBAC 未校验租户与集合归属",
		Severity: "HIGH",
		CVSS:     8.8,
		Affected: ">= 0.5.0, <= 1.5.9",
		Fixed:    "None",
		Description: "SimpleRBACAuthorizationProvider only checks the permission name, not which " +
			"tenant, database or collection it belongs to, enabling cross-tenant operations.",
		DescriptionZH: "SimpleRBACAuthorizationProvider 只校验权限名，不校验该权限属于哪个租户/数据库/集合，" +
			"导致跨租户操作。",
		TTP:       "T1078",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-45831",
		Ranges:    []VersionRange{{Min: "0.5.0", Max: "1.5.9"}},
	},
	{
		ID:       "CVE-2026-92782",
		Vendor:   VendorChroma,
		Title:    "Collection ID parsing bypasses tenant isolation",
		TitleZH:  "集合 ID 解析绕过租户隔离",
		Severity: "HIGH",
		CVSS:     8.1,
		Affected: "<= 1.5.9",
		Fixed:    "None",
		Description: "Collection resolution does not validate the tenant and database path " +
			"segments; an authenticated attacker who knows a collection UUID can read or " +
			"modify data across tenants.",
		DescriptionZH: "解析集合时未校验路径中的 tenant 与 database 段，" +
			"已认证攻击者只要知道集合 UUID 即可跨租户读取或修改数据。",
		TTP:       "T1213",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-92782",
		Ranges:    []VersionRange{{Max: "1.5.9"}},
	},
	{
		ID:       "CVE-2026-85664",
		Vendor:   VendorChroma,
		Title:    "Unbounded HNSW parameters exhaust memory",
		TitleZH:  "HNSW 参数缺少上界导致内存耗尽",
		Severity: "HIGH",
		CVSS:     7.5,
		Affected: "<= 1.5.9",
		Fixed:    "None",
		Description: "Collection creation does not bound max_neighbors, ef_construction or " +
			"ef_search; an unauthenticated attacker can force excessive memory use during " +
			"index compaction.",
		DescriptionZH: "创建集合时未校验 max_neighbors、ef_construction、ef_search 的上界，" +
			"未认证攻击者可传入超大值在索引压缩阶段耗尽内存。",
		TTP:       "T1190",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-85664",
		Ranges:    []VersionRange{{Max: "1.5.9"}},
	},
}

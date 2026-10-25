package constant

import "vecmap/internal/model"

// Advisories 返回内置的已校验漏洞公告目录。
//
// 所有条目均来自官方 CVE 记录、NVD、GitHub Advisory 或 CNVD 公告，
// 受影响版本区间在收录时经过在线核对；
// Matchable 为 false 的条目仅作报告引用，不会自动关联目标版本。
func Advisories() []model.Advisory {
	return []model.Advisory{
		qdrant20243584(),
		qdrant20243829(),
		qdrant202625628(),
		milvus202564513(),
		milvus202626190(),
		milvus202669111(),
		weaviate202611500(),
		chroma202692782(),
		chroma202645829(),
		typesense202647216(),
		typesense202647225(),
		log4j202144228(),
		redis20220543(),
	}
}

func qdrant20243584() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2024-3584",
		CVE:           "CVE-2024-3584",
		Vendor:        model.VendorQdrant,
		Product:       "qdrant",
		Title:         "Path Traversal in qdrant/qdrant snapshot upload endpoint",
		TitleZH:       "Qdrant 快照上传接口路径穿越漏洞",
		Summary:       "qdrant/qdrant is vulnerable to path traversal due to improper input validation in the /collections/{name}/snapshots/upload endpoint. A manipulated name parameter can write or overwrite arbitrary files on the server. Fixed in 1.9.0.",
		SummaryZH:     "qdrant/qdrant 的 /collections/{name}/snapshots/upload 接口对 name 参数校验不严，攻击者可借 URL 编码实现路径穿越，向服务器任意位置写入或覆盖文件。1.9.0 版本已修复。",
		Impact:        "Unauthenticated arbitrary file write and overwrite, potentially leading to full host takeover.",
		ImpactZH:      "未授权状态下可任意写入与覆盖服务器文件，可能导致主机完全失陷。",
		Remediation:   "Upgrade Qdrant to 1.9.0 or later.",
		RemediationZH: "将 Qdrant 升级到 1.9.0 或更高版本。",
		Severity:      model.SeverityCritical,
		CVSS:          model.CVSS{Score: 9.8, Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Version: "3.0"},
		Affected:      []string{"< 1.9.0"},
		References: []model.Reference{
			{Title: "CVE-2024-3584 (CVE.org)", URL: "https://www.cve.org/CVERecord?id=CVE-2024-3584", Source: "CVE"},
			{Title: "NVD - CVE-2024-3584", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-3584", Source: "NVD"},
			{Title: "GHSA-xcr2-h8hv-6227", URL: "https://github.com/advisories/GHSA-xcr2-h8hv-6227", Source: "GitHub Advisory"},
		},
		MITRE:       []string{"T1210"},
		Verified:    true,
		Matchable:   true,
		Source:      "CVE/NVD/GitHub Advisory",
		PublishedAt: "2024-05-30",
	}
}

func qdrant20243829() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2024-3829",
		CVE:           "CVE-2024-3829",
		Vendor:        model.VendorQdrant,
		Product:       "qdrant",
		Title:         "Arbitrary File Read and Write during Snapshot Recovery in qdrant/qdrant",
		TitleZH:       "Qdrant 快照恢复过程任意文件读写漏洞",
		Summary:       "qdrant/qdrant versions prior to 1.9.0 are vulnerable to arbitrary file read and write during the snapshot recovery process. Attackers can manipulate snapshot files to include symlinks, leading to arbitrary file read and write. Fixed in v1.9.0.",
		SummaryZH:     "1.9.0 之前的 qdrant/qdrant 在快照恢复过程中存在任意文件读写漏洞，攻击者可构造包含符号链接的快照文件读取或写入任意文件。v1.9.0 已修复。",
		Impact:        "Unauthenticated arbitrary file read and write, potentially leading to remote code execution and full takeover.",
		ImpactZH:      "未授权状态下可任意读写服务器文件，可能导致远程代码执行与主机完全失陷。",
		Remediation:   "Upgrade Qdrant to v1.9.0 or later.",
		RemediationZH: "将 Qdrant 升级到 v1.9.0 或更高版本。",
		Severity:      model.SeverityCritical,
		CVSS:          model.CVSS{Score: 9.1, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Version: "3.1"},
		Affected:      []string{"< 1.9.0"},
		References: []model.Reference{
			{Title: "CVE-2024-3829 (CVE.org)", URL: "https://www.cve.org/CVERecord?id=CVE-2024-3829", Source: "CVE"},
			{Title: "NVD - CVE-2024-3829", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-3829", Source: "NVD"},
			{Title: "Qdrant response to CVE-2024-3829", URL: "https://qdrant.tech/blog/cve-2024-3829-response", Source: "Vendor"},
		},
		MITRE:       []string{"T1210"},
		Verified:    true,
		Matchable:   true,
		Source:      "CVE/NVD/Vendor",
		PublishedAt: "2024-06-03",
	}
}

func qdrant202625628() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-25628",
		CVE:           "CVE-2026-25628",
		Vendor:        model.VendorQdrant,
		Product:       "qdrant",
		Title:         "Qdrant arbitrary file write via /logger endpoint",
		TitleZH:       "Qdrant /logger 接口任意文件写入漏洞",
		Summary:       "From 1.9.3 to before 1.16.0, it is possible to append to arbitrary files via the /logger endpoint using an attacker-controlled on_disk.log_file path. Minimal privileges are required (read-only access). Fixed in 1.16.0.",
		SummaryZH:     "1.9.3 至 1.16.0 之前的版本中，攻击者可通过 /logger 接口构造 on_disk.log_file 路径向任意文件追加内容，仅需只读权限。1.16.0 已修复。",
		Impact:        "Authenticated arbitrary file append, potentially enabling privilege escalation or system compromise.",
		ImpactZH:      "认证后即可向任意文件追加内容，可能被用于提权或进一步入侵。",
		Remediation:   "Upgrade Qdrant to 1.16.0 or later.",
		RemediationZH: "将 Qdrant 升级到 1.16.0 或更高版本。",
		Severity:      model.SeverityHigh,
		CVSS:          model.CVSS{Score: 8.6, Vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", Version: "3.1"},
		Affected:      []string{">= 1.9.3, < 1.16.0"},
		References: []model.Reference{
			{Title: "CVE-2026-25628 (CVE.org)", URL: "https://www.cve.org/CVERecord?id=CVE-2026-25628", Source: "CVE"},
			{Title: "NVD - CVE-2026-25628", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-25628", Source: "NVD"},
			{Title: "GHSA-f632-vm87-2m2f", URL: "https://github.com/advisories/GHSA-f632-vm87-2m2f", Source: "GitHub Advisory"},
		},
		MITRE:       []string{"T1059"},
		Verified:    true,
		Matchable:   true,
		Source:      "CVE/NVD/GitHub Advisory",
		PublishedAt: "2026-02-06",
	}
}

func milvus202564513() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2025-64513",
		CVE:           "CVE-2025-64513",
		Vendor:        model.VendorMilvus,
		Product:       "milvus",
		Title:         "Milvus Proxy Critical Authentication Bypass Vulnerability",
		TitleZH:       "Milvus Proxy 认证绕过漏洞（严重）",
		Summary:       "An unauthenticated attacker can bypass all authentication mechanisms in the Milvus Proxy component in versions prior to 2.4.24, 2.5.21, and 2.6.5, gaining full administrative access to the Milvus cluster. Fixed in Milvus 2.4.24, 2.5.21, and 2.6.5.",
		SummaryZH:     "2.4.24、2.5.21、2.6.5 之前的 Milvus Proxy 存在认证绕过，未授权攻击者可获得集群完整管理权限。已在 2.4.24、2.5.21、2.6.5 修复。",
		Impact:        "Unauthenticated administrative access to the Milvus cluster, enabling read, modify, or delete of all data and privileged operations.",
		ImpactZH:      "未授权获得 Milvus 集群管理权限，可读取、修改、删除全部数据并执行特权操作。",
		Remediation:   "Upgrade to Milvus 2.4.24, 2.5.21, 2.6.5, or later.",
		RemediationZH: "升级到 Milvus 2.4.24、2.5.21、2.6.5 或更高版本。",
		Severity:      model.SeverityCritical,
		CVSS:          model.CVSS{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Version: "3.1"},
		Affected:      []string{"< 2.4.24", ">= 2.5.0, < 2.5.21", ">= 2.6.0, < 2.6.5"},
		References: []model.Reference{
			{Title: "CVE-2025-64513 (CVE.org)", URL: "https://www.cve.org/CVERecord?id=CVE-2025-64513", Source: "CVE"},
			{Title: "NVD - CVE-2025-64513", URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-64513", Source: "NVD"},
			{Title: "GHSA-mhjq-8c7m-3f7p", URL: "https://github.com/milvus-io/milvus/security/advisories/GHSA-mhjq-8c7m-3f7p", Source: "GitHub Advisory"},
		},
		MITRE:       []string{"T1078"},
		Verified:    true,
		Matchable:   true,
		Source:      "CVE/NVD/GitHub Advisory",
		PublishedAt: "2025-11-10",
	}
}

func milvus202626190() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-26190",
		CVE:           "CVE-2026-26190",
		Vendor:        model.VendorMilvus,
		Product:       "milvus",
		Title:         "Milvus unauthenticated REST API access on metrics port 9091",
		TitleZH:       "Milvus 9091 管理端口未授权 REST API 访问漏洞",
		Summary:       "Prior to 2.5.27 and 2.6.10, Milvus exposes TCP port 9091 by default with authentication bypasses. The /expr debug endpoint uses a weak, predictable default authentication token derived from etcd.rootPath, enabling arbitrary expression evaluation. Fixed in 2.5.27 and 2.6.10.",
		SummaryZH:     "2.5.27 与 2.6.10 之前，Milvus 默认开放的 9091 端口存在认证绕过，/expr 调试接口使用可预测的默认令牌，可被用于任意表达式求值。已在 2.5.27 与 2.6.10 修复。",
		Impact:        "Unauthenticated arbitrary expression evaluation on the management port, enabling data manipulation and credential management.",
		ImpactZH:      "未授权即可在管理端口执行任意表达式，可操纵数据与凭据管理。",
		Remediation:   "Upgrade to Milvus 2.5.27 or 2.6.10, or later.",
		RemediationZH: "升级到 Milvus 2.5.27 或 2.6.10 及更高版本。",
		Severity:      model.SeverityCritical,
		CVSS:          model.CVSS{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Version: "3.1"},
		Affected:      []string{"< 2.5.27", ">= 2.6.0, < 2.6.10"},
		References: []model.Reference{
			{Title: "NVD - CVE-2026-26190", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-26190", Source: "NVD"},
			{Title: "GHSA-7ppg-37fh-vcr6", URL: "https://github.com/milvus-io/milvus/security/advisories/GHSA-7ppg-37fh-vcr6", Source: "GitHub Advisory"},
		},
		MITRE:       []string{"T1078"},
		Verified:    true,
		Matchable:   true,
		Source:      "NVD/GitHub Advisory/KEV",
		PublishedAt: "2026-02-13",
	}
}

func milvus202669111() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-69111",
		CVE:           "CVE-2026-69111",
		Vendor:        model.VendorMilvus,
		Product:       "milvus",
		Title:         "Milvus unauthenticated denial of service via /management/stop",
		TitleZH:       "Milvus /management/stop 未授权拒绝服务漏洞",
		Summary:       "Milvus through 2.6.22 and 3.0.0 contains an unauthenticated denial of service vulnerability. Attackers can exploit the unprotected /management/stop endpoint on the management server port 9091 to terminate proxy, datanode, or querynode components. NOTE: this endpoint is advisory-only for vecmap and is never invoked during scans.",
		SummaryZH:     "Milvus 2.6.22 及之前版本与 3.0.0 存在未授权拒绝服务漏洞：9091 管理端口的 /management/stop 接口可被用于终止 proxy、datanode 或 querynode 组件。注意：vecmap 仅做版本关联，绝不请求该接口。",
		Impact:        "Remote unauthenticated termination of Milvus service components, resulting in denial of service.",
		ImpactZH:      "远程未授权终止 Milvus 服务组件，造成拒绝服务。",
		Remediation:   "Upgrade Milvus past 2.6.22 / 3.0.0 and restrict network access to port 9091.",
		RemediationZH: "升级 Milvus（2.6.22 / 3.0.0 之后）并限制 9091 端口的网络访问。",
		Severity:      model.SeverityHigh,
		CVSS:          model.CVSS{Score: 7.5, Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", Version: "4.0"},
		Affected:      []string{"<= 2.6.22", "== 3.0.0"},
		References: []model.Reference{
			{Title: "CVE-2026-69111 (CVE.org)", URL: "https://www.cve.org/CVERecord?id=CVE-2026-69111", Source: "CVE"},
			{Title: "NVD - CVE-2026-69111", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-69111", Source: "NVD"},
		},
		MITRE:       []string{"T1499"},
		Verified:    true,
		Matchable:   true,
		Source:      "CVE/NVD/VulnCheck",
		PublishedAt: "2026-08-05",
	}
}

func weaviate202611500() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-11500",
		CVE:           "CVE-2026-11500",
		Vendor:        model.VendorWeaviate,
		Product:       "weaviate",
		Title:         "Weaviate Static API Key handler authorization bypass",
		TitleZH:       "Weaviate 静态 API Key 处理器授权绕过漏洞",
		Summary:       "A vulnerability in Weaviate up to 1.37.7 affects the validateConfig function of the Static API Key handler. Manipulation of the StaticApiKey argument leads to authorization bypass. Upgrading to 1.38.0-rc.0 resolves the issue.",
		SummaryZH:     "1.37.7 及之前的 Weaviate 静态 API Key 处理器的 validateConfig 存在缺陷，操纵 StaticApiKey 参数可绕过授权。升级到 1.38.0-rc.0 可修复。",
		Impact:        "Authorization bypass in the static API key authentication path.",
		ImpactZH:      "静态 API Key 认证路径存在授权绕过。",
		Remediation:   "Upgrade Weaviate to 1.38.0-rc.0 or later.",
		RemediationZH: "将 Weaviate 升级到 1.38.0-rc.0 或更高版本。",
		Severity:      model.SeverityMedium,
		CVSS:          model.CVSS{Score: 5.0, Version: "3.1"},
		Affected:      []string{"<= 1.37.7"},
		References: []model.Reference{
			{Title: "CVE-2026-11500 (CVE.org)", URL: "https://www.cve.org/CVERecord?id=CVE-2026-11500", Source: "CVE"},
			{Title: "GHSA-jqpm-wf57-qx5c", URL: "https://github.com/advisories/GHSA-jqpm-wf57-qx5c", Source: "GitHub Advisory"},
		},
		MITRE:       []string{"T1078"},
		Verified:    true,
		Matchable:   true,
		Source:      "CVE/VulDB/GitHub Advisory",
		PublishedAt: "2026-06-08",
	}
}

func chroma202692782() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-92782",
		CVE:           "CVE-2026-92782",
		Vendor:        model.VendorChroma,
		Product:       "chroma",
		Title:         "Chroma authorization bypass via collection identifier",
		TitleZH:       "Chroma 集合标识符授权绕过漏洞",
		Summary:       "Chroma through 1.5.9 fails to validate tenant and database segments when resolving collections, allowing authenticated attackers to access collections from other tenants by knowing the collection identifier.",
		SummaryZH:     "1.5.9 及之前的 Chroma 在解析集合时未校验租户与数据库分段，认证攻击者仅凭集合标识即可访问其他租户的集合。",
		Impact:        "Cross-tenant collection access; attackers can read, modify, and update records in foreign collections.",
		ImpactZH:      "可跨租户访问集合，读取、修改并更新其他租户的记录。",
		Remediation:   "Upgrade Chroma beyond 1.5.9 and review multi-tenant isolation.",
		RemediationZH: "升级 Chroma（1.5.9 之后）并检查多租户隔离配置。",
		Severity:      model.SeverityHigh,
		CVSS:          model.CVSS{Score: 8.1, Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", Version: "4.0"},
		Affected:      []string{"<= 1.5.9"},
		References: []model.Reference{
			{Title: "NVD - CVE-2026-92782", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-92782", Source: "NVD"},
			{Title: "VulnCheck advisory", URL: "https://www.vulncheck.com/advisories/chroma-through-1.5.9-authorization-bypass-via-collection-identifier", Source: "VulnCheck"},
			{Title: "chroma issue #7462", URL: "https://github.com/chroma-core/chroma/issues/7462", Source: "GitHub"},
		},
		MITRE:       []string{"T1078"},
		Verified:    true,
		Matchable:   true,
		Source:      "NVD/VulnCheck",
		PublishedAt: "2026-09-16",
	}
}

func chroma202645829() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-45829",
		CVE:           "CVE-2026-45829",
		Vendor:        model.VendorChroma,
		Product:       "chroma",
		Title:         "ChromaDB pre-authentication code injection (ChromaToast)",
		TitleZH:       "ChromaDB 预认证代码注入漏洞（ChromaToast）",
		Summary:       "A pre-authentication code injection vulnerability in version 1.0.0 or later of the ChromaDB Python project allows an unauthenticated attacker to run arbitrary code on the server by sending a malicious model repository with trust_remote_code set to true on the collection creation endpoint.",
		SummaryZH:     "ChromaDB 1.0.0 及之后版本存在预认证代码注入漏洞，未授权攻击者可在集合创建接口提交恶意模型仓库（trust_remote_code=true）实现服务器任意代码执行。",
		Impact:        "CVSS 10.0 pre-authentication remote code execution and full server compromise.",
		ImpactZH:      "CVSS 10.0 预认证远程代码执行，服务器可被完全接管。",
		Remediation:   "Upgrade ChromaDB, disable trust_remote_code, and restrict network access to the API port.",
		RemediationZH: "升级 ChromaDB、禁用 trust_remote_code，并限制 API 端口的网络访问。",
		Severity:      model.SeverityCritical,
		CVSS:          model.CVSS{Score: 9.3, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Version: "3.1"},
		Affected:      []string{">= 1.0.0, <= 1.5.9"},
		References: []model.Reference{
			{Title: "CVE-2026-45829 (CVE.org)", URL: "https://www.cve.org/CVERecord?id=CVE-2026-45829", Source: "CVE"},
			{Title: "GHSA-f4j7-r4q5-qw2c", URL: "https://github.com/advisories/GHSA-f4j7-r4q5-qw2c", Source: "GitHub Advisory"},
			{Title: "CSA research note", URL: "https://labs.cloudsecurityalliance.org/research/csa-research-note-chromadb-rce-ai-infrastructure-security-20", Source: "CSA"},
		},
		MITRE:       []string{"T1059", "T1210"},
		Verified:    true,
		Matchable:   true,
		Source:      "CVE/NVD/GitHub Advisory",
		PublishedAt: "2026-05-18",
	}
}

func typesense202647216() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-47216",
		CVE:           "CVE-2026-47216",
		Vendor:        model.VendorTypesense,
		Product:       "typesense",
		Title:         "Typesense unauthenticated denial of service in /multi_search",
		TitleZH:       "Typesense /multi_search 未授权拒绝服务漏洞",
		Summary:       "Prior to versions 29.1 and 30.2, there is an unauthenticated denial-of-service vulnerability in the /multi_search endpoint. A specially crafted request can trigger an unhandled exception, terminating the server process. Patched in 29.1 and 30.2.",
		SummaryZH:     "29.1 与 30.2 之前，/multi_search 接口存在未授权拒绝服务漏洞，构造的请求可触发未处理异常导致服务进程终止。已在 29.1 与 30.2 修复。",
		Impact:        "Unauthenticated remote termination of the Typesense server process.",
		ImpactZH:      "未授权远程终止 Typesense 服务进程。",
		Remediation:   "Upgrade Typesense to 29.1 or 30.2, or later.",
		RemediationZH: "升级 Typesense 到 29.1 或 30.2 及更高版本。",
		Severity:      model.SeverityHigh,
		CVSS:          model.CVSS{Score: 8.7, Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", Version: "4.0"},
		Affected:      []string{"< 29.1", ">= 30.0, < 30.2"},
		References: []model.Reference{
			{Title: "NVD - CVE-2026-47216", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-47216", Source: "NVD"},
			{Title: "GHSA-fpx5-8c99-247j", URL: "https://github.com/typesense/typesense/security/advisories/GHSA-fpx5-8c99-247j", Source: "GitHub Advisory"},
		},
		MITRE:       []string{"T1499"},
		Verified:    true,
		Matchable:   true,
		Source:      "NVD/GitHub Advisory",
		PublishedAt: "2026-06-12",
	}
}

func typesense202647225() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2026-47225",
		CVE:           "CVE-2026-47225",
		Vendor:        model.VendorTypesense,
		Product:       "typesense",
		Title:         "Typesense search cache isolation flaw with scoped API keys",
		TitleZH:       "Typesense 作用域 API Key 搜索结果缓存隔离缺陷",
		Summary:       "Prior to versions 29.1 and 30.2, there is a cache isolation issue affecting search requests that use both server-side search result caching and Scoped Search API Keys. Cached results could be reused across requests with different key constraints. Patched in 29.1 and 30.2.",
		SummaryZH:     "29.1 与 30.2 之前，同时启用服务端结果缓存与作用域 API Key 时存在缓存隔离缺陷，缓存结果可能跨越不同的 Key 约束被复用。已在 29.1 与 30.2 修复。",
		Impact:        "Cross-scope information disclosure of cached search results.",
		ImpactZH:      "缓存搜索结果可跨作用域泄露受限数据。",
		Remediation:   "Upgrade Typesense to 29.1 or 30.2, or disable server-side search result caching.",
		RemediationZH: "升级 Typesense 到 29.1 或 30.2，或禁用服务端搜索结果缓存。",
		Severity:      model.SeverityMedium,
		CVSS:          model.CVSS{Vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", Version: "4.0"},
		Affected:      []string{"< 29.1", ">= 30.0, < 30.2"},
		References: []model.Reference{
			{Title: "NVD - CVE-2026-47225", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-47225", Source: "NVD"},
			{Title: "GHSA-97x4-gm45-jpcw", URL: "https://github.com/typesense/typesense/security/advisories/GHSA-97x4-gm45-jpcw", Source: "GitHub Advisory"},
		},
		MITRE:       []string{"T1213"},
		Verified:    true,
		Matchable:   true,
		Source:      "NVD/GitHub Advisory",
		PublishedAt: "2026-06-12",
	}
}

func log4j202144228() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2021-44228",
		CVE:           "CVE-2021-44228",
		CNVD:          "CNVD-2021-95914",
		Vendor:        model.VendorApache,
		Product:       "log4j2",
		Title:         "Apache Log4j2 JNDI remote code execution (Log4Shell)",
		TitleZH:       "Apache Log4j2 JNDI 远程代码执行漏洞（Log4Shell）",
		Summary:       "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) is vulnerable to JNDI injection in log messages, enabling unauthenticated remote code execution. CNVD tracked this issue as CNVD-2021-95914.",
		SummaryZH:     "Apache Log4j2 2.0-beta9 至 2.15.0（不含 2.12.2、2.12.3、2.3.1 安全版本）存在 JNDI 注入缺陷，可被未授权利用实现远程代码执行。CNVD 编号为 CNVD-2021-95914。",
		Impact:        "Unauthenticated remote code execution on systems using vulnerable Log4j2.",
		ImpactZH:      "使用受影响 Log4j2 组件的系统可被未授权远程执行代码。",
		Remediation:   "Upgrade Log4j2 to 2.17.1 or later; apply vendor-specific patches for bundled products.",
		RemediationZH: "升级 Log4j2 至 2.17.1 及以上；针对内置组件产品应用厂商补丁。",
		Severity:      model.SeverityCritical,
		CVSS:          model.CVSS{Score: 10.0, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Version: "3.1"},
		Affected:      []string{">= 2.0-beta9, <= 2.15.0"},
		References: []model.Reference{
			{Title: "NVD - CVE-2021-44228", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", Source: "NVD"},
			{Title: "CNVD-2021-95914", URL: "https://www.cnvd.org.cn/flaw/show/CNVD-2021-95914", Source: "CNVD"},
			{Title: "CNCERT 公告", URL: "https://www.cert.org.cn/publish/main/9/2021/20211210110550958546708/20211210110550958546708_.html", Source: "CNCERT"},
		},
		MITRE:       []string{"T1210", "T1059"},
		Verified:    true,
		Matchable:   false,
		Source:      "NVD/CNVD/CNCERT",
		PublishedAt: "2021-12-10",
	}
}

func redis20220543() model.Advisory {
	return model.Advisory{
		ID:            "CVE-2022-0543",
		CVE:           "CVE-2022-0543",
		Vendor:        model.VendorRedis,
		Product:       "redis",
		Title:         "Redis Lua sandbox escape (Debian/Ubuntu packaging)",
		TitleZH:       "Redis Lua 沙箱逃逸漏洞（Debian/Ubuntu 打包问题）",
		Summary:       "Redis on Debian/Ubuntu prior to 6.2.6 was vulnerable to a Lua sandbox escape that allowed remote code execution. The flaw stems from Debian-specific packaging, not upstream Redis.",
		SummaryZH:     "Debian/Ubuntu 打包的 Redis 6.2.6 之前版本存在 Lua 沙箱逃逸，可导致远程代码执行；该缺陷源于发行版打包，而非上游 Redis 代码。",
		Impact:        "Remote code execution on vulnerable Debian/Ubuntu-packaged Redis deployments.",
		ImpactZH:      "受影响的 Debian/Ubuntu Redis 部署可被远程执行代码。",
		Remediation:   "Upgrade the distribution-packaged Redis or switch to the upstream build.",
		RemediationZH: "升级发行版打包的 Redis，或改用上游官方构建。",
		Severity:      model.SeverityCritical,
		CVSS:          model.CVSS{Score: 10.0, Version: "3.1"},
		Affected:      []string{"< 6.2.6"},
		References: []model.Reference{
			{Title: "NVD - CVE-2022-0543", URL: "https://nvd.nist.gov/vuln/detail/CVE-2022-0543", Source: "NVD"},
		},
		MITRE:       []string{"T1059"},
		Verified:    true,
		Matchable:   false,
		Source:      "NVD",
		PublishedAt: "2022-02-18",
	}
}

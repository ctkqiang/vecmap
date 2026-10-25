package utilities

import "fmt"

// englishMessages 保存英文消息目录。
var englishMessages = map[string]string{
	"finding.unauth_api.title":             "Unauthenticated enumeration endpoint exposed",
	"finding.unauth_api.desc":              "A collection, schema, or index enumeration endpoint returned data without authentication. Attackers can inventory the full vector database without credentials.",
	"finding.unauth_api.impact":            "Full schema and collection disclosure enables targeted extraction, model inversion, and business logic abuse.",
	"finding.unauth_api.remediation":       "Enable authentication and authorization on the management API and restrict it to trusted networks.",
	"finding.unauth_extract.desc":          "Unauthenticated access allowed extraction of stored records",
	"finding.unauth_extract.title":         "Unauthenticated record extraction",
	"finding.unauth_extract.impact":        "Stored documents, metadata, and vector embeddings can be exfiltrated anonymously.",
	"finding.unauth_extract.remediation":   "Require authentication for read APIs and enforce per-collection authorization.",
	"finding.metrics.title":                "Metrics endpoint exposed without authentication",
	"finding.metrics.desc":                 "The metrics endpoint is reachable anonymously and discloses operational counters and resource usage.",
	"finding.metrics.impact":               "Operational intelligence disclosure assists further attacks and capacity planning for denial of service.",
	"finding.metrics.remediation":          "Restrict or authenticate the metrics endpoint and bind it to a management network.",
	"finding.docs.title":                   "API documentation endpoint exposed",
	"finding.docs.desc":                    "API documentation or OpenAPI schemas are served without authentication.",
	"finding.docs.impact":                  "Documentation accelerates discovery of API routes and parameters for further enumeration.",
	"finding.docs.remediation":             "Disable documentation endpoints in production or require authentication.",
	"finding.exposed_snapshot.title":       "Snapshot or backup listing exposed",
	"finding.exposed_snapshot.desc":        "Snapshot or backup metadata is readable without authentication.",
	"finding.exposed_snapshot.impact":      "Snapshot exposure can reveal full data-set copies and recovery paths.",
	"finding.exposed_snapshot.remediation": "Require authentication for snapshot APIs and restrict listing.",
	"finding.cors.title":                   "Permissive CORS configuration with credentials",
	"finding.cors.desc":                    "The service reflects arbitrary origins and allows credentialed cross-origin reads.",
	"finding.cors.impact":                  "Browsers of authenticated users can be abused to read API responses cross-origin.",
	"finding.cors.remediation":             "Restrict Access-Control-Allow-Origin to trusted origins and disable credentialed wildcard.",
	"finding.exposure.title":               "Operational endpoint exposure",
	"finding.exposure.desc":                "Stats, status, telemetry, or cluster endpoints are readable without authentication.",
	"finding.exposure.impact":              "Cluster topology and operational state disclosure support further attacks.",
	"finding.exposure.remediation":         "Authenticate operational endpoints and restrict them to management networks.",
	"finding.grpc_reflection.title":        "gRPC server reflection enabled",
	"finding.grpc_reflection.desc":         "The gRPC endpoint exposes server reflection, disclosing the full service and method inventory.",
	"finding.grpc_reflection.impact":       "Complete RPC surface disclosure enables targeted enumeration and abuse of exported methods.",
	"finding.grpc_reflection.remediation":  "Disable gRPC reflection in production or restrict it to authorized callers.",
	"finding.tls.title":                    "Cleartext management endpoint",
	"finding.tls.desc":                     "The vector database management endpoint is served over plaintext HTTP.",
	"finding.tls.impact":                   "Credentials and extracted data can be intercepted on the network path.",
	"finding.tls.remediation":              "Enable TLS and redirect or reject plaintext connections.",
	"finding.advisory.title":               "Vulnerable version: %s",
	"finding.advisory.desc":                "Identified version %s matches advisory %s.",
	"finding.advisory.remediation":         "Apply the vendor patch or upgrade documented in the advisory.",
	"msg.scan.start":                       "Scanning %d target(s)",
	"msg.scan.done":                        "Scan finished in %s: %d finding(s)",
	"msg.discovery.start":                  "Discovering %d host(s) on %d port(s)",
	"msg.discovery.done":                   "Discovery finished in %s: %d open port(s)",
	"msg.scope.denied":                     "target %s is outside the authorized scope",
	"msg.session.created":                  "Session %s created",
	"msg.report.written":                   "Report written to %s",
	"msg.no.findings":                      "No findings were produced for this session",
	"msg.advisories.count":                 "%d verified advisory entries loaded",
	"msg.session.deleted":                  "Session %s deleted",
	"msg.not.found":                        "Session %s not found",
	"msg.records.extracted":                "%d record(s) extracted across %d collection(s)",
	"err.authorization":                    "This tool requires explicit authorization for the target scope",
	"report.title":                         "Vector Database Attack-Surface Assessment Report",
	"report.session":                       "Session",
	"report.generated":                     "Generated",
	"report.started":                       "Started",
	"report.ended":                         "Ended",
	"report.duration":                      "Duration",
	"report.summary":                       "Risk Summary",
	"report.findings":                      "Findings",
	"report.targets":                       "Targets",
	"report.collections":                   "Collections",
	"report.records":                       "Extracted Records",
	"report.mitre":                         "MITRE ATT&CK Coverage",
	"report.appendix":                      "Evidence Appendix",
	"report.advisories":                    "Referenced Advisories",
	"report.none":                          "None",
	"report.severity.critical":             "Critical",
	"report.severity.high":                 "High",
	"report.severity.medium":               "Medium",
	"report.severity.low":                  "Low",
	"report.severity.info":                 "Info",
	"report.records.count":                 "%d record(s)",
	"report.vectors.count":                 "%d vector(s)",
	"report.points.count":                  "%d point(s)",
	"report.evidence":                      "Evidence",
	"report.references":                    "References",
	"report.remediation":                   "Remediation",
	"report.impact":                        "Impact",
	"report.confidence":                    "Confidence",
	"report.field.target":                  "Target",
	"report.field.vendor":                  "Vendor",
	"report.field.product":                 "Product",
	"report.field.version":                 "Version",
	"report.field.auth":                    "Auth",
	"report.field.transport":               "Transport",
	"report.field.collection":              "Collection",
	"report.field.namespace":               "Namespace",
	"report.field.dimension":               "Dimension",
	"report.field.metric":                  "Metric",
	"report.field.index":                   "Index",
	"report.field.external_id":             "External ID",
	"report.field.method":                  "Method",
	"report.field.path":                    "Path",
	"report.field.status":                  "Status",
	"report.field.bytes":                   "Bytes",
	"report.field.hash":                    "SHA-256",
	"report.field.points":                  "Points",
}

// chineseMessages 保存中文消息目录。
var chineseMessages = map[string]string{
	"finding.unauth_api.title":             "未授权枚举接口暴露",
	"finding.unauth_api.desc":              "集合、模式或索引枚举接口在未认证状态下返回数据，攻击者无需凭据即可完整盘点向量数据库。",
	"finding.unauth_api.impact":            "完整模式与集合清单泄露，可用于定向提取、模型反演与业务逻辑滥用。",
	"finding.unauth_api.remediation":       "为管理 API 启用认证与授权，并限制为可信网络访问。",
	"finding.unauth_extract.desc":          "未授权访问允许提取已存储的记录",
	"finding.unauth_extract.title":         "未授权记录提取",
	"finding.unauth_extract.impact":        "存储的文档、元数据与向量嵌入可被匿名批量导出。",
	"finding.unauth_extract.remediation":   "对读取 API 强制认证，并实施集合级授权。",
	"finding.metrics.title":                "指标接口未认证暴露",
	"finding.metrics.desc":                 "指标接口可匿名访问，泄露运行计数与资源使用情况。",
	"finding.metrics.impact":               "运行情报泄露可辅助进一步攻击与拒绝服务容量评估。",
	"finding.metrics.remediation":          "对指标接口实施认证或限网，绑定管理网络。",
	"finding.docs.title":                   "API 文档接口暴露",
	"finding.docs.desc":                    "API 文档或 OpenAPI 模式无需认证即可访问。",
	"finding.docs.impact":                  "文档加速 API 路由与参数的发现，便利后续枚举。",
	"finding.docs.remediation":             "生产环境关闭文档接口或要求认证。",
	"finding.exposed_snapshot.title":       "快照或备份清单暴露",
	"finding.exposed_snapshot.desc":        "快照或备份元数据无需认证即可读取。",
	"finding.exposed_snapshot.impact":      "快照暴露可泄露完整数据集副本与恢复路径。",
	"finding.exposed_snapshot.remediation": "对快照 API 强制认证并限制列表能力。",
	"finding.cors.title":                   "宽松 CORS 配置（携带凭据）",
	"finding.cors.desc":                    "服务反射任意 Origin 并允许携带凭据的跨域读取。",
	"finding.cors.impact":                  "已认证用户的浏览器可被利用跨域读取 API 响应。",
	"finding.cors.remediation":             "将 Access-Control-Allow-Origin 限制为可信来源，禁用凭据通配。",
	"finding.exposure.title":               "运行状态接口暴露",
	"finding.exposure.desc":                "统计、状态、遥测或集群接口无需认证即可读取。",
	"finding.exposure.impact":              "集群拓扑与运行状态泄露，可支持进一步攻击。",
	"finding.exposure.remediation":         "为运行状态接口启用认证并限制为管理网络。",
	"finding.grpc_reflection.title":        "gRPC 服务反射已开启",
	"finding.grpc_reflection.desc":         "gRPC 端点暴露服务反射，可获取完整服务与方法清单。",
	"finding.grpc_reflection.impact":       "完整 RPC 攻击面泄露，可定向枚举与滥用导出方法。",
	"finding.grpc_reflection.remediation":  "生产环境关闭 gRPC 反射或限制为授权调用方。",
	"finding.tls.title":                    "明文管理端点",
	"finding.tls.desc":                     "向量数据库管理端点使用明文 HTTP 提供服务。",
	"finding.tls.impact":                   "凭据与提取数据可在网络路径上被截获。",
	"finding.tls.remediation":              "启用 TLS 并重定向或拒绝明文连接。",
	"finding.advisory.title":               "存在已知漏洞的版本：%s",
	"finding.advisory.desc":                "识别到的版本 %s 命中公告 %s。",
	"finding.advisory.remediation":         "按公告指引应用厂商补丁或升级版本。",
	"msg.scan.start":                       "正在扫描 %d 个目标",
	"msg.scan.done":                        "扫描完成，耗时 %s：%d 条发现",
	"msg.discovery.start":                  "正在发现 %d 个主机、%d 个端口",
	"msg.discovery.done":                   "发现完成，耗时 %s：%d 个开放端口",
	"msg.scope.denied":                     "目标 %s 超出授权范围",
	"msg.session.created":                  "会话 %s 已创建",
	"msg.report.written":                   "报告已写入 %s",
	"msg.no.findings":                      "本次会话未产生任何发现",
	"msg.advisories.count":                 "已加载 %d 条经校验的漏洞公告",
	"msg.session.deleted":                  "会话 %s 已删除",
	"msg.not.found":                        "会话 %s 不存在",
	"msg.records.extracted":                "已提取 %d 条记录（%d 个集合）",
	"err.authorization":                    "使用本工具必须获得目标范围的明确授权",
	"report.title":                         "向量数据库攻击面评估报告",
	"report.session":                       "会话",
	"report.generated":                     "生成时间",
	"report.started":                       "开始时间",
	"report.ended":                         "结束时间",
	"report.duration":                      "耗时",
	"report.summary":                       "风险汇总",
	"report.findings":                      "风险发现",
	"report.targets":                       "目标清单",
	"report.collections":                   "集合清单",
	"report.records":                       "提取记录",
	"report.mitre":                         "MITRE ATT&CK 覆盖",
	"report.appendix":                      "证据附录",
	"report.advisories":                    "引用公告",
	"report.none":                          "无",
	"report.severity.critical":             "严重",
	"report.severity.high":                 "高危",
	"report.severity.medium":               "中危",
	"report.severity.low":                  "低危",
	"report.severity.info":                 "信息",
	"report.records.count":                 "%d 条记录",
	"report.vectors.count":                 "%d 条向量",
	"report.points.count":                  "%d 个点",
	"report.evidence":                      "证据",
	"report.references":                    "参考资料",
	"report.remediation":                   "修复建议",
	"report.impact":                        "影响",
	"report.confidence":                    "可信度",
	"report.field.target":                  "目标",
	"report.field.vendor":                  "厂商",
	"report.field.product":                 "产品",
	"report.field.version":                 "版本",
	"report.field.auth":                    "认证",
	"report.field.transport":               "传输协议",
	"report.field.collection":              "集合",
	"report.field.namespace":               "命名空间",
	"report.field.dimension":               "维度",
	"report.field.metric":                  "度量",
	"report.field.index":                   "索引",
	"report.field.external_id":             "外部 ID",
	"report.field.method":                  "方法",
	"report.field.path":                    "路径",
	"report.field.status":                  "状态码",
	"report.field.bytes":                   "字节数",
	"report.field.hash":                    "SHA-256",
	"report.field.points":                  "点数",
}

// T 返回本地化文本。
//
// 参数 key 为消息键；缺失时返回键本身，避免界面出现空文本。
func T(key string) string {
	if value, exists := englishMessages[key]; exists {
		return value
	}
	return key
}

// Tf 返回格式化后的本地化文本。
//
// 参数 key 为消息键，args 为格式化参数。
// 返回使用 fmt.Sprintf 处理后的文本。
func Tf(key string, args ...any) string {
	return fmt.Sprintf(T(key), args...)
}

// TIn 返回指定语言的本地化文本。
//
// 参数 lang 为 en 或 zh，key 为消息键。
// 返回指定语言的文本；缺失时回退英文，再回退键本身。
func TIn(lang, key string) string {
	if lang == "zh" {
		if value, exists := chineseMessages[key]; exists {
			return value
		}
	}
	if value, exists := englishMessages[key]; exists {
		return value
	}
	return key
}

// TfIn 返回指定语言的格式化本地化文本。
//
// 参数 lang 为 en 或 zh，key 为消息键，args 为格式化参数。
// 返回使用 fmt.Sprintf 处理后的指定语言文本。
func TfIn(lang, key string, args ...any) string {
	return fmt.Sprintf(TIn(lang, key), args...)
}

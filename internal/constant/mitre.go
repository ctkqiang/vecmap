package constant

import "github.com/ctkqiang/vecmap/internal/model"

// MITRE 战术常量。
const (
	// TacticReconnaissance 表示侦察战术。
	TacticReconnaissance = "Reconnaissance"
	// TacticResourceDevelopment 表示资源开发战术。
	TacticResourceDevelopment = "Resource Development"
	// TacticInitialAccess 表示初始访问战术。
	TacticInitialAccess = "Initial Access"
	// TacticExecution 表示执行战术。
	TacticExecution = "Execution"
	// TacticPersistence 表示持久化战术。
	TacticPersistence = "Persistence"
	// TacticPrivilegeEscalation 表示权限提升战术。
	TacticPrivilegeEscalation = "Privilege Escalation"
	// TacticDefenseEvasion 表示防御规避战术。
	TacticDefenseEvasion = "Defense Evasion"
	// TacticCredentialAccess 表示凭据访问战术。
	TacticCredentialAccess = "Credential Access"
	// TacticDiscovery 表示发现战术。
	TacticDiscovery = "Discovery"
	// TacticLateralMovement 表示横向移动战术。
	TacticLateralMovement = "Lateral Movement"
	// TacticCollection 表示收集战术。
	TacticCollection = "Collection"
	// TacticCommandAndControl 表示命令与控制战术。
	TacticCommandAndControl = "Command and Control"
	// TacticExfiltration 表示渗出战术。
	TacticExfiltration = "Exfiltration"
	// TacticImpact 表示影响战术。
	TacticImpact = "Impact"
)

// mitre 是内置的 MITRE ATT&CK 技术目录构造器。
//
// 参数 id、name、nameZH、tactic、tacticZH 分别对应技术编号、英文名、
// 中文名、所属战术与中文战术名；URL 按官方模式自动生成。
func mitre(id, name, nameZH, tactic, tacticZH string) model.MITRETechnique {
	return model.MITRETechnique{
		ID:       id,
		Name:     name,
		NameZH:   nameZH,
		Tactic:   tactic,
		TacticZH: tacticZH,
		URL:      mitreURL(id),
	}
}

// mitreURL 生成官方技术页面 URL。
//
// 参数 id 为技术编号；返回形如 /techniques/T1595/002/ 的路径。
func mitreURL(id string) string {
	base := "https://attack.mitre.org/techniques/"
	dot := indexOf(id, ".")
	if dot < 0 {
		return base + id + "/"
	}
	return base + id[:dot] + "/" + id[dot+1:] + "/"
}

// mitreCatalog 保存内置的 MITRE ATT&CK 技术条目。
//
// 目录覆盖侦察、资源开发、初始访问、执行、持久化、权限提升、防御规避、
// 凭据访问、发现、横向移动、收集、命令与控制、渗出与影响 14 个战术。
var mitreCatalog = map[string]model.MITRETechnique{
	// 侦察
	"T1595":     mitre("T1595", "Active Scanning", "主动扫描", TacticReconnaissance, "侦察"),
	"T1595.002": mitre("T1595.002", "Active Scanning: Vulnerability Scanning", "主动扫描：漏洞扫描", TacticReconnaissance, "侦察"),
	"T1592":     mitre("T1592", "Gather Victim Host Information", "收集受害主机信息", TacticReconnaissance, "侦察"),
	"T1590":     mitre("T1590", "Gather Victim Network Information", "收集受害网络信息", TacticReconnaissance, "侦察"),
	"T1593":     mitre("T1593", "Search Open Websites/Domains", "搜索公开网站与域名", TacticReconnaissance, "侦察"),
	"T1594":     mitre("T1594", "Search Victim-Owned Websites", "搜索受害方自有网站", TacticReconnaissance, "侦察"),
	"T1589":     mitre("T1589", "Gather Victim Identity Information", "收集受害身份信息", TacticReconnaissance, "侦察"),
	// 资源开发
	"T1588": mitre("T1588", "Obtain Capabilities", "获取攻击能力", TacticResourceDevelopment, "资源开发"),
	"T1583": mitre("T1583", "Acquire Infrastructure", "获取基础设施", TacticResourceDevelopment, "资源开发"),
	"T1586": mitre("T1586", "Compromise Accounts", "攻陷账户", TacticResourceDevelopment, "资源开发"),
	"T1587": mitre("T1587", "Develop Capabilities", "开发攻击能力", TacticResourceDevelopment, "资源开发"),
	// 初始访问
	"T1078": mitre("T1078", "Valid Accounts", "有效账户", TacticInitialAccess, "初始访问"),
	"T1190": mitre("T1190", "Exploit Public-Facing Application", "利用面向公众的应用", TacticInitialAccess, "初始访问"),
	"T1133": mitre("T1133", "External Remote Services", "外部远程服务", TacticInitialAccess, "初始访问"),
	"T1199": mitre("T1199", "Trusted Relationship", "信任关系", TacticInitialAccess, "初始访问"),
	"T1566": mitre("T1566", "Phishing", "钓鱼攻击", TacticInitialAccess, "初始访问"),
	"T1189": mitre("T1189", "Drive-by Compromise", "路过式攻击", TacticInitialAccess, "初始访问"),
	// 执行
	"T1059":     mitre("T1059", "Command and Scripting Interpreter", "命令与脚本解释器", TacticExecution, "执行"),
	"T1059.001": mitre("T1059.001", "Command and Scripting Interpreter: PowerShell", "命令与脚本解释器：PowerShell", TacticExecution, "执行"),
	"T1059.004": mitre("T1059.004", "Command and Scripting Interpreter: Unix Shell", "命令与脚本解释器：Unix Shell", TacticExecution, "执行"),
	"T1203":     mitre("T1203", "Exploitation for Client Execution", "客户端执行利用", TacticExecution, "执行"),
	"T1204":     mitre("T1204", "User Execution", "用户执行", TacticExecution, "执行"),
	// 持久化
	"T1098": mitre("T1098", "Account Manipulation", "账户操纵", TacticPersistence, "持久化"),
	"T1505": mitre("T1505", "Server Software Component", "服务器软件组件", TacticPersistence, "持久化"),
	"T1136": mitre("T1136", "Create Account", "创建账户", TacticPersistence, "持久化"),
	"T1554": mitre("T1554", "Compromise Host Software Binary", "攻陷主机软件二进制", TacticPersistence, "持久化"),
	// 权限提升
	"T1068": mitre("T1068", "Exploitation for Privilege Escalation", "提权利用", TacticPrivilegeEscalation, "权限提升"),
	"T1548": mitre("T1548", "Abuse Elevation Control Mechanism", "滥用权限提升控制机制", TacticPrivilegeEscalation, "权限提升"),
	// 防御规避
	"T1070": mitre("T1070", "Indicator Removal", "痕迹清除", TacticDefenseEvasion, "防御规避"),
	"T1027": mitre("T1027", "Obfuscated Files or Information", "文件或信息混淆", TacticDefenseEvasion, "防御规避"),
	"T1562": mitre("T1562", "Impair Defenses", "削弱防御", TacticDefenseEvasion, "防御规避"),
	"T1218": mitre("T1218", "System Binary Proxy Execution", "系统二进制代理执行", TacticDefenseEvasion, "防御规避"),
	// 凭据访问
	"T1555": mitre("T1555", "Credentials from Password Stores", "从密码库获取凭据", TacticCredentialAccess, "凭据访问"),
	"T1110": mitre("T1110", "Brute Force", "暴力破解", TacticCredentialAccess, "凭据访问"),
	"T1040": mitre("T1040", "Network Sniffing", "网络嗅探", TacticCredentialAccess, "凭据访问"),
	"T1003": mitre("T1003", "OS Credential Dumping", "操作系统凭据转储", TacticCredentialAccess, "凭据访问"),
	"T1552": mitre("T1552", "Unsecured Credentials", "未保护的凭据", TacticCredentialAccess, "凭据访问"),
	"T1528": mitre("T1528", "Steal Application Access Token", "窃取应用访问令牌", TacticCredentialAccess, "凭据访问"),
	"T1556": mitre("T1556", "Modify Authentication Process", "修改认证流程", TacticCredentialAccess, "凭据访问"),
	// 发现
	"T1046": mitre("T1046", "Network Service Discovery", "网络服务发现", TacticDiscovery, "发现"),
	"T1083": mitre("T1083", "File and Directory Discovery", "文件与目录发现", TacticDiscovery, "发现"),
	"T1082": mitre("T1082", "System Information Discovery", "系统信息发现", TacticDiscovery, "发现"),
	"T1087": mitre("T1087", "Account Discovery", "账户发现", TacticDiscovery, "发现"),
	"T1018": mitre("T1018", "Remote System Discovery", "远程系统发现", TacticDiscovery, "发现"),
	"T1007": mitre("T1007", "System Service Discovery", "系统服务发现", TacticDiscovery, "发现"),
	"T1217": mitre("T1217", "Browser Information Discovery", "浏览器信息发现", TacticDiscovery, "发现"),
	"T1120": mitre("T1120", "Peripheral Device Discovery", "外设发现", TacticDiscovery, "发现"),
	// 横向移动
	"T1210":     mitre("T1210", "Exploitation of Remote Services", "远程服务利用", TacticLateralMovement, "横向移动"),
	"T1021":     mitre("T1021", "Remote Services", "远程服务", TacticLateralMovement, "横向移动"),
	"T1021.001": mitre("T1021.001", "Remote Services: Remote Desktop Protocol", "远程服务：远程桌面协议", TacticLateralMovement, "横向移动"),
	"T1080":     mitre("T1080", "Taint Shared Content", "污染共享内容", TacticLateralMovement, "横向移动"),
	"T1550":     mitre("T1550", "Use Alternate Authentication Material", "使用替代认证材料", TacticLateralMovement, "横向移动"),
	"T1570":     mitre("T1570", "Lateral Tool Transfer", "横向工具传输", TacticLateralMovement, "横向移动"),
	// 收集
	"T1213": mitre("T1213", "Data from Information Repositories", "从信息库收集数据", TacticCollection, "收集"),
	"T1005": mitre("T1005", "Data from Local System", "从本地系统收集数据", TacticCollection, "收集"),
	"T1119": mitre("T1119", "Automated Collection", "自动收集", TacticCollection, "收集"),
	"T1530": mitre("T1530", "Data from Cloud Storage Object", "从云存储对象收集数据", TacticCollection, "收集"),
	"T1113": mitre("T1113", "Screen Capture", "屏幕捕获", TacticCollection, "收集"),
	"T1123": mitre("T1123", "Audio Capture", "音频捕获", TacticCollection, "收集"),
	"T1074": mitre("T1074", "Data Staged", "数据暂存", TacticCollection, "收集"),
	"T1557": mitre("T1557", "Adversary-in-the-Middle", "中间人攻击", TacticCollection, "收集"),
	"T1185": mitre("T1185", "Browser Session Hijacking", "浏览器会话劫持", TacticCollection, "收集"),
	"T1114": mitre("T1114", "Email Collection", "邮件收集", TacticCollection, "收集"),
	"T1560": mitre("T1560", "Archive Collected Data", "归档收集的数据", TacticCollection, "收集"),
	// 命令与控制
	"T1071": mitre("T1071", "Application Layer Protocol", "应用层协议", TacticCommandAndControl, "命令与控制"),
	"T1090": mitre("T1090", "Proxy", "代理", TacticCommandAndControl, "命令与控制"),
	"T1572": mitre("T1572", "Protocol Tunneling", "协议隧道", TacticCommandAndControl, "命令与控制"),
	"T1105": mitre("T1105", "Ingress Tool Transfer", "工具传入", TacticCommandAndControl, "命令与控制"),
	"T1132": mitre("T1132", "Data Encoding", "数据编码", TacticCommandAndControl, "命令与控制"),
	"T1573": mitre("T1573", "Encrypted Channel", "加密信道", TacticCommandAndControl, "命令与控制"),
	"T1102": mitre("T1102", "Web Service", "Web 服务", TacticCommandAndControl, "命令与控制"),
	// 渗出
	"T1567": mitre("T1567", "Exfiltration Over Web Service", "通过 Web 服务渗出", TacticExfiltration, "渗出"),
	"T1041": mitre("T1041", "Exfiltration Over C2 Channel", "通过 C2 信道渗出", TacticExfiltration, "渗出"),
	"T1048": mitre("T1048", "Exfiltration Over Alternative Protocol", "通过替代协议渗出", TacticExfiltration, "渗出"),
	"T1020": mitre("T1020", "Automated Exfiltration", "自动渗出", TacticExfiltration, "渗出"),
	"T1011": mitre("T1011", "Exfiltration Over Other Network Medium", "通过其他网络介质渗出", TacticExfiltration, "渗出"),
	"T1052": mitre("T1052", "Exfiltration Over Physical Medium", "通过物理介质渗出", TacticExfiltration, "渗出"),
	// 影响
	"T1499": mitre("T1499", "Endpoint Denial of Service", "端点拒绝服务", TacticImpact, "影响"),
	"T1485": mitre("T1485", "Data Destruction", "数据销毁", TacticImpact, "影响"),
	"T1486": mitre("T1486", "Data Encrypted for Impact", "数据加密勒索", TacticImpact, "影响"),
	"T1490": mitre("T1490", "Inhibit System Recovery", "抑制系统恢复", TacticImpact, "影响"),
	"T1489": mitre("T1489", "Service Stop", "服务停止", TacticImpact, "影响"),
	"T1491": mitre("T1491", "Defacement", "页面篡改", TacticImpact, "影响"),
	"T1496": mitre("T1496", "Resource Hijacking", "资源劫持", TacticImpact, "影响"),
	"T1531": mitre("T1531", "Account Access Removal", "账户访问移除", TacticImpact, "影响"),
}

// MITRETechniques 返回内置 MITRE ATT&CK 技术目录。
//
// 返回值为按技术编号稳定排序的切片副本。
func MITRETechniques() []model.MITRETechnique {
	result := make([]model.MITRETechnique, 0, len(mitreCatalog))
	for _, technique := range mitreCatalog {
		result = append(result, technique)
	}
	sortMITRE(result)
	return result
}

// MITREByID 按编号查找 MITRE 技术。
//
// 参数 id 为技术编号，例如 T1595 或 T1595.002。
// 返回技术条目与是否存在标志。
func MITREByID(id string) (model.MITRETechnique, bool) {
	technique, exists := mitreCatalog[id]
	return technique, exists
}

func sortMITRE(techniques []model.MITRETechnique) {
	for left := 0; left < len(techniques); left++ {
		for right := left + 1; right < len(techniques); right++ {
			if techniques[right].ID < techniques[left].ID {
				techniques[left], techniques[right] = techniques[right], techniques[left]
			}
		}
	}
}

func indexOf(value, substring string) int {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return index
		}
	}
	return -1
}

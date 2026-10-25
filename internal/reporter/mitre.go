package reporter

import "vecmap/internal/model"

// 报告与扫描阶段使用的 MITRE ATT&CK 技术编号。
const (
	TTPNetworkServiceDiscovery = "T1046"
	TTPExploitPublicFacing     = "T1190"
	TTPDataFromLocalSystem     = "T1005"
	TTPDataFromInfoRepo        = "T1213"
	TTPValidAccounts           = "T1078"
)

// Technique 是报告需要展示的技术信息，中英文并列，
// 名称沿用 ATT&CK 官方英文写法，中文为对照翻译。
type Technique struct {
	ID       string
	Name     string
	NameZH   string
	Tactic   string
	TacticZH string
}

var techniques = map[string]Technique{
	TTPNetworkServiceDiscovery: {
		ID:       TTPNetworkServiceDiscovery,
		Name:     "Network Service Discovery",
		NameZH:   "网络服务发现",
		Tactic:   "Discovery",
		TacticZH: "发现",
	},
	TTPExploitPublicFacing: {
		ID:       TTPExploitPublicFacing,
		Name:     "Exploit Public-Facing Application",
		NameZH:   "利用对外暴露的应用",
		Tactic:   "Initial Access",
		TacticZH: "初始访问",
	},
	TTPDataFromLocalSystem: {
		ID:       TTPDataFromLocalSystem,
		Name:     "Data from Local System",
		NameZH:   "本地系统数据",
		Tactic:   "Collection",
		TacticZH: "收集",
	},
	TTPDataFromInfoRepo: {
		ID:       TTPDataFromInfoRepo,
		Name:     "Data from Information Repositories",
		NameZH:   "信息仓库数据",
		Tactic:   "Collection",
		TacticZH: "收集",
	},
	TTPValidAccounts: {
		ID:       TTPValidAccounts,
		Name:     "Valid Accounts",
		NameZH:   "有效账户",
		Tactic:   "Initial Access",
		TacticZH: "初始访问",
	},
}

// TechniqueOf 返回技术详情；未知编号返回保留编号的占位条目，
// 保证报告中不会出现空白的 ATT&CK 字段。
func TechniqueOf(id string) Technique {
	if technique, ok := techniques[id]; ok {
		return technique
	}
	return Technique{ID: id, Name: "Unknown technique", NameZH: "未知技术"}
}

// MapKind 把发现类别映射到默认技术编号。
// 已经带有明确 TTP 的漏洞应优先使用其自身编号。
func MapKind(kind model.FindingKind) string {
	switch kind {
	case model.FindingDiscovery:
		return TTPNetworkServiceDiscovery
	case model.FindingExfiltration:
		return TTPDataFromInfoRepo
	default:
		return TTPExploitPublicFacing
	}
}

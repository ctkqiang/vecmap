package constant

import "vecmap/internal/model"

// MITRE 战术常量。
const (
	// TacticReconnaissance 表示侦察战术。
	TacticReconnaissance = "Reconnaissance"
	// TacticDiscovery 表示发现战术。
	TacticDiscovery = "Discovery"
	// TacticCollection 表示收集战术。
	TacticCollection = "Collection"
	// TacticExfiltration 表示渗出战术。
	TacticExfiltration = "Exfiltration"
	// TacticCredentialAccess 表示凭据访问战术。
	TacticCredentialAccess = "Credential Access"
	// TacticInitialAccess 表示初始访问战术。
	TacticInitialAccess = "Initial Access"
	// TacticExecution 表示执行战术。
	TacticExecution = "Execution"
	// TacticLateralMovement 表示横向移动战术。
	TacticLateralMovement = "Lateral Movement"
	// TacticImpact 表示影响战术。
	TacticImpact = "Impact"
)

// mitreCatalog 保存内置的 MITRE ATT&CK 技术条目。
var mitreCatalog = map[string]model.MITRETechnique{
	"T1595": {
		ID:     "T1595",
		Name:   "Active Scanning",
		Tactic: TacticReconnaissance,
		URL:    "https://attack.mitre.org/techniques/T1595/",
	},
	"T1595.002": {
		ID:     "T1595.002",
		Name:   "Active Scanning: Vulnerability Scanning",
		Tactic: TacticReconnaissance,
		URL:    "https://attack.mitre.org/techniques/T1595/002/",
	},
	"T1592": {
		ID:     "T1592",
		Name:   "Gather Victim Host Information",
		Tactic: TacticReconnaissance,
		URL:    "https://attack.mitre.org/techniques/T1592/",
	},
	"T1046": {
		ID:     "T1046",
		Name:   "Network Service Discovery",
		Tactic: TacticDiscovery,
		URL:    "https://attack.mitre.org/techniques/T1046/",
	},
	"T1213": {
		ID:     "T1213",
		Name:   "Data from Information Repositories",
		Tactic: TacticCollection,
		URL:    "https://attack.mitre.org/techniques/T1213/",
	},
	"T1005": {
		ID:     "T1005",
		Name:   "Data from Local System",
		Tactic: TacticCollection,
		URL:    "https://attack.mitre.org/techniques/T1005/",
	},
	"T1119": {
		ID:     "T1119",
		Name:   "Automated Collection",
		Tactic: TacticCollection,
		URL:    "https://attack.mitre.org/techniques/T1119/",
	},
	"T1530": {
		ID:     "T1530",
		Name:   "Data from Cloud Storage Object",
		Tactic: TacticCollection,
		URL:    "https://attack.mitre.org/techniques/T1530/",
	},
	"T1567": {
		ID:     "T1567",
		Name:   "Exfiltration Over Web Service",
		Tactic: TacticExfiltration,
		URL:    "https://attack.mitre.org/techniques/T1567/",
	},
	"T1185": {
		ID:     "T1185",
		Name:   "Browser Session Hijacking",
		Tactic: TacticCollection,
		URL:    "https://attack.mitre.org/techniques/T1185/",
	},
	"T1040": {
		ID:     "T1040",
		Name:   "Network Sniffing",
		Tactic: TacticCredentialAccess,
		URL:    "https://attack.mitre.org/techniques/T1040/",
	},
	"T1078": {
		ID:     "T1078",
		Name:   "Valid Accounts",
		Tactic: TacticInitialAccess,
		URL:    "https://attack.mitre.org/techniques/T1078/",
	},
	"T1059": {
		ID:     "T1059",
		Name:   "Command and Scripting Interpreter",
		Tactic: TacticExecution,
		URL:    "https://attack.mitre.org/techniques/T1059/",
	},
	"T1210": {
		ID:     "T1210",
		Name:   "Exploitation of Remote Services",
		Tactic: TacticLateralMovement,
		URL:    "https://attack.mitre.org/techniques/T1210/",
	},
	"T1499": {
		ID:     "T1499",
		Name:   "Endpoint Denial of Service",
		Tactic: TacticImpact,
		URL:    "https://attack.mitre.org/techniques/T1499/",
	},
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

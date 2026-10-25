// Package utilities 提供跨模块的通用能力，当前包含：
//
//   - 界面语言（en / zh）词典与取词接口 T() / Tf()；
//   - 语言检测：按 LC_ALL > LC_MESSAGES > LANG，再回退到 macOS 系统语言；
//   - 其余工具（环境变量、本地化设置等）分别见同目录下的其他文件。
//
// 应用所有面向用户的字符串都必须走这里，任何模块都不得硬编码中文或英文文案，
// 否则切换语言时会出现中英混排。
package utilities

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Language 是受支持的界面语言。
type Language string

const (
	English Language = "en"
	Chinese Language = "zh"
)

// 翻译键。所有面向用户的字符串都要用这里的键取值（T()/Tf()），
// 新增文案必须同时补齐英、中两份词典，测试会校验键集一致。
const (
	// 应用
	KeyAppTitle     = "app.title"
	KeyAppTagline   = "app.tagline"
	KeyLangEnglish  = "lang.en"
	KeyLangChinese  = "lang.zh"
	KeyLangDetected = "lang.detected"
	KeyLangUnknown  = "lang.unknown"

	// 日志前缀（logger.go 取用，随语言切换）
	KeyLogPrefixDebug    = "log.prefix.debug"
	KeyLogPrefixInfo     = "log.prefix.info"
	KeyLogPrefixWarn     = "log.prefix.warn"
	KeyLogPrefixCritical = "log.prefix.critical"
	KeyLogPrefixSuccess  = "log.prefix.success"

	// 本地数据库
	KeyDBReady     = "db.ready"
	KeyDBPath      = "db.path"
	KeyDBFailed    = "db.failed"
	KeyDBClosed    = "db.closed"
	KeyDBNotReady  = "db.not.ready"
	KeyDBReplaying = "db.replaying"

	// 会话
	KeySessionCreated    = "session.created"
	KeySessionExists     = "session.exists"
	KeySessionNotFound   = "session.notfound"
	KeySessionOpened     = "session.opened"
	KeySessionListHeader = "session.list.header"
	KeySessionListEmpty  = "session.list.empty"
	KeySessionFinished   = "session.finished"
	KeySessionReplayHint = "session.replay.hint"
	KeySessionRescanned  = "session.rescanned"
	KeyStatusRunning     = "status.running"
	KeyStatusCompleted   = "status.completed"
	KeyStatusAborted     = "status.aborted"

	// 目标
	KeyTargetSeen       = "target.seen"
	KeyTargetRecorded   = "target.recorded"
	KeyTargetSkipped    = "target.skipped"
	KeyTargetVulnerable = "target.vulnerable"
	KeyTargetClean      = "target.clean"

	// 步骤历史
	KeyStepRecorded    = "step.recorded"
	KeyStepReplayStart = "step.replay.start"
	KeyStepReplayEnd   = "step.replay.end"
	KeyStepFailed      = "step.failed"
	KeyStepScanPort    = "step.port.scan"
	KeyStepService     = "step.service.probe"
	KeyStepVersion     = "step.version.grab"
	KeyStepVulnCheck   = "step.vuln.check"
	KeyStepRequest     = "step.http.request"
	KeyStepDump        = "step.schema.dump"

	// 漏洞发现
	KeyVulnFound        = "vuln.found"
	KeyVulnNone         = "vuln.none"
	KeySeverityCritical = "severity.critical"
	KeySeverityHigh     = "severity.high"
	KeySeverityMedium   = "severity.medium"
	KeySeverityLow      = "severity.low"
	KeySeverityInfo     = "severity.info"

	// 汇总
	KeySummarySessions = "summary.sessions"
	KeySummaryTargets  = "summary.targets"
	KeySummarySteps    = "summary.steps"
	KeySummaryFindings = "summary.findings"
	KeySummaryHeader   = "summary.header"

	// 通用错误提示
	KeyErrInvalidInput = "err.invalid.input"
	KeyErrOperation    = "err.operation"
	KeyErrRetry        = "err.retry"

	// 扫描引擎
	KeyScanStart          = "scan.start"
	KeyScanScope          = "scan.scope"
	KeyScanHosts          = "scan.hosts"
	KeyScanPorts          = "scan.ports"
	KeyScanComplete       = "scan.complete"
	KeyScanSaved          = "scan.saved"
	KeyScopeInvalid       = "scope.invalid"
	KeyScopeTooLarge      = "scope.too.large"
	KeyPortOpen           = "port.open"
	KeyPortClosed         = "port.closed"
	KeyFingerprintFound   = "fingerprint.found"
	KeyFingerprintVersion = "fingerprint.version"
	KeyAuthAnonymous      = "auth.anonymous"
	KeyAuthRequired       = "auth.required"
	KeyCVEHit             = "cve.hit"
	KeyDumpCollections    = "dump.collections"
	KeyDumpCollection     = "dump.collection"
	KeyDumpSamples        = "dump.samples"
	KeyDumpKnn            = "dump.knn"
	KeyDumpUnsupported    = "dump.unsupported"
	KeyScanAborted        = "scan.aborted"
	KeyScanNoOpenPorts    = "scan.noopen"
	KeyPortsInvalid       = "ports.invalid"

	// 发现描述（非 CVE 类）
	KeyFindingAnonymousTitle = "finding.anonymous.title"
	KeyFindingAnonymousDesc  = "finding.anonymous.desc"
	KeyFindingMetadataTitle  = "finding.metadata.title"
	KeyFindingMetadataDesc   = "finding.metadata.desc"
	KeyFindingExfilTitle     = "finding.exfil.title"
	KeyFindingExfilDesc      = "finding.exfil.desc"
	KeyFindingKnnDesc        = "finding.knn.desc"

	// 报告
	KeyReportHeader      = "report.header"
	KeyReportSession     = "report.session"
	KeyReportScope       = "report.scope"
	KeyReportGenerated   = "report.generated"
	KeyReportTarget      = "report.target"
	KeyReportFindings    = "report.findings"
	KeyReportTTP         = "report.ttp"
	KeyReportSummary     = "report.summary"
	KeyReportNoFindings  = "report.nofindings"
	KeyReportCollections = "report.collections"
	KeyReportStatus      = "report.status"
	KeyReportTargets     = "report.targets"
	KeyReportNoTargets   = "report.notargets"
	KeyReportTTPLine     = "report.ttp.line"
	KeyReportFix         = "report.fix"
	KeyReportReference   = "report.reference"
	KeyReportTotal       = "report.total"
	KeyReportSaved       = "report.saved"

	// 命令行
	KeyCLIUsage          = "cli.usage"
	KeyCLIUnknownCommand = "cli.unknown"
	KeyCLISessionNeeded  = "cli.session.needed"
	KeySessionListRow    = "session.list.row"
	KeyFlagDB            = "flag.db"
	KeyFlagJSON          = "flag.json"
	KeyFlagOut           = "flag.out"
	KeyFlagScope         = "flag.scope"
	KeyFlagSession       = "flag.session"
	KeyFlagPorts         = "flag.ports"
	KeyFlagWorkers       = "flag.workers"
	KeyFlagTimeout       = "flag.timeout"
	KeyFlagSweep         = "flag.sweep"
	KeyFlagInsecure      = "flag.insecure"
	KeyFlagVerbose       = "flag.verbose"
	KeyFlagLimit         = "flag.limit"
)

// dictionaries 保存两种语言的词典。键缺失时回退到键名本身，
// 这样漏翻译会直接暴露在界面上，而不是显示成空白。
var dictionaries = map[Language]map[string]string{
	English: {
		KeyAppTitle:     "vecmap",
		KeyAppTagline:   "Local scan mapping and session replay",
		KeyLangEnglish:  "English",
		KeyLangChinese:  "Chinese (简体中文)",
		KeyLangDetected: "Interface language: %s",
		KeyLangUnknown:  "Unrecognised locale %q, falling back to English",

		KeyLogPrefixDebug:    "[DBG]",
		KeyLogPrefixInfo:     "[INF]",
		KeyLogPrefixWarn:     "[WRN]",
		KeyLogPrefixCritical: "[CRT]",
		KeyLogPrefixSuccess:  "[SUC]",

		KeyDBReady:     "Local SQLite store ready",
		KeyDBPath:      "Database: %s",
		KeyDBFailed:    "Failed to open the local store: %v",
		KeyDBClosed:    "Local store closed",
		KeyDBNotReady:  "Local store is not initialised",
		KeyDBReplaying: "Replaying stored session data instead of rescanning",

		KeySessionCreated:    "Session %q created (scope: %s)",
		KeySessionExists:     "Session %q already exists — reopening the stored run",
		KeySessionNotFound:   "Session not found",
		KeySessionOpened:     "Session %q loaded (status: %s)",
		KeySessionListHeader: "Stored sessions",
		KeySessionListEmpty:  "No stored session yet",
		KeySessionFinished:   "Session %q saved as %s",
		KeySessionReplayHint: "Run vecmap --session <name> to view a stored session without rescanning",
		KeySessionRescanned:  "Nothing to scan: everything is already stored for this session",
		KeyStatusRunning:     "running",
		KeyStatusCompleted:   "completed",
		KeyStatusAborted:     "aborted",

		KeyTargetSeen:       "Already stored: %s:%d/%s",
		KeyTargetRecorded:   "Target recorded: %s:%d/%s",
		KeyTargetSkipped:    "Skipped (already in this session): %s:%d/%s",
		KeyTargetVulnerable: "Target %s:%d flagged as vulnerable",
		KeyTargetClean:      "No finding for %s:%d/%s",

		KeyStepRecorded:    "Step recorded: %s",
		KeyStepReplayStart: "Replaying %d stored steps",
		KeyStepReplayEnd:   "Replay finished",
		KeyStepFailed:      "Step failed: %s",
		KeyStepScanPort:    "port scan",
		KeyStepService:     "service probe",
		KeyStepVersion:     "version grab",
		KeyStepVulnCheck:   "vulnerability check",
		KeyStepRequest:     "HTTP request",
		KeyStepDump:        "schema enumeration",

		KeyVulnFound:        "Finding: %s (%s)",
		KeyVulnNone:         "No vulnerability recorded",
		KeySeverityCritical: "CRITICAL",
		KeySeverityHigh:     "HIGH",
		KeySeverityMedium:   "MEDIUM",
		KeySeverityLow:      "LOW",
		KeySeverityInfo:     "INFO",

		KeySummaryHeader:   "Session summary",
		KeySummarySessions: "sessions stored: %d",
		KeySummaryTargets:  "targets: %d",
		KeySummarySteps:    "steps recorded: %d",
		KeySummaryFindings: "findings: %d",

		KeyErrInvalidInput: "Invalid input: %s",
		KeyErrOperation:    "Operation failed: %v",
		KeyErrRetry:        "Please retry the operation",

		KeyScanStart:          "Starting scan",
		KeyScanScope:          "Scope: %s",
		KeyScanHosts:          "Hosts to scan: %d",
		KeyScanPorts:          "Ports per host: %d",
		KeyScanComplete:       "Scan finished in %s",
		KeyScanSaved:          "Results saved to session %q",
		KeyScopeInvalid:       "Invalid scope %q: %v",
		KeyScopeTooLarge:      "Scope expands to %d hosts, above the limit of %d",
		KeyPortOpen:           "open  %s:%d (%s)",
		KeyPortClosed:         "closed %s:%d",
		KeyFingerprintFound:   "Fingerprint: %s %s",
		KeyFingerprintVersion: "Version: %s",
		KeyAuthAnonymous:      "Anonymous access allowed",
		KeyAuthRequired:       "Authentication required",
		KeyCVEHit:             "%s (%s, CVSS %.1f) affects this version",
		KeyDumpCollections:    "Collections: %d",
		KeyDumpCollection:     "  - %s (dim=%d, metric=%s, points=%d)",
		KeyDumpSamples:        "Records readable without credentials: %d",
		KeyDumpKnn:            "k-NN query returned data without credentials",
		KeyDumpUnsupported:    "%s is not supported by the dumper",
		KeyScanAborted:        "Scan interrupted, partial results saved",
		KeyScanNoOpenPorts:    "No open vector database port found",
		KeyPortsInvalid:       "Invalid port list %q: %v",

		KeyFindingAnonymousTitle: "Anonymous access enabled",
		KeyFindingAnonymousDesc:  "%s accepts unauthenticated API requests, so metadata is reachable by anyone who can reach the port.",
		KeyFindingMetadataTitle:  "Collection metadata readable without credentials",
		KeyFindingMetadataDesc:   "%[1]d collection(s) on %[2]s were enumerated without authentication.",
		KeyFindingExfilTitle:     "Vector data readable without credentials",
		KeyFindingExfilDesc:      "%[1]d record(s) were read from %[2]s without authentication.",
		KeyFindingKnnDesc:        "A zero-vector k-NN query returned %d record(s) without authentication.",

		KeyReportHeader:      "vecmap audit report",
		KeyReportSession:     "Session: %s",
		KeyReportScope:       "Scope: %s",
		KeyReportGenerated:   "Generated: %s",
		KeyReportTarget:      "Target: %s",
		KeyReportFindings:    "Findings",
		KeyReportTTP:         "MITRE ATT&CK",
		KeyReportSummary:     "Summary",
		KeyReportNoFindings:  "No finding for this target",
		KeyReportCollections: "Collections",
		KeyReportStatus:      "Status: %s",
		KeyReportTargets:     "Targets",
		KeyReportNoTargets:   "No target recorded",
		KeyReportTTPLine:     "MITRE ATT&CK: %s %s",
		KeyReportFix:         "fixed in: %s",
		KeyReportReference:   "reference: %s",
		KeyReportTotal:       "total findings: %d",
		KeyReportSaved:       "JSON report written to %s",

		KeyCLIUsage:          "usage: vecmap <scan|sessions|show> [flags]\n\n  scan     --scope <cidr|host> [--session name] [--ports 8080,6333] [--workers 64] [--timeout 800ms] [--sweep] [--insecure] [--json] [--out file]\n  sessions [--limit 20]\n  show     --session <name> [--json] [--out file]\n\nEvery subcommand accepts --db <path> and --verbose.",
		KeyCLIUnknownCommand: "Unknown command %q",
		KeyCLISessionNeeded:  "--session is required",
		KeySessionListRow:    "  %-20s %-10s scope=%s targets=%d findings=%d started=%s",
		KeyFlagDB:            "path to the local SQLite database",
		KeyFlagJSON:          "write the report as JSON",
		KeyFlagOut:           "JSON output path (default vecmap-<session>.json)",
		KeyFlagScope:         "target scope: host, CIDR, range or comma separated list",
		KeyFlagSession:       "session name; an existing session is resumed",
		KeyFlagPorts:         "comma separated ports or ranges",
		KeyFlagWorkers:       "concurrent workers",
		KeyFlagTimeout:       "per-probe timeout",
		KeyFlagSweep:         "enumerate schemas and run non-destructive k-NN checks",
		KeyFlagInsecure:      "skip TLS certificate verification",
		KeyFlagVerbose:       "print debug output",
		KeyFlagLimit:         "maximum number of sessions to list",
	},
	Chinese: {
		KeyAppTitle:     "vecmap 扫描映射",
		KeyAppTagline:   "本地扫描记录与会话回放",
		KeyLangEnglish:  "英语（English）",
		KeyLangChinese:  "简体中文",
		KeyLangDetected: "界面语言：%s",
		KeyLangUnknown:  "无法识别的区域设置 %q，已回退到英文",

		KeyLogPrefixDebug:    "[调试]",
		KeyLogPrefixInfo:     "[信息]",
		KeyLogPrefixWarn:     "[警告]",
		KeyLogPrefixCritical: "[严重]",
		KeyLogPrefixSuccess:  "[成功]",

		KeyDBReady:     "本地 SQLite 数据库已就绪",
		KeyDBPath:      "数据库文件：%s",
		KeyDBFailed:    "打开本地数据库失败：%v",
		KeyDBClosed:    "本地数据库已关闭",
		KeyDBNotReady:  "本地数据库尚未初始化",
		KeyDBReplaying: "回放已保存的会话数据，无需重新扫描",

		KeySessionCreated:    "已创建会话 %q（目标范围：%s）",
		KeySessionExists:     "会话 %q 已存在，直接载入已保存的记录",
		KeySessionNotFound:   "未找到该会话",
		KeySessionOpened:     "已载入会话 %q（状态：%s）",
		KeySessionListHeader: "已保存的会话",
		KeySessionListEmpty:  "暂无已保存的会话",
		KeySessionFinished:   "会话 %q 已保存，状态：%s",
		KeySessionReplayHint: "使用 vecmap --session <名称> 可直接查看历史会话，无需重新扫描",
		KeySessionRescanned:  "无需扫描：该会话的数据已全部保存在本地",
		KeyStatusRunning:     "进行中",
		KeyStatusCompleted:   "已完成",
		KeyStatusAborted:     "已中止",

		KeyTargetSeen:       "已存在：%s:%d/%s",
		KeyTargetRecorded:   "已记录目标：%s:%d/%s",
		KeyTargetSkipped:    "已跳过（本会话内已存在）：%s:%d/%s",
		KeyTargetVulnerable: "目标 %s:%d 标记为存在漏洞",
		KeyTargetClean:      "%s:%d/%s 未发现漏洞",

		KeyStepRecorded:    "已记录步骤：%s",
		KeyStepReplayStart: "正在回放 %d 条历史步骤",
		KeyStepReplayEnd:   "回放结束",
		KeyStepFailed:      "步骤失败：%s",
		KeyStepScanPort:    "端口扫描",
		KeyStepService:     "服务识别",
		KeyStepVersion:     "版本探测",
		KeyStepVulnCheck:   "漏洞检测",
		KeyStepRequest:     "HTTP 请求",
		KeyStepDump:        "Schema 枚举",

		KeyVulnFound:        "发现漏洞：%s（%s）",
		KeyVulnNone:         "未记录到漏洞",
		KeySeverityCritical: "严重",
		KeySeverityHigh:     "高危",
		KeySeverityMedium:   "中危",
		KeySeverityLow:      "低危",
		KeySeverityInfo:     "信息",

		KeySummaryHeader:   "会话汇总",
		KeySummarySessions: "已保存会话：%d",
		KeySummaryTargets:  "目标数：%d",
		KeySummarySteps:    "步骤数：%d",
		KeySummaryFindings: "漏洞数：%d",

		KeyErrInvalidInput: "输入无效：%s",
		KeyErrOperation:    "操作失败：%v",
		KeyErrRetry:        "请重试该操作",

		KeyScanStart:          "开始扫描",
		KeyScanScope:          "目标范围：%s",
		KeyScanHosts:          "待扫描主机数：%d",
		KeyScanPorts:          "每台主机端口数：%d",
		KeyScanComplete:       "扫描完成，耗时 %s",
		KeyScanSaved:          "结果已保存到会话 %q",
		KeyScopeInvalid:       "目标范围 %q 无效：%v",
		KeyScopeTooLarge:      "目标范围展开为 %d 台主机，超过上限 %d",
		KeyPortOpen:           "开放  %s:%d（%s）",
		KeyPortClosed:         "关闭  %s:%d",
		KeyFingerprintFound:   "指纹：%s %s",
		KeyFingerprintVersion: "版本：%s",
		KeyAuthAnonymous:      "允许匿名访问",
		KeyAuthRequired:       "需要身份认证",
		KeyCVEHit:             "%s（%s，CVSS %.1f）影响该版本",
		KeyDumpCollections:    "集合数量：%d",
		KeyDumpCollection:     "  - %s（维度=%d，度量=%s，记录数=%d）",
		KeyDumpSamples:        "无凭证可读取的记录数：%d",
		KeyDumpKnn:            "k-NN 检索在无凭证情况下返回了数据",
		KeyDumpUnsupported:    "%s 暂不支持 Schema 枚举",
		KeyScanAborted:        "扫描被中断，已保存部分结果",
		KeyScanNoOpenPorts:    "未发现开放的向量数据库端口",
		KeyPortsInvalid:       "端口列表 %q 无效：%v",

		KeyFindingAnonymousTitle: "允许匿名访问",
		KeyFindingAnonymousDesc:  "%s 接受未认证的 API 请求，任何能访问该端口的人都可以读取元数据。",
		KeyFindingMetadataTitle:  "无凭证即可读取集合元数据",
		KeyFindingMetadataDesc:   "在 %[2]s 上未认证枚举到 %[1]d 个集合。",
		KeyFindingExfilTitle:     "无凭证即可读取向量数据",
		KeyFindingExfilDesc:      "在 %[2]s 上未认证读取到 %[1]d 条记录。",
		KeyFindingKnnDesc:        "零向量 k-NN 检索在未认证情况下返回了 %d 条记录。",

		KeyReportHeader:      "vecmap 审计报告",
		KeyReportSession:     "会话：%s",
		KeyReportScope:       "目标范围：%s",
		KeyReportGenerated:   "生成时间：%s",
		KeyReportTarget:      "目标：%s",
		KeyReportFindings:    "发现",
		KeyReportTTP:         "MITRE ATT&CK",
		KeyReportSummary:     "汇总",
		KeyReportNoFindings:  "该目标未发现问题",
		KeyReportCollections: "集合",
		KeyReportStatus:      "状态：%s",
		KeyReportTargets:     "目标",
		KeyReportNoTargets:   "未记录任何目标",
		KeyReportTTPLine:     "MITRE ATT&CK：%s %s",
		KeyReportFix:         "修复版本：%s",
		KeyReportReference:   "参考链接：%s",
		KeyReportTotal:       "发现总数：%d",
		KeyReportSaved:       "JSON 报告已写入 %s",

		KeyCLIUsage:          "用法：vecmap <scan|sessions|show> [参数]\n\n  scan      --scope <网段|主机> [--session 名称] [--ports 8080,6333] [--workers 64] [--timeout 800ms] [--sweep] [--insecure] [--json] [--out 文件]\n  sessions  [--limit 20]\n  show      --session <名称> [--json] [--out 文件]\n\n所有子命令均支持 --db <路径> 与 --verbose。",
		KeyCLIUnknownCommand: "未知命令 %q",
		KeyCLISessionNeeded:  "必须指定 --session",
		KeySessionListRow:    "  %-20s %-10s 范围=%s 目标数=%d 漏洞数=%d 开始时间=%s",
		KeyFlagDB:            "本地 SQLite 数据库路径",
		KeyFlagJSON:          "以 JSON 格式导出报告",
		KeyFlagOut:           "JSON 输出路径（默认 vecmap-<会话>.json）",
		KeyFlagScope:         "目标范围：主机、CIDR、区间或逗号分隔列表",
		KeyFlagSession:       "会话名称；已存在时继续该会话",
		KeyFlagPorts:         "逗号分隔的端口或端口区间",
		KeyFlagWorkers:       "并发 worker 数量",
		KeyFlagTimeout:       "单次探测超时",
		KeyFlagSweep:         "枚举 Schema 并执行非破坏性 k-NN 验证",
		KeyFlagInsecure:      "跳过 TLS 证书校验",
		KeyFlagVerbose:       "输出调试日志",
		KeyFlagLimit:         "最多列出的会话数量",
	},
}

// 当前语言。读写用 RWMutex 保护，保证并发扫描时取词安全。
var (
	localeMutex sync.RWMutex
	locale      = English
)

// InitLocale 按设备设置选定界面语言并生效，返回实际选中的语言。
// 程序启动时调用一次即可（见 cmd/vecmap.go 的 setLocle）。
func InitLocale() Language {
	return SetLocale(DetectLocale())
}

// SetLocale 切换当前语言。未知语言回退到英文，并把回退结果返回给调用方，
// 便于调用方给出提示。
func SetLocale(l Language) Language {
	if _, ok := dictionaries[l]; !ok {
		l = English
	}
	localeMutex.Lock()
	locale = l
	localeMutex.Unlock()
	return l
}

// Locale 返回当前生效的语言。
func Locale() Language {
	localeMutex.RLock()
	defer localeMutex.RUnlock()
	return locale
}

// SetLocaleByCode 把 "zh-Hans-CN"、"zh_CN.UTF-8"、"en_US" 这类区域设置字符串
// 映射为受支持的语言并生效；无法识别的代码按英文处理。
func SetLocaleByCode(code string) Language {
	return SetLocale(LanguageFromCode(code))
}

// LanguageFromCode 把任意 POSIX / BCP-47 区域设置标签翻译成受支持的语言，
// 不支持的语言返回空字符串（由调用方决定回退策略）。
func LanguageFromCode(code string) Language {
	c := strings.ToLower(strings.TrimSpace(code))
	if c == "" {
		return ""
	}
	if strings.HasPrefix(c, "zh") {
		return Chinese
	}
	if strings.HasPrefix(c, "en") {
		return English
	}
	return ""
}

// LangName 返回语言名称，并用当前语言渲染，供语言切换与状态行显示。
func LangName(l Language) string {
	if l == Chinese {
		return T(KeyLangChinese)
	}
	return T(KeyLangEnglish)
}

// Keys 返回指定语言词典中的全部键。用于校验翻译完整性，
// 以及在 test/ 等外部包里做键集比对（词典本身不对外暴露）。
func Keys(l Language) []string {
	localeMutex.RLock()
	dict, ok := dictionaries[l]
	localeMutex.RUnlock()
	if !ok {
		return nil
	}

	keys := make([]string, 0, len(dict))
	for k := range dict {
		keys = append(keys, k)
	}
	return keys
}

// T 按当前语言返回键对应的文案；键不存在时原样返回键名。
func T(key string) string {
	localeMutex.RLock()
	lang := locale
	localeMutex.RUnlock()

	if msg, ok := dictionaries[lang][key]; ok {
		return msg
	}
	if msg, ok := dictionaries[English][key]; ok {
		return msg
	}
	return key
}

// Tf 在 T() 的基础上按给定参数格式化，用于带占位符的文案。
func Tf(key string, args ...any) string {
	return fmt.Sprintf(T(key), args...)
}

// DetectLocale 按以下顺序读取设备语言设置：
//  1. POSIX 环境变量：LC_ALL > LC_MESSAGES > LANG；
//  2. macOS 不导出 LANG，改为读取系统语言 defaults read -g AppleLocale；
//  3. 以上都取不到时回退到英文。
func DetectLocale() Language {
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := LanguageFromCode(os.Getenv(env)); l != "" {
			return l
		}
	}

	if runtime.GOOS == "darwin" {
		if l := macOSLocale(); l != "" {
			return l
		}
	}
	return English
}

// macOSLocale 读取当前用户的系统语言，这是 macOS 上唯一能感知设备设置的途径。
// 命令带 2 秒超时，任何失败都静默忽略并由上层回退到英文。
func macOSLocale() Language {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// AppleLocale 形如 zh_CN / en_US
	if out, err := exec.CommandContext(ctx, "defaults", "read", "-g", "AppleLocale").Output(); err == nil {
		if l := LanguageFromCode(strings.TrimSpace(string(out))); l != "" {
			return l
		}
	}

	// AppleLanguages 是一个数组，取第一项，形如 ( "zh-Hans-CN", en )
	if out, err := exec.CommandContext(ctx, "defaults", "read", "-g", "AppleLanguages").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			token := strings.Trim(strings.TrimSpace(line), `",()`)
			if token == "" {
				continue
			}
			if l := LanguageFromCode(token); l != "" {
				return l
			}
		}
	}
	return ""
}

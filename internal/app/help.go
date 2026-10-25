package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"vecmap/internal/constant"
	"vecmap/internal/model"
)

// 帮助渲染样式（复用用户的 lipgloss 模块）。
var (
	helpBanner  = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true)
	helpTitle   = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Bold(true)
	helpCommand = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	helpFlag    = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	helpDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	helpWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	helpErr     = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
)

// optionDoc 描述一条命令参数。
type optionDoc struct {
	Flag string
	En   string
	Zh   string
}

// exampleDoc 描述一条使用示例。
type exampleDoc struct {
	En string
	Zh string
}

// commandDoc 描述一条子命令的完整帮助内容。
type commandDoc struct {
	Name     string
	Synopsis string
	En       string
	Zh       string
	Options  []optionDoc
	Examples []exampleDoc
}

// commandDocs 是所有子命令的帮助目录。
var commandDocs = map[string]commandDoc{
	"scan": {
		Name:     "scan",
		Synopsis: "vecmap scan [OPTIONS] TARGET...",
		En:       "Attack-surface scan of vector databases: product fingerprinting, read-only surface probes, CVE/CNVD correlation and risk findings. Use --mode deep (or --extract) to enumerate collections and extract records.",
		Zh:       "向量数据库攻击面扫描：产品指纹识别、只读暴露面探测、CVE/CNVD 关联与风险发现。使用 --mode deep（或 --extract）可枚举集合并提取记录。",
		Options:  scanOptions,
		Examples: scanExamples,
	},
	"discover": {
		Name:     "discover",
		Synopsis: "vecmap discover [OPTIONS] HOST|CIDR...",
		En:       "Concurrent TCP/HTTP/TLS/gRPC/RESP port discovery across hosts or CIDR ranges. Open ports are persisted as session targets.",
		Zh:       "对主机或网段执行 TCP/HTTP/TLS/gRPC/RESP 并发端口发现，开放端口作为会话目标持久化。",
		Options:  discoverOptions,
		Examples: discoverExamples,
	},
	"dump": {
		Name:     "dump",
		Synopsis: "vecmap dump [OPTIONS] TARGET...",
		En:       "Deep enumeration and record extraction (implies --mode deep --extract). Restrict scope with --collection and --namespace.",
		Zh:       "深度枚举与记录提取（等价于 --mode deep --extract）。可用 --collection、--namespace 限定范围。",
		Options:  scanOptions,
		Examples: dumpExamples,
	},
	"sessions": {
		Name:     "sessions",
		Synopsis: "vecmap sessions [--db PATH]",
		En:       "List locally persisted sessions, newest first.",
		Zh:       "列出本地持久化的会话，按时间倒序。",
		Options:  sessionsOptions,
		Examples: nil,
	},
	"report": {
		Name:     "report",
		Synopsis: "vecmap report --session ID [--format markdown|json|html] [--output PATH]",
		En:       "Render a session report offline. Without --output the report is printed to stdout.",
		Zh:       "离线生成会话报告。未指定 --output 时输出到标准输出。",
		Options:  reportOptions,
		Examples: reportExamples,
	},
	"advisories": {
		Name:     "advisories",
		Synopsis: "vecmap advisories [--lang en|zh]",
		En:       "List the built-in advisory catalog sourced from embedded GitHub Security Advisory snapshots.",
		Zh:       "列出内置公告目录（数据来自内嵌的 GitHub Security Advisory 快照）。",
		Options:  globalOptions,
		Examples: nil,
	},
	"delete": {
		Name:     "delete",
		Synopsis: "vecmap delete --session ID",
		En:       "Delete a session and all of its associated evidence (cascading).",
		Zh:       "删除会话及其全部关联证据（级联删除）。",
		Options: []optionDoc{
			{Flag: "--session ID", En: "Session ID to delete (required)", Zh: "待删除的会话 ID（必填）"},
			{Flag: "--db PATH", En: "Local database path (default ~/.vecmap/vecmap.db)", Zh: "本地数据库路径（默认 ~/.vecmap/vecmap.db）"},
			{Flag: "--lang en|zh", En: "UI language", Zh: "界面语言"},
			{Flag: "--verbose", En: "Verbose logging", Zh: "详细日志"},
		},
		Examples: []exampleDoc{{En: "vecmap delete --session ses_1234abcd", Zh: "vecmap delete --session ses_1234abcd"}},
	},
	"version": {
		Name:     "version",
		Synopsis: "vecmap version",
		En:       "Print the version string.",
		Zh:       "输出版本信息。",
		Options:  nil,
		Examples: nil,
	},
	"man": {
		Name:     "man",
		Synopsis: "vecmap man",
		En:       "Print the manual page in roff format (pipe to man -l - or install docs/vecmap.1).",
		Zh:       "以 roff 格式输出手册页（可管道到 man -l -，或将 docs/vecmap.1 安装到系统）。",
		Options:  nil,
		Examples: []exampleDoc{{En: "vecmap man | man -l -", Zh: "vecmap man | man -l -"}},
	},
	"completion": {
		Name:     "completion",
		Synopsis: "vecmap completion bash|zsh",
		En:       "Print a shell completion script for bash or zsh.",
		Zh:       "输出 bash 或 zsh 的补全脚本。",
		Options:  nil,
		Examples: []exampleDoc{
			{En: "source <(vecmap completion bash)", Zh: "source <(vecmap completion bash)"},
			{En: "vecmap completion zsh > _vecmap", Zh: "vecmap completion zsh > _vecmap"},
		},
	},
	"help": {
		Name:     "help",
		Synopsis: "vecmap help [COMMAND]",
		En:       "Show this help or the detailed usage of one command.",
		Zh:       "显示总帮助或某条命令的详细用法。",
		Options:  nil,
		Examples: []exampleDoc{{En: "vecmap help scan", Zh: "vecmap help scan"}},
	},
}

var globalOptions = []optionDoc{
	{Flag: "--db PATH", En: "Local database path (default ~/.vecmap/vecmap.db)", Zh: "本地数据库路径（默认 ~/.vecmap/vecmap.db）"},
	{Flag: "--lang en|zh", En: "UI and report language (default: VECMAP_LANG, then system locale, else en)", Zh: "界面与报告语言（默认：VECMAP_LANG，其次系统 locale，否则 en）"},
	{Flag: "--verbose", En: "Verbose protocol logging", Zh: "输出底层协议调试日志"},
	{Flag: "--help, -h", En: "Show help for the command", Zh: "显示该命令的帮助"},
	{Flag: "--usage", En: "Print the command synopsis only", Zh: "仅输出命令语法"},
}

var scopeOptions = []optionDoc{
	{Flag: "--scope-cidr CIDR", En: "Authorized CIDR (repeatable; allowlist when set)", Zh: "授权网段（可重复；配置后未命中即拒绝）"},
	{Flag: "--scope-domain DOMAIN", En: "Authorized domain (repeatable)", Zh: "授权域名（可重复）"},
	{Flag: "--scope-port PORT", En: "Authorized port (repeatable/comma list)", Zh: "授权端口（可重复或逗号列表）"},
	{Flag: "--exclude-cidr CIDR", En: "Excluded CIDR (repeatable)", Zh: "排除网段（可重复）"},
	{Flag: "--exclude-domain DOMAIN", En: "Excluded domain (repeatable)", Zh: "排除域名（可重复）"},
	{Flag: "--authorize", En: "Confirm written authorization for the targets (required)", Zh: "确认已获得目标书面授权（必填）"},
}

var authOptions = []optionDoc{
	{Flag: "--api-key KEY", En: "API key (vendor-specific header)", Zh: "API Key（按厂商自动选择请求头）"},
	{Flag: "--bearer TOKEN", En: "Bearer token", Zh: "Bearer 令牌"},
	{Flag: "--user USER", En: "Basic-auth username", Zh: "基础认证用户名"},
	{Flag: "--pass PASS", En: "Basic-auth password", Zh: "基础认证密码"},
	{Flag: "--database NAME", En: "Database / tenant / Redis DB number", Zh: "数据库名 / 租户 / Redis 库号"},
	{Flag: "--dsn DSN", En: "PostgreSQL connection string", Zh: "PostgreSQL 连接串"},
}

var scanOptions = append([]optionDoc{
	{Flag: "--name NAME", En: "Session name", Zh: "会话名称"},
	{Flag: "--mode standard|deep", En: "Scan mode (deep enumerates and extracts)", Zh: "扫描模式（deep 执行枚举与提取）"},
	{Flag: "--ports PORTS", En: "Ports for bare hosts (comma list)", Zh: "裸主机的端口列表（逗号分隔）"},
	{Flag: "--timeout DUR", En: "Per-request timeout (default 8s)", Zh: "单请求超时（默认 8s）"},
	{Flag: "--concurrency N", En: "Concurrency (default 8)", Zh: "并发数（默认 8）"},
	{Flag: "--rate N", En: "Request rate limit (req/s)", Zh: "请求速率限制（req/s）"},
	{Flag: "--insecure", En: "Skip TLS certificate verification", Zh: "跳过 TLS 证书校验"},
	{Flag: "--fuzz", En: "Extended read-only path probing", Zh: "扩展只读路径探测"},
	{Flag: "--extract", En: "Extract records (implies deep)", Zh: "提取记录（隐含 deep 模式）"},
	{Flag: "--collection NAME", En: "Restrict enumeration to one collection", Zh: "仅枚举指定集合"},
	{Flag: "--namespace NS", En: "Restrict enumeration to one namespace", Zh: "仅枚举指定命名空间"},
	{Flag: "--max-records N", En: "Record extraction limit (default 200)", Zh: "记录提取上限（默认 200）"},
	{Flag: "--batch N", En: "Page size (default 100)", Zh: "分页大小（默认 100）"},
	{Flag: "--vectors", En: "Include vector samples in extraction", Zh: "提取时包含向量采样"},
	{Flag: "--user-agent UA", En: "Custom User-Agent", Zh: "自定义 User-Agent"},
	{Flag: "--proxy URL", En: "HTTP(S) proxy", Zh: "HTTP(S) 代理"},
	{Flag: "--header K:V", En: "Extra request header (repeatable)", Zh: "附加请求头（可重复）"},
	{Flag: "--advisories PATH", En: "Import extra advisories JSON", Zh: "导入外部公告 JSON"},
	{Flag: "--dry-run", En: "Do not persist anything", Zh: "不持久化任何数据"},
}, append(append(scopeOptions, authOptions...), globalOptions...)...)

var discoverOptions = append([]optionDoc{
	{Flag: "--name NAME", En: "Session name", Zh: "会话名称"},
	{Flag: "--ports PORTS", En: "Ports to probe (default: vendor port set)", Zh: "探测端口（默认：厂商端口集合）"},
	{Flag: "--timeout DUR", En: "Per-probe timeout (default 5s)", Zh: "单端口探测超时（默认 5s）"},
	{Flag: "--concurrency N", En: "Concurrency (default 64)", Zh: "并发数（默认 64）"},
	{Flag: "--dry-run", En: "Do not persist anything", Zh: "不持久化任何数据"},
}, append(scopeOptions, globalOptions...)...)

var sessionsOptions = globalOptions

var reportOptions = append([]optionDoc{
	{Flag: "--session ID", En: "Session ID to report (required)", Zh: "待报告的会话 ID（必填）"},
	{Flag: "--format markdown|json|html", En: "Report format (default markdown)", Zh: "报告格式（默认 markdown）"},
	{Flag: "--output PATH", En: "Write report to file (0600)", Zh: "报告输出路径（权限 0600）"},
}, globalOptions...)

var scanExamples = []exampleDoc{
	{En: "# Standard scan of one Qdrant host", Zh: "# 标准扫描单个 Qdrant 主机"},
	{En: "vecmap scan --authorize --scope-cidr 10.0.0.0/24 http://10.0.0.5:6333", Zh: "vecmap scan --authorize --scope-cidr 10.0.0.0/24 http://10.0.0.5:6333"},
	{En: "# Deep scan with authenticated extraction", Zh: "# 带认证的深度扫描与提取"},
	{En: "vecmap scan --authorize --mode deep --api-key SECRET --vectors 10.0.0.5:6333", Zh: "vecmap scan --authorize --mode deep --api-key SECRET --vectors 10.0.0.5:6333"},
	{En: "# Scan a Redis endpoint over TLS", Zh: "# 扫描 TLS Redis 端点"},
	{En: "vecmap scan --authorize rediss://db.example.com:6380", Zh: "vecmap scan --authorize rediss://db.example.com:6380"},
	{En: "# Scan a PostgreSQL pgvector database", Zh: "# 扫描 PostgreSQL pgvector 数据库"},
	{En: "vecmap scan --authorize --dsn 'postgres://user:pass@10.0.0.9:5432/vecdb' 10.0.0.9:5432", Zh: "vecmap scan --authorize --dsn 'postgres://user:pass@10.0.0.9:5432/vecdb' 10.0.0.9:5432"},
}

var discoverExamples = []exampleDoc{
	{En: "# Discover vendor ports across a /24", Zh: "# 对 /24 网段做厂商端口发现"},
	{En: "vecmap discover --authorize --scope-cidr 10.0.0.0/24 10.0.0.0/24", Zh: "vecmap discover --authorize --scope-cidr 10.0.0.0/24 10.0.0.0/24"},
	{En: "# Probe a fixed port set", Zh: "# 探测固定端口集合"},
	{En: "vecmap discover --authorize --ports 6333,19530,9200 10.0.0.0/28", Zh: "vecmap discover --authorize --ports 6333,19530,9200 10.0.0.0/28"},
}

var dumpExamples = []exampleDoc{
	{En: "# Extract up to 500 records with vector samples", Zh: "# 提取至多 500 条记录并采样向量"},
	{En: "vecmap dump --authorize --max-records 500 --vectors http://10.0.0.5:6333", Zh: "vecmap dump --authorize --max-records 500 --vectors http://10.0.0.5:6333"},
	{En: "# Extract one collection only", Zh: "# 仅提取单个集合"},
	{En: "vecmap dump --authorize --collection docs http://10.0.0.5:6333", Zh: "vecmap dump --authorize --collection docs http://10.0.0.5:6333"},
}

var reportExamples = []exampleDoc{
	{En: "# Markdown report to a file", Zh: "# 输出 Markdown 报告到文件"},
	{En: "vecmap report --session ses_1234abcd --output report.md", Zh: "vecmap report --session ses_1234abcd --output report.md"},
	{En: "# HTML report to stdout", Zh: "# HTML 报告输出到终端"},
	{En: "vecmap report --session ses_1234abcd --format html", Zh: "vecmap report --session ses_1234abcd --format html"},
}

// bannerText 是帮助与扫描启动时展示的 ASCII 艺术字。
const bannerText = `__     __ _____ _____ __  __    _    ____  
\ \   / // ____/ ____|  \/  |  / \  |  _ \ 
 \ \ / /| |   | |    | |\/| | / _ \ | |_) |
  \ V / | |___| |____| |  | |/ ___ \|  __/ 
   \_/  |______\______|_|  |_/_/   \_\_|    `

// Banner 返回带版本号的彩色 ASCII 横幅。
//
// 返回按终端能力渲染（或降级为纯文本）的横幅文本。
func (a *App) Banner() string {
	var output strings.Builder
	for _, line := range strings.Split(bannerText, "\n") {
		output.WriteString(paint(helpBanner, line) + "\n")
	}
	output.WriteString(paint(helpDim, fmt.Sprintf("%s v%s — %s", constant.Name, constant.Version, localized(a.language == "zh", constant.Tagline, "向量数据库攻击面评估框架"))))
	return output.String()
}

// UsageSynopsis 返回命令的精简用法行。
//
// 参数 topic 为命令名；空字符串返回总览用法。
// 用于 --usage 输出与使用错误提示。
func (a *App) UsageSynopsis(topic string) string {
	topic = strings.ToLower(strings.TrimSpace(topic))
	if topic == "" {
		return fmt.Sprintf("Usage: vecmap <command> [options]\n       vecmap <command> --help | --usage\n       vecmap man | completion bash|zsh\n")
	}
	if doc, exists := commandDocs[topic]; exists {
		return fmt.Sprintf("Usage: %s\n", doc.Synopsis)
	}
	return fmt.Sprintf("Usage: vecmap help\n")
}

// SeverityStyle 返回风险等级对应的显示样式。
//
// 参数 severity 为风险等级；返回彩色样式，非 TTY 时输出纯文本。
func SeverityStyle(severity model.Severity, text string) string {
	var style lipgloss.Style
	switch severity {
	case model.SeverityCritical:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	case model.SeverityHigh:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	case model.SeverityMedium:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	case model.SeverityLow:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	default:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	}
	return paint(style, text)
}

// StatusStyle 返回会话状态对应的显示样式。
//
// 参数 status 为状态文本；completed 绿色、running 黄色、failed 红色。
func StatusStyle(status, text string) string {
	var style lipgloss.Style
	switch strings.ToLower(status) {
	case "completed":
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	case "running":
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	case "failed":
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	default:
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	}
	return paint(style, text)
}

// DefaultLanguage 根据环境检测默认界面语言。
//
// 优先级：VECMAP_LANG > LANG/LC_ALL/LC_MESSAGES 中的 zh 前缀 > en。
// 返回 en 或 zh。
func DefaultLanguage() string {
	if value := strings.TrimSpace(os.Getenv("VECMAP_LANG")); value != "" {
		if strings.HasPrefix(strings.ToLower(value), "zh") {
			return "zh"
		}
		return "en"
	}
	for _, key := range []string{"LANG", "LC_ALL", "LC_MESSAGES"} {
		if strings.Contains(strings.ToLower(os.Getenv(key)), "zh") {
			return "zh"
		}
	}
	return "en"
}

// colorsEnabled 判断终端是否支持彩色输出。
//
// 遵守 NO_COLOR 约定，TERM=dumb 时也禁用彩色。
func colorsEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return os.Getenv("TERM") != "dumb"
}

func paint(style lipgloss.Style, text string) string {
	if !colorsEnabled() {
		return text
	}
	return style.Render(text)
}

func localized(zh bool, en, zhText string) string {
	if zh && zhText != "" {
		return zhText
	}
	return en
}

// languageBanner 返回按语言渲染的 ASCII 横幅。
//
// 参数 language 为 en 或 zh。
func languageBanner(language string) string {
	zh := language == "zh"
	var output strings.Builder
	for _, line := range strings.Split(bannerText, "\n") {
		output.WriteString(paint(helpBanner, line) + "\n")
	}
	output.WriteString(paint(helpDim, fmt.Sprintf("%s v%s — %s", constant.Name, constant.Version, localized(zh, constant.Tagline, "向量数据库攻击面评估框架"))))
	return output.String()
}

// Help 渲染总帮助或单条命令的详细用法。
//
// 参数 topic 为命令名，空字符串渲染总览。
// 返回按当前语言（en/zh）与终端能力渲染的帮助文本。
func (a *App) Help(topic string) string {
	topic = strings.ToLower(strings.TrimSpace(topic))
	if topic != "" {
		if doc, exists := commandDocs[topic]; exists {
			return renderCommandHelp(a.language, doc)
		}
		return fmt.Sprintf("vecmap: unknown command %q\n\nRun 'vecmap help' for the command list.\n", topic)
	}
	return renderOverview(a.language)
}

func renderOverview(language string) string {
	zh := language == "zh"
	var output strings.Builder
	output.WriteString(languageBanner(language) + "\n")
	output.WriteString(paint(helpTitle, localized(zh, "USAGE", "用法")) + "\n")
	output.WriteString("  vecmap <command> [options]\n")
	output.WriteString("  vecmap <command> --help\n\n")
	output.WriteString(paint(helpTitle, localized(zh, "DESCRIPTION", "说明")) + "\n")
	output.WriteString("  " + localized(zh,
		"vecmap is a local-only, sqlmap-style attack-surface assessment framework for",
		"vecmap 是一个本地运行、sqlmap 风格的攻击面评估框架，面向") + "\n")
	output.WriteString("  " + localized(zh,
		"vector databases and retrieval infrastructure (Qdrant, Milvus, Weaviate, Chroma,",
		"向量数据库与检索基础设施（Qdrant、Milvus、Weaviate、Chroma、") + "\n")
	output.WriteString("  " + localized(zh,
		"Redis, Elasticsearch, OpenSearch, pgvector, Typesense, Pinecone, Vespa).",
		"Redis、Elasticsearch、OpenSearch、pgvector、Typesense、Pinecone、Vespa）。") + "\n")
	output.WriteString("  " + localized(zh,
		"All probes are strictly read-only; destructive endpoints are never invoked.",
		"所有探测严格只读，破坏性接口一律不执行。") + "\n\n")
	output.WriteString(paint(helpTitle, localized(zh, "COMMANDS", "命令")) + "\n")
	for _, name := range []string{"scan", "discover", "dump", "sessions", "report", "advisories", "delete", "version", "help", "man", "completion"} {
		doc := commandDocs[name]
		output.WriteString(fmt.Sprintf("  %-12s %s\n", paint(helpCommand, name), localized(zh, doc.En, doc.Zh)))
	}
	output.WriteString("\n")
	output.WriteString(paint(helpTitle, localized(zh, "GLOBAL OPTIONS", "全局参数")) + "\n")
	for _, option := range globalOptions {
		output.WriteString(fmt.Sprintf("  %-22s %s\n", paint(helpFlag, option.Flag), localized(zh, option.En, option.Zh)))
	}
	output.WriteString("\n")
	output.WriteString(paint(helpTitle, localized(zh, "EXAMPLES", "示例")) + "\n")
	renderExampleLines(&output, language, scanExamples)
	output.WriteString("\n")
	output.WriteString(paint(helpTitle, localized(zh, "TARGET FORMATS", "目标格式")) + "\n")
	output.WriteString("  http://host:6333  https://host  redis://host:6379  postgres://user:pass@host/db  grpc://host:19530\n")
	output.WriteString("  " + localized(zh, "10.0.0.5:6333    10.0.0.0/24 (CIDR, expand with --ports)", "10.0.0.5:6333    10.0.0.0/24（CIDR，配合 --ports 展开）") + "\n\n")
	output.WriteString(paint(helpTitle, localized(zh, "EXIT STATUS", "退出码")) + "\n")
	output.WriteString("  " + localized(zh, "0  success        1  runtime error        2  usage error", "0  成功    1  运行期错误    2  用法错误") + "\n\n")
	output.WriteString(paint(helpTitle, localized(zh, "ENVIRONMENT", "环境变量")) + "\n")
	output.WriteString("  " + localized(zh, "VECMAP_DB     default database path (overrides ~/.vecmap/vecmap.db)", "VECMAP_DB     默认数据库路径（覆盖 ~/.vecmap/vecmap.db）") + "\n")
	output.WriteString("  " + localized(zh, "VECMAP_LANG   default UI language (en|zh)", "VECMAP_LANG   默认界面语言（en|zh）") + "\n")
	output.WriteString("  " + localized(zh, "NO_COLOR      disable colored output", "NO_COLOR      关闭彩色输出") + "\n")
	output.WriteString("  " + localized(zh, "HTTP_PROXY / HTTPS_PROXY   honored when --proxy is not set", "HTTP_PROXY / HTTPS_PROXY   未指定 --proxy 时生效") + "\n\n")
	output.WriteString(paint(helpTitle, localized(zh, "FILES", "文件")) + "\n")
	output.WriteString("  " + localized(zh, "~/.vecmap/vecmap.db   local session database (dir 0700, file 0600)", "~/.vecmap/vecmap.db   本地会话数据库（目录 0700、文件 0600）") + "\n")
	output.WriteString("  " + localized(zh, "<--output path>       session reports (0600)", "<--output 路径>        会话报告（0600）") + "\n\n")
	output.WriteString(paint(helpWarn, localized(zh,
		"AUTHORIZATION: you must obtain written permission for every target",
		"授权声明：必须事先取得每个目标范围的书面授权")) + "\n")
	output.WriteString(paint(helpWarn, localized(zh,
		"and pass --authorize. Unauthorized scanning is illegal.",
		"并传入 --authorize。未授权扫描属于违法行为。")) + "\n\n")
	output.WriteString(paint(helpDim, localized(zh,
		"See 'vecmap help <command>' for per-command options, and 'vecmap man' for the manual.",
		"使用 'vecmap help <命令>' 查看单条命令参数，'vecmap man' 输出手册页。")) + "\n")
	return output.String()
}

// renderExampleLines 输出示例块，按语言选择英文或中文注释。
//
// 参数 output 为输出缓冲，language 为 en 或 zh，examples 为示例列表。
func renderExampleLines(output *strings.Builder, language string, examples []exampleDoc) {
	zh := language == "zh"
	for _, example := range examples {
		line := example.En
		if zh && example.Zh != "" {
			line = example.Zh
		}
		if strings.HasPrefix(line, "#") {
			output.WriteString("  " + paint(helpDim, line) + "\n")
			continue
		}
		output.WriteString("  " + line + "\n")
	}
}

func renderCommandHelp(language string, doc commandDoc) string {
	zh := language == "zh"
	var output strings.Builder
	output.WriteString(paint(helpBanner, constant.Name+" "+doc.Name) + "\n\n")
	output.WriteString(paint(helpTitle, localized(zh, "SYNOPSIS", "语法")) + "\n")
	output.WriteString("  " + doc.Synopsis + "\n\n")
	output.WriteString(paint(helpTitle, localized(zh, "DESCRIPTION", "说明")) + "\n")
	output.WriteString("  " + localized(zh, doc.En, doc.Zh) + "\n\n")
	if len(doc.Options) > 0 {
		output.WriteString(paint(helpTitle, localized(zh, "OPTIONS", "参数")) + "\n")
		for _, option := range doc.Options {
			output.WriteString(fmt.Sprintf("  %-24s %s\n", paint(helpFlag, option.Flag), localized(zh, option.En, option.Zh)))
		}
		output.WriteString("\n")
	}
	if len(doc.Examples) > 0 {
		output.WriteString(paint(helpTitle, localized(zh, "EXAMPLES", "示例")) + "\n")
		renderExampleLines(&output, language, doc.Examples)
		output.WriteString("\n")
	}
	output.WriteString(paint(helpDim, localized(zh,
		"See 'vecmap help' for the command overview and exit status.",
		"使用 'vecmap help' 查看命令总览与退出码说明。")) + "\n")
	return output.String()
}

// Usage 返回总帮助文本。
//
// 兼容早期接口；等同于 Help("")。
func (a *App) Usage() string {
	return a.Help("")
}

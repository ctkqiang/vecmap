// Package logger 提供 vecmap 的终端输出，带颜色、时间戳与分级前缀。
//
// 本包已接入 internal/utilities/localisation.go：
//   - 级别前缀（[INF]/[信息] 等）在打印时才渲染，因此 setLocle() 切换语言后立即生效；
//   - LogKey / StepHeaderKey 直接用翻译键输出，调用方无需自己取词。
package logger

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"vecmap/internal/utilities"
)

// LogLevel 是日志级别。
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	CRITICAL
	SUCCESS
)

// 样式表。级别前缀不使用 SetString 固化文本，改为打印时传入本地化文案。
var (
	timeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	debugStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	infoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Bold(true)
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	critStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	succStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)

	// 传输协议名属于专有名词，不随语言切换，因此这里仍然固化文本。
	protocolTCP  = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true).SetString("TCP")
	protocolHTTP = lipgloss.NewStyle().Foreground(lipgloss.Color("33")).Bold(true).SetString("HTTP")
	protocolGRPC = lipgloss.NewStyle().Foreground(lipgloss.Color("141")).Bold(true).SetString("gRPC")

	borderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

// Logger 是日志输出器，Verbose 控制 DEBUG 级别是否打印。
type Logger struct {
	Verbose bool
}

// New 创建输出器；verbose 为 true 时打印 DEBUG 级别日志。
func New(verbose bool) *Logger {
	return &Logger{Verbose: verbose}
}

// levelStyle 把级别映射到样式与本地化键。未知级别返回 ok=false。
func levelStyle(level LogLevel) (style lipgloss.Style, key string, ok bool) {
	switch level {
	case DEBUG:
		return debugStyle, utilities.KeyLogPrefixDebug, true
	case INFO:
		return infoStyle, utilities.KeyLogPrefixInfo, true
	case WARN:
		return warnStyle, utilities.KeyLogPrefixWarn, true
	case CRITICAL:
		return critStyle, utilities.KeyLogPrefixCritical, true
	case SUCCESS:
		return succStyle, utilities.KeyLogPrefixSuccess, true
	}
	return lipgloss.Style{}, "", false
}

// Log 输出一条日志：时间戳 + 本地化级别前缀 + 按 format 渲染的消息。
// DEBUG 级别在非 verbose 模式下直接丢弃。
func (l *Logger) Log(level LogLevel, format string, args ...any) {
	if level == DEBUG && !l.Verbose {
		return
	}

	timestamp := timeStyle.Render(time.Now().Format("15:04:05.000"))

	prefix := ""
	if style, key, ok := levelStyle(level); ok {
		prefix = style.Render(utilities.T(key))
	}

	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", timestamp, prefix, msg)
}

// LogKey 输出一条已本地化的日志：文案从 localisation.go 的词典按 key 取出
// 并用 args 格式化，这样同一行代码在中英文下都能正确显示。
func (l *Logger) LogKey(level LogLevel, key string, args ...any) {
	l.Log(level, "%s", utilities.Tf(key, args...))
}

// ProtocolCall 记录一次底层传输动作（TCP / HTTP / gRPC）。
// action 与 details 由调用方传入，若为面向用户的文案应先经 utilities.T() 翻译。
func (l *Logger) ProtocolCall(proto string, target string, action string, details string) {
	timestamp := timeStyle.Render(time.Now().Format("15:04:05.000"))

	var protoTag string
	switch strings.ToUpper(proto) {
	case "TCP":
		protoTag = protocolTCP.String()
	case "HTTP":
		protoTag = protocolHTTP.String()
	case "GRPC":
		protoTag = protocolGRPC.String()
	default:
		protoTag = lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Bold(true).Render(strings.ToUpper(proto))
	}

	targetStr := lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(target)
	actionStr := lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render(action)
	detailsStr := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(details)

	fmt.Printf("%s [%s] %s ➔ %s: %s\n", timestamp, protoTag, targetStr, actionStr, detailsStr)
}

// StepHeader 打印分节标题，用 ─ 框线把不同阶段隔开。
func (l *Logger) StepHeader(title string) {
	line := borderStyle.Render(strings.Repeat("─", 60))
	headerText := lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true).Render(title)

	fmt.Printf("\n%s\n  %s\n%s\n", line, headerText, line)
}

// StepHeaderKey 与 StepHeader 相同，但标题按翻译键取值并格式化。
func (l *Logger) StepHeaderKey(key string, args ...any) {
	l.StepHeader(utilities.Tf(key, args...))
}

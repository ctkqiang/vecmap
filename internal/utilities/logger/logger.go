package logger

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	CRITICAL
	SUCCESS
)

var (
	timeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	debugStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true).SetString("[DBG]")
	infoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Bold(true).SetString("[INF]")
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true).SetString("[WRN]")
	critStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true).SetString("[CRT]")
	succStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true).SetString("[SUC]")

	protocolTCP  = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true).SetString("TCP")
	protocolHTTP = lipgloss.NewStyle().Foreground(lipgloss.Color("33")).Bold(true).SetString("HTTP")
	protocolGRPC = lipgloss.NewStyle().Foreground(lipgloss.Color("141")).Bold(true).SetString("gRPC")

	borderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
)

type Logger struct {
	Verbose bool
}

func New(verbose bool) *Logger {
	return &Logger{Verbose: verbose}
}

func (l *Logger) Log(level LogLevel, format string, args ...interface{}) {
	timestamp := timeStyle.Render(time.Now().Format("15:04:05.000"))
	var prefix string

	switch level {
	case DEBUG:
		if !l.Verbose {
			return
		}

		prefix = debugStyle.String()
	case INFO:
		prefix = infoStyle.String()
	case WARN:
		prefix = warnStyle.String()
	case CRITICAL:
		prefix = critStyle.String()
	case SUCCESS:
		prefix = succStyle.String()
	}

	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s %s\n", timestamp, prefix, msg)
}

// ProtocolCall logs explicit low-level transport actions (TCP, HTTP, gRPC) like a true red-team framework.
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

func (l *Logger) StepHeader(title string) {
	line := borderStyle.Render(strings.Repeat("─", 60))
	headerText := lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true).Render(title)

	fmt.Printf("\n%s\n  %s\n%s\n", line, headerText, line)
}

package logger

import (
	ulogger "github.com/ctkqiang/vecmap/internal/utilities/logger"
)

// Logger 是内部统一日志接口，包装用户的 Lipgloss 日志器。
//
// 引擎与适配器统一使用本适配器输出日志，
// 底层格式与样式由用户的 utilities/logger 模块负责。
type Logger struct {
	inner *ulogger.Logger
}

// New 创建内部日志器。
//
// 参数 verbose 为 true 时输出调试级别日志。
// 返回包装后的日志器。
func New(verbose bool) *Logger {
	return &Logger{inner: ulogger.New(verbose)}
}

// Debugf 输出调试日志。
//
// 参数 format 与 args 遵循 fmt.Sprintf 规则；非 verbose 模式忽略。
func (l *Logger) Debugf(format string, args ...any) {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.Log(ulogger.DEBUG, format, args...)
}

// Infof 输出信息日志。
//
// 参数 format 与 args 遵循 fmt.Sprintf 规则。
func (l *Logger) Infof(format string, args ...any) {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.Log(ulogger.INFO, format, args...)
}

// Warnf 输出警告日志。
//
// 参数 format 与 args 遵循 fmt.Sprintf 规则。
func (l *Logger) Warnf(format string, args ...any) {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.Log(ulogger.WARN, format, args...)
}

// Criticalf 输出严重错误日志。
//
// 参数 format 与 args 遵循 fmt.Sprintf 规则。
func (l *Logger) Criticalf(format string, args ...any) {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.Log(ulogger.CRITICAL, format, args...)
}

// Successf 输出成功日志。
//
// 参数 format 与 args 遵循 fmt.Sprintf 规则。
func (l *Logger) Successf(format string, args ...any) {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.Log(ulogger.SUCCESS, format, args...)
}

// ProtocolCall 输出底层传输动作日志。
//
// 参数 proto 为协议名，target 为端点，action 与 details 为动作描述。
func (l *Logger) ProtocolCall(proto, target, action, details string) {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.ProtocolCall(proto, target, action, details)
}

// StepHeader 输出阶段标题分隔线。
//
// 参数 title 为阶段标题文本。
func (l *Logger) StepHeader(title string) {
	if l == nil || l.inner == nil {
		return
	}
	l.inner.StepHeader(title)
}

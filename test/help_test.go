package test

import (
	"errors"
	"strings"
	"testing"

	"vecmap/internal/app"
)

func TestParseArgsHelpTopic(t *testing.T) {
	command, err := app.ParseArgs([]string{"scan", "--help"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.Action != "help" || command.HelpTopic != "scan" {
		t.Fatalf("expected help topic scan, got action=%s topic=%s", command.Action, command.HelpTopic)
	}
	command, err = app.ParseArgs([]string{"help", "report"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.HelpTopic != "report" {
		t.Fatalf("expected report topic, got %q", command.HelpTopic)
	}
}

func TestParseArgsGlobalVersion(t *testing.T) {
	command, err := app.ParseArgs([]string{"--version"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.Action != "version" {
		t.Fatalf("expected version action, got %q", command.Action)
	}
}

func TestParseArgsManAndCompletion(t *testing.T) {
	command, err := app.ParseArgs([]string{"completion", "bash"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.Action != "completion" || command.Shell != "bash" {
		t.Fatalf("unexpected completion command: %+v", command)
	}
	if _, err := app.ParseArgs([]string{"completion"}); err == nil {
		t.Fatalf("expected completion without shell to fail")
	}
	command, err = app.ParseArgs([]string{"man"})
	if err != nil {
		t.Fatalf("ParseArgs man: %v", err)
	}
	if command.Action != "man" {
		t.Fatalf("expected man action, got %q", command.Action)
	}
}

func TestParseArgsEnvironmentDefaults(t *testing.T) {
	t.Setenv("VECMAP_DB", "/tmp/custom-vecmap.db")
	t.Setenv("VECMAP_LANG", "zh")
	command, err := app.ParseArgs([]string{"sessions"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.DBPath != "/tmp/custom-vecmap.db" {
		t.Fatalf("expected VECMAP_DB default, got %q", command.DBPath)
	}
	if command.Language != "zh" {
		t.Fatalf("expected VECMAP_LANG default, got %q", command.Language)
	}
}

func TestParseArgsFlagOverridesEnv(t *testing.T) {
	t.Setenv("VECMAP_DB", "/tmp/custom-vecmap.db")
	command, err := app.ParseArgs([]string{"sessions", "--db", "/tmp/flag.db"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.DBPath != "/tmp/flag.db" {
		t.Fatalf("expected flag to override env, got %q", command.DBPath)
	}
}

func TestUsageErrorClassification(t *testing.T) {
	if _, err := app.ParseArgs([]string{"nope"}); !isUsageError(err) {
		t.Fatalf("expected UsageError, got %v", err)
	}
	if _, err := app.ParseArgs(nil); !isUsageError(err) {
		t.Fatalf("expected UsageError for missing command, got %v", err)
	}
}

func TestHelpOverviewContent(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "en"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	content := application.Help("")
	for _, want := range []string{"USAGE", "COMMANDS", "scan", "discover", "report", "EXIT STATUS", "VECMAP_DB", "--authorize", "EXAMPLES"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected overview help to contain %q", want)
		}
	}
}

func TestHelpCommandTopic(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "en"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	content := application.Help("scan")
	for _, want := range []string{"SYNOPSIS", "vecmap scan [OPTIONS] TARGET...", "--mode standard|deep", "--api-key", "--scope-cidr"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected scan help to contain %q", want)
		}
	}
	if unknown := application.Help("frobnicate"); !strings.Contains(unknown, "unknown command") {
		t.Fatalf("expected unknown topic message, got %q", unknown)
	}
}

func TestHelpChinese(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "zh"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	content := application.Help("")
	if !strings.Contains(content, "用法") || !strings.Contains(content, "命令") {
		t.Fatalf("expected Chinese overview help")
	}
	scan := application.Help("scan")
	if !strings.Contains(scan, "语法") || !strings.Contains(scan, "攻击面") {
		t.Fatalf("expected Chinese scan help")
	}
}

func TestHelpChineseFullyLocalized(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "zh"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	content := application.Help("")
	for _, want := range []string{"退出码", "环境变量", "目标格式", "文件", "默认数据库路径", "本地会话数据库", "配合 --ports 展开", "授权声明", "向量数据库攻击面评估框架"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected Chinese overview to contain %q", want)
		}
	}
	if strings.Contains(content, "runtime error") {
		t.Fatalf("expected exit-status section to be localized")
	}
	scan := application.Help("scan")
	if !strings.Contains(scan, "标准扫描单个 Qdrant 主机") {
		t.Fatalf("expected Chinese example comments in scan help, got:\n%s", scan)
	}
}

func TestDefaultLanguageLocaleDetection(t *testing.T) {
	t.Setenv("VECMAP_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "zh_CN.UTF-8")
	if got := app.DefaultLanguage(); got != "zh" {
		t.Fatalf("expected zh from locale, got %q", got)
	}
	t.Setenv("LANG", "en_US.UTF-8")
	if got := app.DefaultLanguage(); got != "en" {
		t.Fatalf("expected en from locale, got %q", got)
	}
}

func TestDefaultLanguageEnvWins(t *testing.T) {
	t.Setenv("LANG", "zh_CN.UTF-8")
	t.Setenv("VECMAP_LANG", "en")
	if got := app.DefaultLanguage(); got != "en" {
		t.Fatalf("expected VECMAP_LANG to override locale, got %q", got)
	}
}

func TestManPage(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "en"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	content := application.Man()
	for _, want := range []string{".TH VECMAP 1", ".SH NAME", ".SH SYNOPSIS", ".SH GLOBAL OPTIONS", ".SH EXIT STATUS", `scope\-cidr`, `\-\-authorize`, ".SH FILES"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected man page to contain %q", want)
		}
	}
}

func TestCompletionScripts(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "en"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	bash, err := application.Completion("bash")
	if err != nil {
		t.Fatalf("Completion bash: %v", err)
	}
	if !strings.Contains(bash, "_vecmap_complete") || !strings.Contains(bash, "complete -F") {
		t.Fatalf("unexpected bash completion script")
	}
	zsh, err := application.Completion("zsh")
	if err != nil {
		t.Fatalf("Completion zsh: %v", err)
	}
	if !strings.Contains(zsh, "#compdef vecmap") || !strings.Contains(zsh, "_arguments") {
		t.Fatalf("unexpected zsh completion script")
	}
	if _, err := application.Completion("fish"); err == nil {
		t.Fatalf("expected unsupported shell to fail")
	}
}

func TestParseArgsUsageFlag(t *testing.T) {
	command, err := app.ParseArgs([]string{"scan", "--usage"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.Action != "scan" || !command.UsageFlag {
		t.Fatalf("expected scan with usage flag, got %+v", command)
	}
	command, err = app.ParseArgs([]string{"--usage"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if !command.UsageFlag {
		t.Fatalf("expected top-level --usage to set usage flag")
	}
}

func TestUsageSynopsis(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "en"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	if got := application.UsageSynopsis("scan"); !strings.Contains(got, "vecmap scan [OPTIONS] TARGET...") {
		t.Fatalf("unexpected scan synopsis: %q", got)
	}
	if got := application.UsageSynopsis(""); !strings.Contains(got, "vecmap <command> [options]") {
		t.Fatalf("unexpected overview synopsis: %q", got)
	}
	if got := application.UsageSynopsis("nope"); !strings.Contains(got, "vecmap help") {
		t.Fatalf("expected fallback synopsis, got %q", got)
	}
}

func TestBanner(t *testing.T) {
	application, err := app.NewLite(app.Config{Language: "en"})
	if err != nil {
		t.Fatalf("NewLite: %v", err)
	}
	banner := application.Banner()
	if !strings.Contains(banner, "vecmap v1.0.0") {
		t.Fatalf("expected version in banner, got: %s", banner)
	}
	if !strings.Contains(banner, "_____") {
		t.Fatalf("expected ASCII art in banner")
	}
}

func TestSeverityAndStatusStylesNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if got := app.SeverityStyle("critical", "CRITICAL"); got != "CRITICAL" {
		t.Fatalf("expected plain text under NO_COLOR, got %q", got)
	}
	if got := app.StatusStyle("completed", "completed"); got != "completed" {
		t.Fatalf("expected plain text under NO_COLOR, got %q", got)
	}
}

func isUsageError(err error) bool {
	var usageError *app.UsageError
	return errors.As(err, &usageError)
}

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

func isUsageError(err error) bool {
	var usageError *app.UsageError
	return errors.As(err, &usageError)
}

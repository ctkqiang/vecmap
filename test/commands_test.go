package test

import (
	"testing"

	"github.com/ctkqiang/vecmap/internal/app"
)

func TestParseArgsScan(t *testing.T) {
	command, err := app.ParseArgs([]string{
		"scan", "--authorize", "-lang", "zh", "--mode", "deep",
		"--ports", "6333,6334", "--extract", "--vectors", "--max-records", "50",
		"--scope-cidr", "10.0.0.0/24", "--exclude-domain", "internal.example.com",
		"--api-key", "secret", "--collection", "docs",
		"http://10.0.0.5:6333",
	})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if command.Action != "scan" || !command.Authorized || command.Language != "zh" {
		t.Fatalf("unexpected command: %+v", command)
	}
	if len(command.Targets) != 1 || command.Targets[0] != "http://10.0.0.5:6333" {
		t.Fatalf("unexpected targets: %v", command.Targets)
	}
	if len(command.Ports) != 2 || command.Ports[0] != 6333 {
		t.Fatalf("unexpected ports: %v", command.Ports)
	}
	if !command.Extract || !command.IncludeVectors || command.MaxRecords != 50 {
		t.Fatalf("unexpected extract options: %+v", command)
	}
	request := command.BuildScanRequest()
	if !request.Authorized {
		t.Fatalf("expected authorized request")
	}
	if request.Options.Mode != "deep" {
		t.Fatalf("expected deep mode, got %s", request.Options.Mode)
	}
	if request.Options.Collection != "docs" {
		t.Fatalf("expected collection filter, got %q", request.Options.Collection)
	}
	if len(request.Scope.CIDRs) != 1 || len(request.Scope.ExcludeDomains) != 1 {
		t.Fatalf("unexpected scope: %+v", request.Scope)
	}
	if request.Options.Credentials.APIKey != "secret" {
		t.Fatalf("expected API key in credentials")
	}
}

func TestParseArgsUnknownCommand(t *testing.T) {
	if _, err := app.ParseArgs([]string{"frobnicate"}); err == nil {
		t.Fatalf("expected unknown command error")
	}
}

func TestParseArgsNoCommand(t *testing.T) {
	if _, err := app.ParseArgs(nil); err == nil {
		t.Fatalf("expected missing command error")
	}
}

func TestParseArgsDumpImpliesDeep(t *testing.T) {
	command, err := app.ParseArgs([]string{"dump", "--authorize", "10.0.0.5:6333"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	request := command.BuildScanRequest()
	if request.Options.Mode != "deep" || !request.Options.Extract {
		t.Fatalf("expected dump to force deep extraction: %+v", request.Options)
	}
}

func TestParseArgsReport(t *testing.T) {
	command, err := app.ParseArgs([]string{"report", "--session", "ses_abc", "--format", "json", "--output", "/tmp/report.json"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	options := command.BuildReportOptions()
	if options.Format != "json" || options.Path != "/tmp/report.json" {
		t.Fatalf("unexpected report options: %+v", options)
	}
	if command.SessionID != "ses_abc" {
		t.Fatalf("unexpected session id: %q", command.SessionID)
	}
}

func TestParseArgsHeaders(t *testing.T) {
	command, err := app.ParseArgs([]string{"scan", "--authorize", "--header", "X-Foo: bar", "--header", "X-Baz:qux", "10.0.0.5"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	request := command.BuildScanRequest()
	if request.Options.Headers["X-Foo"] != "bar" || request.Options.Headers["X-Baz"] != "qux" {
		t.Fatalf("unexpected headers: %v", request.Options.Headers)
	}
}

func TestParseArgsTimeout(t *testing.T) {
	command, err := app.ParseArgs([]string{"scan", "--authorize", "--timeout", "12s", "10.0.0.5"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	request := command.BuildScanRequest()
	if request.Options.Timeout.String() != "12s" {
		t.Fatalf("expected 12s timeout, got %s", request.Options.Timeout)
	}
}

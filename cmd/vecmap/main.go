package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"vecmap/internal/app"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vecmap: %s\n", err)
		os.Exit(1)
	}
}

// run 执行解析后的命令。
//
// 参数 args 为命令行参数；返回处理错误，正常退出返回 nil。
func run(args []string) error {
	command, err := app.ParseArgs(args)
	if err != nil {
		return err
	}
	if command.Action == "version" || command.Action == "help" || command.Action == "advisories" {
		return runLite(command)
	}
	application, err := app.New(app.Config{
		DatabasePath:   command.DBPath,
		AdvisoriesPath: command.AdvisoriesPath,
		Verbose:        command.Verbose,
		Language:       command.Language,
	})
	if err != nil {
		return err
	}
	defer func() { _ = application.Close() }()
	switch command.Action {
	case "scan", "dump":
		return runScan(application, command)
	case "discover":
		return runDiscover(application, command)
	case "sessions":
		return runSessions(application)
	case "report":
		return runReport(application, command)
	case "delete":
		return runDelete(application, command)
	default:
		return fmt.Errorf("unknown command: %s", command.Action)
	}
}

// runLite 执行不依赖本地数据库的只读命令。
//
// 参数 command 为解析后的命令；这些命令不会创建数据库文件。
func runLite(command *app.Command) error {
	application, err := app.NewLite(app.Config{
		AdvisoriesPath: command.AdvisoriesPath,
		Verbose:        command.Verbose,
		Language:       command.Language,
	})
	if err != nil {
		return err
	}
	switch command.Action {
	case "version":
		fmt.Println(application.Version())
	case "help":
		fmt.Print(application.Usage())
	case "advisories":
		return runAdvisories(application, command)
	}
	return nil
}

func runScan(application *app.App, command *app.Command) error {
	if !command.Authorized {
		return fmt.Errorf("%s (pass --authorize after obtaining written permission)", utilities.TIn(command.Language, "err.authorization"))
	}
	if len(command.Targets) == 0 {
		return fmt.Errorf("no targets supplied")
	}
	result, err := application.RunScan(command.BuildScanRequest())
	if err != nil {
		return err
	}
	printScanSummary(application, result)
	return nil
}

func runDiscover(application *app.App, command *app.Command) error {
	if !command.Authorized {
		return fmt.Errorf("%s (pass --authorize after obtaining written permission)", utilities.TIn(command.Language, "err.authorization"))
	}
	if len(command.Targets) == 0 {
		return fmt.Errorf("no hosts supplied")
	}
	_, err := application.RunDiscover(command.BuildScanRequest())
	return err
}

func runSessions(application *app.App) error {
	sessions, total, err := application.ListSessions(50, 0)
	if err != nil {
		return err
	}
	if total == 0 {
		fmt.Println(utilities.TIn(application.Language(), "report.none"))
		return nil
	}
	fmt.Printf("%-24s  %-10s  %-20s  %s\n", "ID", "MODE", "STATUS", "STARTED")
	for _, session := range sessions {
		fmt.Printf("%-24s  %-10s  %-20s  %s\n", session.ID, session.Mode, session.Status, session.StartedAt.Local().Format("2006-01-02 15:04:05"))
	}
	return nil
}

func runReport(application *app.App, command *app.Command) error {
	if command.SessionID == "" {
		return fmt.Errorf("--session is required")
	}
	output, err := application.Report(command.SessionID, command.BuildReportOptions())
	if err != nil {
		return err
	}
	if output != "" {
		fmt.Print(output)
	}
	return nil
}

func runAdvisories(application *app.App, command *app.Command) error {
	advisories := application.Advisories()
	fmt.Printf("%s\n\n", utilities.TfIn(command.Language, "msg.advisories.count", len(advisories)))
	fmt.Printf("%-18s  %-12s  %-10s  %-10s  %-34s  %s\n", "ID", "VENDOR", "SEVERITY", "MATCHABLE", "AFFECTED", "TITLE")
	for _, advisory := range advisories {
		affected := strings.Join(advisory.Affected, "; ")
		if affected == "" {
			affected = "-"
		}
		matchable := "no"
		if advisory.Matchable {
			matchable = "yes"
		}
		title := advisory.Title
		if command.Language == "zh" && advisory.TitleZH != "" {
			title = advisory.TitleZH
		}
		fmt.Printf("%-18s  %-12s  %-10s  %-10s  %-34s  %s\n",
			advisory.ID, advisory.Vendor, advisory.Severity, matchable, utilities.Truncate(affected, 34), utilities.Truncate(title, 60))
	}
	return nil
}

func runDelete(application *app.App, command *app.Command) error {
	if command.SessionID == "" {
		return fmt.Errorf("--session is required")
	}
	if err := application.DeleteSession(command.SessionID); err != nil {
		return err
	}
	fmt.Println(utilities.TfIn(command.Language, "msg.session.deleted", command.SessionID))
	return nil
}

func printScanSummary(application *app.App, result *model.ScanResult) {
	language := application.Language()
	fmt.Println()
	for _, target := range result.Targets {
		vendor := target.Vendor
		if vendor == model.VendorUnknown {
			vendor = "?"
		}
		fmt.Printf("  %-40s %-14s %-24s %s\n", target.BaseURL(), vendor, utilities.Truncate(target.Product, 24), target.Version)
	}
	fmt.Println()
	if len(result.Findings) == 0 {
		fmt.Println("  " + utilities.TIn(language, "msg.no.findings"))
	} else {
		sorted := append([]*model.Finding(nil), result.Findings...)
		sort.SliceStable(sorted, func(left, right int) bool {
			return sorted[left].Severity.Rank() > sorted[right].Severity.Rank()
		})
		for _, finding := range sorted {
			title := finding.Title
			if language == "zh" && finding.TitleZH != "" {
				title = finding.TitleZH
			}
			fmt.Printf("  [%s] %s (%s)\n", strings.ToUpper(string(finding.Severity)), title, finding.Category)
		}
	}
	if session := result.Session; session != nil {
		fmt.Printf("\n  session: %s\n", session.ID)
	}
	for _, message := range result.Errors {
		fmt.Printf("  ! %s\n", message)
	}
	fmt.Println()
}

package main

import (
	"errors"
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
		var usageError *app.UsageError
		if errors.As(err, &usageError) {
			fmt.Fprintf(os.Stderr, "vecmap: %s\n\n", usageError.Message)
			printUsageHint(os.Args[1:])
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "vecmap: %s\n", err)
		os.Exit(1)
	}
}

// printUsageHint 在使用错误时向 stderr 输出对应命令的用法行。
//
// 参数 args 为原始命令行参数；无法定位命令时输出总览用法。
func printUsageHint(args []string) {
	action := "help"
	if len(args) > 0 {
		action = strings.ToLower(args[0])
	}
	language := app.DefaultLanguage()
	lite, err := app.NewLite(app.Config{Language: language})
	if err != nil {
		return
	}
	hintTopic := action
	hint := utilities.TfIn(language, "cli.hint.full", action)
	if !lite.HasCommand(action) {
		hintTopic = ""
		hint = utilities.TIn(language, "cli.hint.overview")
	}
	fmt.Fprintf(os.Stderr, "%s\n%s\n", lite.UsageSynopsis(hintTopic), hint)
}

// run 执行解析后的命令。
//
// 参数 args 为命令行参数；返回处理错误，正常退出返回 nil。
func run(args []string) error {
	command, err := app.ParseArgs(args)
	if err != nil {
		return err
	}
	if command.UsageFlag {
		lite, liteErr := app.NewLite(app.Config{Language: command.Language})
		if liteErr != nil {
			return liteErr
		}
		topic := command.HelpTopic
		if topic == "" && command.Action != "help" {
			topic = command.Action
		}
		fmt.Print(lite.UsageSynopsis(topic))
		return nil
	}
	if command.Action == "version" || command.Action == "help" || command.Action == "advisories" || command.Action == "man" || command.Action == "completion" {
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
		return app.Usagef("%s", utilities.TfIn(command.Language, "cli.usage.unknown", command.Action))
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
		fmt.Print(application.Help(command.HelpTopic))
	case "advisories":
		return runAdvisories(application, command)
	case "man":
		fmt.Print(application.Man())
	case "completion":
		script, err := application.Completion(command.Shell)
		if err != nil {
			return app.Usagef("%v", err)
		}
		fmt.Print(script)
	}
	return nil
}

func runScan(application *app.App, command *app.Command) error {
	if !command.Authorized {
		return app.Usagef("%s", utilities.TIn(command.Language, "cli.usage.authorize"))
	}
	if len(command.Targets) == 0 {
		return app.Usagef("%s", utilities.TfIn(command.Language, "cli.usage.targets", command.Action))
	}
	fmt.Println(application.Banner())
	result, err := application.RunScan(command.BuildScanRequest())
	if err != nil {
		return err
	}
	printScanSummary(application, result)
	return nil
}

func runDiscover(application *app.App, command *app.Command) error {
	if !command.Authorized {
		return app.Usagef("%s", utilities.TIn(command.Language, "cli.usage.authorize"))
	}
	if len(command.Targets) == 0 {
		return app.Usagef("%s", utilities.TIn(command.Language, "cli.usage.hosts"))
	}
	fmt.Println(application.Banner())
	_, err := application.RunDiscover(command.BuildScanRequest())
	return err
}

func runSessions(application *app.App) error {
	language := application.Language()
	sessions, total, err := application.ListSessions(50, 0)
	if err != nil {
		return err
	}
	if total == 0 {
		fmt.Println(utilities.TIn(language, "report.none"))
		return nil
	}
	fmt.Printf("%-24s  %-10s  %-20s  %s\n",
		utilities.TIn(language, "cli.table.id"), utilities.TIn(language, "cli.table.mode"),
		utilities.TIn(language, "cli.table.status"), utilities.TIn(language, "cli.table.started"))
	for _, session := range sessions {
		fmt.Printf("%-24s  %-10s  %-20s  %s\n", session.ID, session.Mode,
			app.StatusStyle(session.Status, session.Status),
			session.StartedAt.Local().Format("2006-01-02 15:04:05"))
	}
	return nil
}

func runReport(application *app.App, command *app.Command) error {
	if command.SessionID == "" {
		return app.Usagef("%s", utilities.TfIn(command.Language, "cli.usage.session", "report"))
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
	language := command.Language
	advisories := application.Advisories()
	fmt.Printf("%s\n\n", utilities.TfIn(language, "msg.advisories.count", len(advisories)))
	fmt.Printf("%-18s  %-12s  %-10s  %-10s  %-34s  %s\n",
		utilities.TIn(language, "cli.table.id"), utilities.TIn(language, "cli.table.vendor"),
		utilities.TIn(language, "cli.table.severity"), utilities.TIn(language, "cli.table.matchable"),
		utilities.TIn(language, "cli.table.affected"), utilities.TIn(language, "cli.table.title"))
	for _, advisory := range advisories {
		affected := strings.Join(advisory.Affected, "; ")
		if affected == "" {
			affected = "-"
		}
		matchable := utilities.TIn(language, "cli.no")
		if advisory.Matchable {
			matchable = utilities.TIn(language, "cli.yes")
		}
		title := advisory.Title
		if language == "zh" && advisory.TitleZH != "" {
			title = advisory.TitleZH
		}
		fmt.Printf("%-18s  %-12s  %-10s  %-10s  %-34s  %s\n",
			advisory.ID, advisory.Vendor,
			app.SeverityStyle(advisory.Severity, string(advisory.Severity)),
			matchable, utilities.Truncate(affected, 34), utilities.Truncate(title, 60))
	}
	return nil
}

func runDelete(application *app.App, command *app.Command) error {
	if command.SessionID == "" {
		return app.Usagef("%s", utilities.TfIn(command.Language, "cli.usage.session", "delete"))
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
			severityText := app.SeverityStyle(finding.Severity, "["+strings.ToUpper(string(finding.Severity))+"]")
			category := utilities.TIn(language, "cat."+finding.Category)
			fmt.Printf("  %-10s %s (%s)\n", severityText, title, category)
		}
	}
	if session := result.Session; session != nil {
		fmt.Printf("  %s\n", utilities.TfIn(language, "cli.summary.session", session.ID, app.StatusStyle(session.Status, session.Status)))
	}
	if len(result.Records) > 0 {
		fmt.Printf("  %s\n", utilities.TfIn(language, "msg.records.extracted", len(result.Records), len(result.Collections)))
	}
	for _, message := range result.Errors {
		fmt.Printf("  ! %s\n", message)
	}
	fmt.Println()
}

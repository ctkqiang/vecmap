package app

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"vecmap/internal/model"
)

// Command 表示一条解析完成的命令行指令。
type Command struct {
	Action         string
	Targets        []string
	Name           string
	Mode           string
	Ports          []int
	Timeout        time.Duration
	TimeoutText    string
	Concurrency    int
	RateLimit      float64
	Insecure       bool
	Fuzz           bool
	Extract        bool
	MaxRecords     int
	BatchSize      int
	IncludeVectors bool
	UserAgent      string
	Proxy          string
	Headers        []string
	Username       string
	Password       string
	APIKey         string
	Bearer         string
	Database       string
	DSN            string
	ScopeCIDRs     []string
	ScopeDomains   []string
	ExcludeCIDRs   []string
	ExcludeDomains []string
	ScopePorts     []int
	Collection     string
	Namespace      string
	AdvisoriesPath string
	Language       string
	DBPath         string
	Output         string
	Format         string
	SessionID      string
	Verbose        bool
	DryRun         bool
	Authorized     bool
	Help           bool
}

// ParseArgs 解析命令行参数。
//
// 参数 args 为 os.Args[1:]。
// 返回命令实例；参数非法或缺少命令时返回错误。
func ParseArgs(args []string) (*Command, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command supplied")
	}
	command := &Command{Action: args[0], Language: "en", Timeout: 8 * time.Second, Concurrency: 8}
	switch command.Action {
	case "scan":
		parseScanFlags(command, args[1:])
	case "discover":
		parseDiscoverFlags(command, args[1:])
	case "dump":
		parseScanFlags(command, args[1:])
		command.Extract = true
		command.Mode = "deep"
	case "sessions":
		parseSessionsFlags(command, args[1:])
	case "report":
		parseReportFlags(command, args[1:])
	case "advisories":
		parseGlobalFlags(command, args[1:])
	case "delete":
		parseDeleteFlags(command, args[1:])
	case "version":
		parseGlobalFlags(command, args[1:])
	case "help", "--help", "-h":
		command.Action = "help"
		parseGlobalFlags(command, args[1:])
	default:
		return nil, fmt.Errorf("unknown command: %s", command.Action)
	}
	if command.Help && command.Action != "help" {
		command.Action = "help"
	}
	return command, nil
}

// BuildScanRequest 将命令转换为扫描请求。
//
// 参数 command 为已解析命令。
// 返回包含目标、范围、凭据与选项的请求。
func (c *Command) BuildScanRequest() model.ScanRequest {
	options := model.ScanOptions{
		Mode:           model.ScanMode(c.Mode),
		Ports:          c.Ports,
		Timeout:        c.Timeout,
		Concurrency:    c.Concurrency,
		RateLimit:      c.RateLimit,
		Insecure:       c.Insecure,
		Fuzz:           c.Fuzz,
		Extract:        c.Extract,
		Collection:     c.Collection,
		Namespace:      c.Namespace,
		MaxRecords:     c.MaxRecords,
		BatchSize:      c.BatchSize,
		IncludeVectors: c.IncludeVectors,
		UserAgent:      c.UserAgent,
		Proxy:          c.Proxy,
		Headers:        parseHeaders(c.Headers),
		AdvisoriesPath: c.AdvisoriesPath,
		DryRun:         c.DryRun,
	}
	options.Credentials = model.Credentials{
		Username: c.Username,
		Password: c.Password,
		APIKey:   c.APIKey,
		Bearer:   c.Bearer,
		Database: c.Database,
		DSN:      c.DSN,
	}
	scope := model.Scope{
		CIDRs:          c.ScopeCIDRs,
		Domains:        c.ScopeDomains,
		ExcludeCIDRs:   c.ExcludeCIDRs,
		ExcludeDomains: c.ExcludeDomains,
		Ports:          c.ScopePorts,
	}
	options = options.Normalize()
	return model.ScanRequest{
		Targets:    c.Targets,
		Name:       c.Name,
		Scope:      scope,
		Options:    options,
		Authorized: c.Authorized,
	}
}

// BuildReportOptions 将命令转换为报告选项。
//
// 参数 command 为已解析命令。
// 返回格式、语言与输出路径配置。
func (c *Command) BuildReportOptions() model.ReportOptions {
	format := model.ReportMarkdown
	switch strings.ToLower(c.Format) {
	case "json":
		format = model.ReportJSON
	case "html":
		format = model.ReportHTML
	case "md", "markdown", "":
		format = model.ReportMarkdown
	}
	return model.ReportOptions{Format: format, Language: c.Language, Path: c.Output}
}

func parseGlobalFlags(command *Command, args []string) {
	set := flag.NewFlagSet("vecmap", flag.ContinueOnError)
	set.StringVar(&command.DBPath, "db", "", "database path")
	set.StringVar(&command.Language, "lang", "en", "language")
	set.BoolVar(&command.Verbose, "verbose", false, "verbose output")
	set.BoolVar(&command.Help, "help", false, "show help")
	set.BoolVar(&command.Help, "h", false, "show help")
	_ = set.Parse(args)
}

func parseScanFlags(command *Command, args []string) {
	set := flag.NewFlagSet("scan", flag.ContinueOnError)
	set.StringVar(&command.DBPath, "db", "", "database path")
	set.StringVar(&command.Language, "lang", "en", "language")
	set.BoolVar(&command.Verbose, "verbose", false, "verbose output")
	set.BoolVar(&command.Help, "help", false, "show help")
	set.StringVar(&command.Name, "name", "", "session name")
	set.StringVar(&command.Mode, "mode", "standard", "scan mode")
	set.StringVar(&command.TimeoutText, "timeout", "8s", "request timeout")
	set.IntVar(&command.Concurrency, "concurrency", 8, "concurrency")
	set.Float64Var(&command.RateLimit, "rate", 0, "rate limit")
	set.BoolVar(&command.Insecure, "insecure", false, "skip TLS verification")
	set.BoolVar(&command.Fuzz, "fuzz", false, "extended path probing")
	set.BoolVar(&command.Extract, "extract", false, "extract records")
	set.IntVar(&command.MaxRecords, "max-records", 0, "record limit")
	set.IntVar(&command.BatchSize, "batch", 0, "batch size")
	set.BoolVar(&command.IncludeVectors, "vectors", false, "include vector samples")
	set.StringVar(&command.UserAgent, "user-agent", "", "user agent")
	set.StringVar(&command.Proxy, "proxy", "", "proxy URL")
	set.StringVar(&command.Username, "user", "", "username")
	set.StringVar(&command.Password, "pass", "", "password")
	set.StringVar(&command.APIKey, "api-key", "", "API key")
	set.StringVar(&command.Bearer, "bearer", "", "bearer token")
	set.StringVar(&command.Database, "database", "", "database name")
	set.StringVar(&command.DSN, "dsn", "", "connection DSN")
	set.StringVar(&command.Collection, "collection", "", "collection filter")
	set.StringVar(&command.Namespace, "namespace", "", "namespace filter")
	set.StringVar(&command.AdvisoriesPath, "advisories", "", "advisories JSON")
	set.BoolVar(&command.DryRun, "dry-run", false, "do not persist")
	set.BoolVar(&command.Authorized, "authorize", false, "authorization confirmation")
	multiString(set, "header", &command.Headers, "request header k=v")
	multiString(set, "scope-cidr", &command.ScopeCIDRs, "authorized CIDR")
	multiString(set, "scope-domain", &command.ScopeDomains, "authorized domain")
	multiString(set, "exclude-cidr", &command.ExcludeCIDRs, "excluded CIDR")
	multiString(set, "exclude-domain", &command.ExcludeDomains, "excluded domain")
	multiInt(set, "ports", &command.Ports, "ports")
	multiInt(set, "scope-port", &command.ScopePorts, "authorized ports")
	_ = set.Parse(args)
	command.Targets = set.Args()
	command.Timeout = parseTimeout(command.TimeoutText)
	if command.Extract {
		command.Mode = "deep"
	}
}

func parseDiscoverFlags(command *Command, args []string) {
	set := flag.NewFlagSet("discover", flag.ContinueOnError)
	set.StringVar(&command.DBPath, "db", "", "database path")
	set.StringVar(&command.Language, "lang", "en", "language")
	set.BoolVar(&command.Verbose, "verbose", false, "verbose output")
	set.BoolVar(&command.Help, "help", false, "show help")
	set.StringVar(&command.Name, "name", "", "session name")
	set.StringVar(&command.TimeoutText, "timeout", "5s", "probe timeout")
	set.IntVar(&command.Concurrency, "concurrency", 64, "concurrency")
	set.BoolVar(&command.DryRun, "dry-run", false, "do not persist")
	set.BoolVar(&command.Authorized, "authorize", false, "authorization confirmation")
	multiString(set, "scope-cidr", &command.ScopeCIDRs, "authorized CIDR")
	multiString(set, "scope-domain", &command.ScopeDomains, "authorized domain")
	multiString(set, "exclude-cidr", &command.ExcludeCIDRs, "excluded CIDR")
	multiString(set, "exclude-domain", &command.ExcludeDomains, "excluded domain")
	multiInt(set, "ports", &command.Ports, "ports")
	_ = set.Parse(args)
	command.Targets = set.Args()
	command.Timeout = parseTimeout(command.TimeoutText)
}

func parseSessionsFlags(command *Command, args []string) {
	set := flag.NewFlagSet("sessions", flag.ContinueOnError)
	set.StringVar(&command.DBPath, "db", "", "database path")
	set.StringVar(&command.Language, "lang", "en", "language")
	set.BoolVar(&command.Verbose, "verbose", false, "verbose output")
	set.BoolVar(&command.Help, "help", false, "show help")
	_ = set.Parse(args)
}

func parseReportFlags(command *Command, args []string) {
	set := flag.NewFlagSet("report", flag.ContinueOnError)
	set.StringVar(&command.DBPath, "db", "", "database path")
	set.StringVar(&command.Language, "lang", "en", "language")
	set.BoolVar(&command.Verbose, "verbose", false, "verbose output")
	set.BoolVar(&command.Help, "help", false, "show help")
	set.StringVar(&command.SessionID, "session", "", "session ID")
	set.StringVar(&command.Format, "format", "markdown", "markdown|json|html")
	set.StringVar(&command.Output, "output", "", "output file")
	_ = set.Parse(args)
}

func parseDeleteFlags(command *Command, args []string) {
	set := flag.NewFlagSet("delete", flag.ContinueOnError)
	set.StringVar(&command.DBPath, "db", "", "database path")
	set.StringVar(&command.Language, "lang", "en", "language")
	set.BoolVar(&command.Verbose, "verbose", false, "verbose output")
	set.BoolVar(&command.Help, "help", false, "show help")
	set.StringVar(&command.SessionID, "session", "", "session ID")
	_ = set.Parse(args)
}

func multiString(set *flag.FlagSet, name string, target *[]string, usage string) {
	set.Func(name, usage, func(value string) error {
		*target = append(*target, value)
		return nil
	})
}

func multiInt(set *flag.FlagSet, name string, target *[]int, usage string) {
	set.Func(name, usage, func(value string) error {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			number, err := strconv.Atoi(part)
			if err != nil || number < 1 || number > 65535 {
				return fmt.Errorf("invalid port %q", part)
			}
			*target = append(*target, number)
		}
		return nil
	})
}

func parseTimeout(value string) time.Duration {
	if value == "" {
		return 8 * time.Second
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 8 * time.Second
	}
	if duration <= 0 {
		return 8 * time.Second
	}
	return duration
}

func parseHeaders(values []string) map[string]string {
	result := map[string]string{}
	for _, value := range values {
		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

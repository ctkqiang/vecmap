package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vecmap/internal/constant"
	"vecmap/internal/database"
	"vecmap/internal/engine"
	"vecmap/internal/model"
	"vecmap/internal/reporter"
	"vecmap/internal/utilities"
	"vecmap/internal/utilities/logger"
)

// setLocle 按用户设备设置选定界面语言（en / zh）：
// 依次读取 LC_ALL > LC_MESSAGES > LANG，取不到时读 macOS 系统语言，
// 最后回退到英文。应用内所有文案都通过 utilities.T()/Tf() 按该语言取值。
func setLocle() utilities.Language {
	lang := utilities.InitLocale()
	log := logger.New(false)
	log.LogKey(logger.INFO, utilities.KeyLangDetected, utilities.LangName(lang))

	return lang
}

// main 是程序入口：先定语言，再把参数交给 run 分派。
func main() {
	lang := setLocle()
	os.Exit(run(os.Args[1:], lang))
}

// run 根据子命令分派，返回进程退出码。
func run(args []string, lang utilities.Language) int {
	if len(args) == 0 {
		fmt.Println(utilities.T(utilities.KeyCLIUsage))
		return 0
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], lang)
	case "sessions":
		return runSessions(args[1:])
	case "show":
		return runShow(args[1:])
	case "help", "-h", "--help":
		fmt.Println(utilities.T(utilities.KeyCLIUsage))
		return 0
	default:
		logger.New(false).LogKey(logger.CRITICAL, utilities.KeyCLIUnknownCommand, args[0])
		fmt.Println(utilities.T(utilities.KeyCLIUsage))
		return 2
	}
}

// cliOptions 保存所有子命令共用的参数。
type cliOptions struct {
	dbPath  string
	verbose bool
	jsonOut bool
	out     string
}

// registerStore 注册存储与日志参数。
func (o *cliOptions) registerStore(fs *flag.FlagSet) {
	fs.StringVar(&o.dbPath, "db", "", utilities.T(utilities.KeyFlagDB))
	fs.BoolVar(&o.verbose, "verbose", false, utilities.T(utilities.KeyFlagVerbose))
}

// registerOutput 注册报告导出参数。
func (o *cliOptions) registerOutput(fs *flag.FlagSet) {
	fs.BoolVar(&o.jsonOut, "json", false, utilities.T(utilities.KeyFlagJSON))
	fs.StringVar(&o.out, "out", "", utilities.T(utilities.KeyFlagOut))
}

// logger 按 --verbose 创建输出器。
func (o *cliOptions) logger() *logger.Logger {
	return logger.New(o.verbose)
}

// newFlagSet 创建带本地化用法的子命令参数集。
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), utilities.T(utilities.KeyCLIUsage))
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags 统一处理 -h 与解析失败。
func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	return 0, true
}

// openStore 打开本地数据库，返回关闭函数。
func openStore(path string, log *logger.Logger) (func(), bool) {
	if _, err := database.InitDB(path); err != nil {
		log.LogKey(logger.CRITICAL, utilities.KeyDBFailed, err)
		return nil, false
	}
	return func() { _ = database.Close() }, true
}

// runScan 执行一次完整扫描：端口发现 → 指纹识别 → CVE 匹配 → Schema 枚举 → 报告。
func runScan(args []string, lang utilities.Language) int {
	fs := newFlagSet("scan")
	opts := &cliOptions{}
	var (
		scope       string
		sessionName string
		portsInput  string
		workers     int
		timeout     time.Duration
		sweep       bool
		insecure    bool
	)

	fs.StringVar(&scope, "scope", "", utilities.T(utilities.KeyFlagScope))
	fs.StringVar(&sessionName, "session", "", utilities.T(utilities.KeyFlagSession))
	fs.StringVar(&portsInput, "ports", "", utilities.T(utilities.KeyFlagPorts))
	fs.IntVar(&workers, "workers", engine.DefaultOptions().Workers, utilities.T(utilities.KeyFlagWorkers))
	fs.DurationVar(&timeout, "timeout", engine.DefaultOptions().Timeout, utilities.T(utilities.KeyFlagTimeout))
	fs.BoolVar(&sweep, "sweep", false, utilities.T(utilities.KeyFlagSweep))
	fs.BoolVar(&insecure, "insecure", false, utilities.T(utilities.KeyFlagInsecure))
	opts.registerStore(fs)
	opts.registerOutput(fs)

	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	log := opts.logger()
	if scope == "" {
		log.LogKey(logger.CRITICAL, utilities.KeyErrInvalidInput, "--scope")
		fs.Usage()
		return 2
	}
	if workers < 1 || workers > 4096 {
		log.LogKey(logger.CRITICAL, utilities.KeyErrInvalidInput, "--workers")
		return 2
	}
	if timeout <= 0 {
		log.LogKey(logger.CRITICAL, utilities.KeyErrInvalidInput, "--timeout")
		return 2
	}

	hosts, err := engine.ParseScope(scope, engine.DefaultOptions().MaxHosts)
	if err != nil {
		var tooLarge *engine.ScopeTooLargeError
		if errors.As(err, &tooLarge) {
			log.LogKey(logger.CRITICAL, utilities.KeyScopeTooLarge, tooLarge.Hosts, tooLarge.Limit)
		} else {
			log.LogKey(logger.CRITICAL, utilities.KeyScopeInvalid, scope, err)
		}
		return 2
	}

	ports := engine.DefaultPorts()
	if portsInput != "" {
		ports, err = engine.ParsePorts(portsInput)
		if err != nil {
			log.LogKey(logger.CRITICAL, utilities.KeyPortsInvalid, portsInput, err)
			return 2
		}
	}

	if sessionName == "" {
		sessionName = "scan-" + time.Now().Format("20060102-150405")
	}

	closeStore, ok := openStore(opts.dbPath, log)
	if !ok {
		return 1
	}
	defer closeStore()

	session, err := database.CreateSession(sessionName, scope, string(lang))
	switch {
	case err == nil:
		log.LogKey(logger.SUCCESS, utilities.KeySessionCreated, sessionName, scope)
	case errors.Is(err, database.ErrSessionExists):
		existing, loadErr := database.FindSessionByName(sessionName)
		if loadErr != nil {
			log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, loadErr)
			return 1
		}
		if restartErr := database.RestartSession(existing.ID); restartErr != nil {
			log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, restartErr)
			return 1
		}
		session = existing
		log.LogKey(logger.WARN, utilities.KeySessionExists, sessionName)
	default:
		log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanOpts := engine.DefaultOptions()
	scanOpts.Workers = workers
	scanOpts.Timeout = timeout
	scanOpts.Insecure = insecure
	scanOpts.Trace = func(protocol, target, action, detail string) {
		log.ProtocolCall(protocol, target, action, detail)
	}

	log.StepHeaderKey(utilities.KeyScanStart)
	log.LogKey(logger.INFO, utilities.KeyScanScope, scope)
	log.LogKey(logger.INFO, utilities.KeyScanHosts, len(hosts))
	log.LogKey(logger.INFO, utilities.KeyScanPorts, len(ports))

	started := time.Now()

	discoverer := engine.NewDiscoverer(scanOpts)
	discoverStart := time.Now()
	results := discoverer.Scan(ctx, hosts, ports)
	recordStep(session.ID, utilities.KeyStepScanPort, scope,
		fmt.Sprintf("%d hosts x %d ports", len(hosts), len(ports)),
		ctx.Err() == nil, time.Since(discoverStart), log)

	fingerprinter := engine.NewFingerprinter(scanOpts)
	dumper := engine.NewDumper(scanOpts)
	openPorts := 0

	for _, result := range results {
		address := net.JoinHostPort(result.Endpoint.Host, strconv.Itoa(result.Endpoint.Port))
		if !result.Open {
			log.LogKey(logger.DEBUG, utilities.KeyPortClosed, result.Endpoint.Host, result.Endpoint.Port)
			continue
		}

		openPorts++
		log.LogKey(logger.SUCCESS, utilities.KeyPortOpen,
			result.Endpoint.Host, result.Endpoint.Port, vendorLabel(result.Endpoint.Vendor))

		target, err := database.UpsertTarget(session.ID, model.TargetInput{
			Host:     result.Endpoint.Host,
			Port:     result.Endpoint.Port,
			Protocol: protocolForVendor(result.Endpoint.Vendor),
			Engine:   result.Endpoint.Vendor,
		})
		if err != nil {
			log.LogKey(logger.WARN, utilities.KeyErrOperation, err)
			continue
		}

		probeStart := time.Now()
		fp := fingerprinter.Probe(ctx, result.Endpoint)
		recordStep(session.ID, utilities.KeyStepService, address, fp.Product,
			fp.Vendor != "", time.Since(probeStart), log)

		if fp.Vendor == "" {
			log.LogKey(logger.DEBUG, utilities.KeyTargetClean,
				result.Endpoint.Host, result.Endpoint.Port, result.Endpoint.Protocol)
			continue
		}

		log.LogKey(logger.SUCCESS, utilities.KeyFingerprintFound, fp.Vendor, fp.Product)
		if fp.Version != "" {
			log.LogKey(logger.INFO, utilities.KeyFingerprintVersion, fp.Version)
		}
		if err := database.UpdateTarget(target.ID, fp.Vendor, fp.Version, protocolForVendor(fp.Vendor)); err != nil {
			log.LogKey(logger.WARN, utilities.KeyErrOperation, err)
		}

		vulnStart := time.Now()
		matched := recordCVEs(session.ID, target.ID, fp, log)
		recordStep(session.ID, utilities.KeyStepVulnCheck, address,
			fmt.Sprintf("%d known CVE(s) matched", matched),
			true, time.Since(vulnStart), log)

		if fp.AnonymousAccess {
			log.LogKey(logger.WARN, utilities.KeyAuthAnonymous)
			addFinding(session.ID, target.ID, model.VulnInput{
				Title:       utilities.T(utilities.KeyFindingAnonymousTitle),
				Severity:    model.SeverityMedium,
				Code:        model.FindingCodeAnonymous,
				Data:        encodeFindingData(model.FindingData{Vendor: fp.Vendor}),
				MitreTTP:    reporter.TTPExploitPublicFacing,
				Description: utilities.Tf(utilities.KeyFindingAnonymousDesc, fp.Vendor),
			}, log)
		}

		if sweep {
			dumpStart := time.Now()
			dump := dumper.Dump(ctx, fp, engine.DefaultDumpOptions())
			recordStep(session.ID, utilities.KeyStepDump, address, dump.Evidence,
				len(dump.Errors) == 0, time.Since(dumpStart), log)
			recordDump(session.ID, target.ID, fp, dump, log)
		}
	}

	elapsed := time.Since(started)
	status := model.StatusCompleted
	if ctx.Err() != nil {
		status = model.StatusAborted
		log.LogKey(logger.WARN, utilities.KeyScanAborted)
	}
	if err := database.FinishSession(session.ID, status); err != nil {
		log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, err)
		return 1
	}

	log.LogKey(logger.SUCCESS, utilities.KeyScanComplete, elapsed.Round(time.Millisecond))
	if openPorts == 0 {
		log.LogKey(logger.WARN, utilities.KeyScanNoOpenPorts)
	}

	loaded, err := database.OpenSession(session.ID)
	if err != nil {
		log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, err)
		return 1
	}
	if code, ok := emitReport(reporter.Build(loaded), sessionName, opts, log); !ok {
		return code
	}

	log.LogKey(logger.INFO, utilities.KeyScanSaved, sessionName)
	return 0
}

// runSessions 列出本地保存的会话。
func runSessions(args []string) int {
	fs := newFlagSet("sessions")
	opts := &cliOptions{}
	limit := 20

	fs.IntVar(&limit, "limit", 20, utilities.T(utilities.KeyFlagLimit))
	opts.registerStore(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	log := opts.logger()
	closeStore, ok := openStore(opts.dbPath, log)
	if !ok {
		return 1
	}
	defer closeStore()

	sessions, err := database.ListSessions(limit)
	if err != nil {
		log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, err)
		return 1
	}

	log.StepHeaderKey(utilities.KeySessionListHeader)
	if len(sessions) == 0 {
		log.LogKey(logger.INFO, utilities.KeySessionListEmpty)
		return 0
	}

	for _, session := range sessions {
		targets, findings, err := database.SessionStats(session.ID)
		if err != nil {
			log.LogKey(logger.WARN, utilities.KeyErrOperation, err)
			continue
		}
		log.LogKey(logger.INFO, utilities.KeySessionListRow,
			session.SessionName,
			localizedStatus(session.Status),
			session.TargetScope,
			targets,
			findings,
			session.StartedAt.Format("2006-01-02 15:04:05"),
		)
	}
	return 0
}

// runShow 载入历史会话并输出报告，不重新扫描。
func runShow(args []string) int {
	fs := newFlagSet("show")
	opts := &cliOptions{}
	var sessionName string

	fs.StringVar(&sessionName, "session", "", utilities.T(utilities.KeyFlagSession))
	opts.registerStore(fs)
	opts.registerOutput(fs)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	log := opts.logger()
	if sessionName == "" {
		log.LogKey(logger.CRITICAL, utilities.KeyCLISessionNeeded)
		fs.Usage()
		return 2
	}

	closeStore, ok := openStore(opts.dbPath, log)
	if !ok {
		return 1
	}
	defer closeStore()

	log.LogKey(logger.INFO, utilities.KeyDBReplaying)
	session, err := database.FindSessionByName(sessionName)
	if errors.Is(err, database.ErrSessionNotFound) {
		log.LogKey(logger.CRITICAL, utilities.KeySessionNotFound)
		return 1
	}
	if err != nil {
		log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, err)
		return 1
	}

	log.LogKey(logger.INFO, utilities.KeySessionOpened, session.SessionName, localizedStatus(session.Status))
	log.LogKey(logger.INFO, utilities.KeyStepReplayStart, len(session.Steps))

	if code, ok := emitReport(reporter.Build(session), sessionName, opts, log); !ok {
		return code
	}
	log.LogKey(logger.DEBUG, utilities.KeyStepReplayEnd)
	return 0
}

// recordCVEs 把匹配到的公告写入会话，标题与说明按当前语言取。
func recordCVEs(sessionID, targetID uint, fp model.Fingerprint, log *logger.Logger) int {
	matched := 0
	for _, advisory := range engine.MatchCVEs(fp.Vendor, fp.Version) {
		inserted := addFinding(sessionID, targetID, model.VulnInput{
			Title:       reporter.AdvisoryTitle(advisory),
			Severity:    advisory.Severity,
			CVE:         advisory.ID,
			MitreTTP:    advisory.TTP,
			Fixed:       advisory.Fixed,
			Reference:   advisory.Reference,
			Description: reporter.AdvisoryDescription(advisory),
		}, log)
		if inserted {
			log.LogKey(logger.WARN, utilities.KeyCVEHit,
				advisory.ID, localizedSeverity(advisory.Severity), advisory.CVSS)
		}
		matched++
	}
	return matched
}

// recordDump 把 Schema 枚举与取样结果转换成漏洞记录。
func recordDump(sessionID, targetID uint, fp model.Fingerprint, dump model.DumpResult, log *logger.Logger) {
	log.LogKey(logger.INFO, utilities.KeyDumpCollections, len(dump.Collections))
	for _, collection := range dump.Collections {
		log.LogKey(logger.INFO, utilities.KeyDumpCollection,
			collection.Name, collection.Dimension, metricLabel(collection.Metric), collection.Points)
	}
	if dump.Samples > 0 {
		log.LogKey(logger.WARN, utilities.KeyDumpSamples, dump.Samples)
	}
	if dump.KnnHits > 0 {
		log.LogKey(logger.WARN, utilities.KeyDumpKnn)
	}
	for _, message := range dump.Errors {
		log.Log(logger.DEBUG, "%s", message)
	}

	if !dump.Anonymous || len(dump.Collections) == 0 {
		return
	}

	if dump.Samples == 0 {
		addFinding(sessionID, targetID, model.VulnInput{
			Title:       utilities.T(utilities.KeyFindingMetadataTitle),
			Severity:    model.SeverityMedium,
			Code:        model.FindingCodeMetadata,
			Data:        encodeFindingData(model.FindingData{Vendor: fp.Vendor, Collections: len(dump.Collections)}),
			MitreTTP:    reporter.TTPExploitPublicFacing,
			Description: utilities.Tf(utilities.KeyFindingMetadataDesc, len(dump.Collections), fp.Vendor),
		}, log)
		return
	}

	description := utilities.Tf(utilities.KeyFindingExfilDesc, dump.Samples, fp.Vendor)
	if dump.KnnHits > 0 {
		description += " " + utilities.Tf(utilities.KeyFindingKnnDesc, dump.KnnHits)
	}
	addFinding(sessionID, targetID, model.VulnInput{
		Title:    utilities.T(utilities.KeyFindingExfilTitle),
		Severity: model.SeverityHigh,
		Code:     model.FindingCodeExfiltration,
		Data: encodeFindingData(model.FindingData{
			Vendor:  fp.Vendor,
			Samples: dump.Samples,
			KnnHits: dump.KnnHits,
		}),
		MitreTTP:    reporter.TTPDataFromInfoRepo,
		Description: description,
	}, log)
}

// addFinding 写入一条漏洞发现并输出日志；同一目标上的重复发现会被跳过。
// 返回是否真正写入了新记录。
func addFinding(sessionID, targetID uint, input model.VulnInput, log *logger.Logger) bool {
	exists, err := database.HasFinding(targetID, input.CVE, input.Code, input.Title)
	if err != nil {
		log.LogKey(logger.WARN, utilities.KeyErrOperation, err)
		return false
	}
	if exists {
		return false
	}

	if _, err := database.AddVulnerability(sessionID, targetID, input); err != nil {
		log.LogKey(logger.WARN, utilities.KeyErrOperation, err)
		return false
	}
	log.LogKey(logger.WARN, utilities.KeyVulnFound, input.Title, localizedSeverity(input.Severity))
	return true
}

// encodeFindingData 把非 CVE 发现的参数序列化为 JSON 存入记录。
// 类型固定，编码不会失败；万一失败则返回空串，回放时退回已存文案。
func encodeFindingData(data model.FindingData) string {
	payload, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(payload)
}

// recordStep 追加一条步骤历史；落库失败不影响扫描本身。
func recordStep(sessionID uint, action, target, detail string, success bool, elapsed time.Duration, log *logger.Logger) {
	if _, err := database.RecordStep(sessionID, model.StepInput{
		Action:   action,
		Target:   target,
		Detail:   detail,
		Success:  success,
		Duration: elapsed,
	}); err != nil {
		log.LogKey(logger.WARN, utilities.KeyErrOperation, err)
	}
}

// emitReport 根据 --json 输出终端报告或写入 JSON 文件。
func emitReport(report reporter.Report, sessionName string, opts *cliOptions, log *logger.Logger) (int, bool) {
	if !opts.jsonOut {
		if err := reporter.Render(os.Stdout, report); err != nil {
			log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, err)
			return 1, false
		}
		return 0, true
	}

	path := opts.out
	if path == "" {
		path = defaultReportPath(sessionName)
	}
	if err := writeReport(path, report); err != nil {
		log.LogKey(logger.CRITICAL, utilities.KeyErrOperation, err)
		return 1, false
	}
	log.LogKey(logger.SUCCESS, utilities.KeyReportSaved, path)
	return 0, true
}

// writeReport 把报告写入指定文件。
func writeReport(path string, report reporter.Report) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return reporter.WriteJSON(file, report)
}

// defaultReportPath 生成不含路径分隔符的默认导出文件名。
func defaultReportPath(sessionName string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, sessionName)
	return "vecmap-" + safe + ".json"
}

// protocolForVendor 返回落库时使用的传输协议。
func protocolForVendor(vendor string) string {
	switch constant.Vendor(engine.NormalizeVendor(vendor)) {
	case constant.VendorWeaviate, constant.VendorQdrant, constant.VendorChroma:
		return string(constant.ProtocolHTTP)
	case constant.VendorMilvus:
		return string(constant.ProtocolGRPC)
	default:
		return string(constant.ProtocolTCP)
	}
}

// vendorLabel 在厂商未知时给出占位符。
func vendorLabel(vendor string) string {
	if vendor == "" {
		return "-"
	}
	return vendor
}

// metricLabel 在度量为空时给出占位符。
func metricLabel(metric string) string {
	if metric == "" {
		return "-"
	}
	return metric
}

// localizedStatus 返回会话状态的中文或英文名称。
func localizedStatus(status string) string {
	switch status {
	case model.StatusRunning:
		return utilities.T(utilities.KeyStatusRunning)
	case model.StatusCompleted:
		return utilities.T(utilities.KeyStatusCompleted)
	case model.StatusAborted:
		return utilities.T(utilities.KeyStatusAborted)
	default:
		return status
	}
}

// localizedSeverity 返回严重级别的本地化名称。
func localizedSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case model.SeverityCritical:
		return utilities.T(utilities.KeySeverityCritical)
	case model.SeverityHigh:
		return utilities.T(utilities.KeySeverityHigh)
	case model.SeverityMedium:
		return utilities.T(utilities.KeySeverityMedium)
	case model.SeverityLow:
		return utilities.T(utilities.KeySeverityLow)
	default:
		return utilities.T(utilities.KeySeverityInfo)
	}
}

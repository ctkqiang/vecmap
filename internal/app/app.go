package app

import (
	"context"
	"fmt"
	"time"

	"vecmap/internal/constant"
	"vecmap/internal/database"
	"vecmap/internal/engine"
	"vecmap/internal/engine/vendors"
	"vecmap/internal/logger"
	"vecmap/internal/model"
	"vecmap/internal/report"
	"vecmap/internal/utilities"
)

// Config 控制应用初始化行为。
type Config struct {
	DatabasePath   string
	AdvisoriesPath string
	Verbose        bool
	Language       string
}

// App 编排本地会话、扫描、发现、提取与报告生成。
type App struct {
	store    *database.Store
	catalog  *engine.AdvisoryCatalog
	log      *logger.Logger
	language string
	verbose  bool
}

// New 初始化应用。
//
// 参数 config 为数据库路径、公告文件与日志配置。
// 返回已打开本地存储并加载公告目录的应用实例。
// 不需要本地数据库的命令（version、help、advisories）应使用 NewLite，
// 避免在仓库目录意外创建数据库文件。
func New(config Config) (*App, error) {
	if config.DatabasePath == "" {
		config.DatabasePath = database.DefaultPath()
	}
	store, err := database.Open(config.DatabasePath)
	if err != nil {
		return nil, err
	}
	app, err := NewLite(config)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	app.store = store
	return app, nil
}

// NewLite 初始化不打开本地数据库的应用。
//
// 参数 config 为公告文件与日志配置；数据库路径被忽略。
// 返回仅提供公告目录、日志与帮助文本的应用实例；
// 任何需要持久化的命令在使用前必须先调用 New 或注入 Store。
func NewLite(config Config) (*App, error) {
	extra, err := engine.LoadAdvisoryFile(config.AdvisoriesPath)
	if err != nil {
		return nil, err
	}
	if config.Language != "zh" && config.Language != "en" {
		config.Language = DefaultLanguage()
	}
	return &App{
		catalog:  engine.NewAdvisoryCatalog(extra),
		log:      logger.New(config.Verbose),
		language: config.Language,
		verbose:  config.Verbose,
	}, nil
}

// Store 返回底层数据库。
//
// 返回存储实例，供命令行查询使用。
func (a *App) Store() *database.Store {
	return a.store
}

// Catalog 返回公告目录。
//
// 返回合并后的公告目录，供命令行列出公告。
func (a *App) Catalog() *engine.AdvisoryCatalog {
	return a.catalog
}

// Logger 返回应用日志器。
//
// 返回日志实例，供命令层输出状态。
func (a *App) Logger() *logger.Logger {
	return a.log
}

// Language 返回当前界面语言。
//
// 返回 en 或 zh。
func (a *App) Language() string {
	return a.language
}

// Close 关闭本地数据库。
//
// 返回关闭错误；Lite 模式实例未打开数据库，关闭为空操作。
func (a *App) Close() error {
	if a.store == nil {
		return nil
	}
	return a.store.Close()
}

// RunScan 执行一次完整扫描。
//
// 参数 request 为授权目标与扫描配置。
// 返回内存结果；所有证据已持久化到本地数据库。
func (a *App) RunScan(request model.ScanRequest) (*model.ScanResult, error) {
	if !request.Authorized {
		return nil, fmt.Errorf("%s", utilities.TIn(a.language, "err.authorization"))
	}
	options := request.Options.Normalize()
	result := &model.ScanResult{StartedAt: time.Now().UTC()}
	targets, credentials, err := engine.ResolveTargets(request.Targets, options.Ports, 4096)
	if err != nil {
		return nil, err
	}
	scoper, err := engine.NewScoper(request.Scope)
	if err != nil {
		return nil, err
	}
	session := &model.Session{
		ID:         utilities.NewID("ses"),
		Name:       utilities.FirstNonEmpty(request.Name, "scan"),
		Mode:       string(options.Mode),
		Language:   a.language,
		Status:     "running",
		Authorized: request.Authorized,
		StartedAt:  time.Now().UTC(),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	database.SetSessionScope(session, request.Scope)
	session.OptionsJSON = options.RedactedJSON()
	result.Session = session
	if !options.DryRun {
		if err := a.store.CreateSession(session); err != nil {
			return nil, err
		}
	}
	a.log.Infof("%s", utilities.TfIn(a.language, "msg.session.created", session.ID))
	runtime, err := engine.NewRuntime(options, a.log)
	if err != nil {
		return nil, err
	}
	defer runtime.Close()
	registry := engine.NewRegistry()
	if err := vendors.RegisterAll(registry, runtime); err != nil {
		return nil, err
	}
	dumper := engine.NewDumper(registry, runtime)
	analyzer := engine.NewAnalyzer(a.catalog)
	a.log.Infof("%s", utilities.TfIn(a.language, "msg.scan.start", len(targets)))
	for index, target := range targets {
		targetOptions := options
		targetOptions.Credentials = credentials[index]
		a.scanTarget(context.Background(), registry, runtime, dumper, analyzer, scoper, session, target, targetOptions, result)
	}
	if !options.DryRun {
		session, err = a.store.UpdateSessionCounts(session)
		if err != nil {
			return result, err
		}
	}
	now := time.Now().UTC()
	session.Status = "completed"
	session.EndedAt = &now
	if !options.DryRun {
		if err := a.store.UpdateSession(session); err != nil {
			return result, err
		}
	}
	result.Session = session
	result.Duration = time.Since(result.StartedAt)
	a.log.Successf("%s", utilities.TfIn(a.language, "msg.scan.done", utilities.FormatDuration(result.Duration), len(result.Findings)))
	return result, nil
}

func (a *App) scanTarget(ctx context.Context, registry *engine.Registry, runtime *engine.Runtime, dumper *engine.Dumper, analyzer *engine.Analyzer, scoper *engine.Scoper, session *model.Session, target model.Target, options model.ScanOptions, result *model.ScanResult) {
	target.ID = utilities.NewID("tgt")
	target.SessionID = session.ID
	target.Reachable = false
	if err := scoper.Check(ctx, target.Host, target.Port); err != nil {
		message := utilities.TfIn(a.language, "msg.scope.denied", target.Input)
		result.Errors = append(result.Errors, message)
		a.log.Warnf("%s", message)
		if !options.DryRun {
			_ = a.store.SaveTargets([]*model.Target{&target})
		}
		return
	}
	runtime.HTTP.ResetExchanges()
	result.Targets = append(result.Targets, &target)
	started := time.Now()
	identification, identifyErr := engine.Identify(ctx, registry, runtime, &target, options)
	identifyStep := &model.Step{
		ID:         utilities.NewID("stp"),
		SessionID:  session.ID,
		TargetID:   target.ID,
		Phase:      "fingerprint",
		Action:     "identify product",
		Protocol:   target.Transport,
		DurationMS: time.Since(started).Milliseconds(),
		CreatedAt:  time.Now().UTC(),
	}
	if identifyErr != nil {
		identifyStep.Status = "failed"
		identifyStep.Error = utilities.Truncate(identifyErr.Error(), 400)
		result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", target.Input, identifyErr))
		a.log.Warnf("%s: %s", target.Input, identifyErr)
		result.Steps = append(result.Steps, identifyStep)
		if !options.DryRun {
			_ = a.store.SaveTargets([]*model.Target{&target})
			_ = a.store.SaveSteps([]*model.Step{identifyStep})
		}
		return
	}
	identifyStep.Status = "ok"
	identifyStep.Detail = fmt.Sprintf("%s %s %s", target.Vendor, target.Product, target.Version)
	identifyStep.DurationMS = time.Since(started).Milliseconds()
	result.Steps = append(result.Steps, identifyStep)
	target.Reachable = true

	probeStarted := time.Now()
	var probes []*model.ProbeResult
	var probeErr error
	if identification.Adapter != nil {
		probes, probeErr = identification.Adapter.Probe(ctx, &target, options)
	} else {
		fuzzer := engine.NewFuzzer(runtime)
		probes, probeErr = fuzzer.Run(ctx, &target, target.Vendor, options, engine.ProbeCatalog(target.Vendor))
	}
	probeStep := &model.Step{
		ID:         utilities.NewID("stp"),
		SessionID:  session.ID,
		TargetID:   target.ID,
		Phase:      "probe",
		Action:     "read-only surface probes",
		Protocol:   "http",
		DurationMS: time.Since(probeStarted).Milliseconds(),
		CreatedAt:  time.Now().UTC(),
	}
	if probeErr != nil {
		probeStep.Status = "failed"
		probeStep.Error = utilities.Truncate(probeErr.Error(), 400)
	} else {
		probeStep.Status = "ok"
		probeStep.Detail = fmt.Sprintf("%d probes", len(probes))
	}
	result.Steps = append(result.Steps, probeStep)
	for _, probe := range probes {
		probe.SessionID = session.ID
	}
	result.Probes = append(result.Probes, probes...)

	var extraction *model.Extraction
	if options.Mode == model.ModeDeep {
		dumpStarted := time.Now()
		extraction, dumpErr := dumper.Dump(ctx, &target, options, options.DumpOptions())
		dumpStep := &model.Step{
			ID:         utilities.NewID("stp"),
			SessionID:  session.ID,
			TargetID:   target.ID,
			Phase:      "extract",
			Action:     "enumerate collections and records",
			Protocol:   target.Transport,
			DurationMS: time.Since(dumpStarted).Milliseconds(),
			CreatedAt:  time.Now().UTC(),
		}
		if dumpErr != nil {
			dumpStep.Status = "failed"
			dumpStep.Error = utilities.Truncate(dumpErr.Error(), 400)
			result.Errors = append(result.Errors, fmt.Sprintf("%s extract: %s", target.Input, dumpErr))
		} else if extraction != nil {
			dumpStep.Status = "ok"
			dumpStep.Detail = utilities.TfIn(a.language, "msg.records.extracted", len(extraction.Records), len(extraction.Collections))
			for _, collection := range extraction.Collections {
				collection.SessionID = session.ID
			}
			for _, record := range extraction.Records {
				record.SessionID = session.ID
			}
			result.Collections = append(result.Collections, extraction.Collections...)
			result.Records = append(result.Records, extraction.Records...)
			for _, message := range extraction.Errors {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", target.Input, message))
			}
		}
		result.Steps = append(result.Steps, dumpStep)
	}

	exchanges := runtime.HTTP.Exchanges()
	for _, exchange := range exchanges {
		exchange.SessionID = session.ID
		exchange.TargetID = target.ID
	}
	result.Exchanges = append(result.Exchanges, exchanges...)

	var fingerprint *model.Fingerprint
	if identification != nil {
		fingerprint = identification.Fingerprint
	}
	findings := analyzer.Analyze(engine.AnalysisInput{
		SessionID:     session.ID,
		Target:        &target,
		Fingerprint:   fingerprint,
		Probes:        probes,
		Extraction:    extraction,
		Authenticated: engine.HasAuth(options.Credentials),
	})
	result.Findings = append(result.Findings, findings...)
	a.log.Infof("%s -> %s %s: %d finding(s)", target.Input, target.Vendor, target.Product, len(findings))

	if options.DryRun {
		return
	}
	_ = a.store.SaveTargets([]*model.Target{&target})
	_ = a.store.SaveSteps(result.Steps)
	_ = a.store.SaveProbes(probes)
	_ = a.store.SaveExchanges(exchanges)
	if extraction != nil {
		_ = a.store.SaveCollections(extraction.Collections)
		_ = a.store.SaveRecords(extraction.Records)
	}
	_ = a.store.SaveFindings(findings)
}

// RunDiscover 执行端口发现并持久化结果。
//
// 参数 request 为授权目标与发现配置。
// 返回发现结果；开放端口会作为目标与会话一并入库。
func (a *App) RunDiscover(request model.ScanRequest) (*model.DiscoveryResult, error) {
	if !request.Authorized {
		return nil, fmt.Errorf("%s", utilities.TIn(a.language, "err.authorization"))
	}
	targets, _, err := engine.ResolveTargets(request.Targets, nil, 4096)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(targets))
	seen := map[string]struct{}{}
	for _, target := range targets {
		if _, exists := seen[target.Host]; exists {
			continue
		}
		seen[target.Host] = struct{}{}
		hosts = append(hosts, target.Host)
	}
	scoper, err := engine.NewScoper(request.Scope)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if err := scoper.Check(context.Background(), host, 0); err != nil {
			a.log.Warnf("%s", utilities.TfIn(a.language, "msg.scope.denied", host))
			continue
		}
		allowed = append(allowed, host)
	}
	options := model.DiscoveryOptions{
		Ports:       request.Options.Ports,
		Timeout:     request.Options.Timeout,
		Concurrency: request.Options.Concurrency,
	}
	a.log.Infof("%s", utilities.TfIn(a.language, "msg.discovery.start", len(allowed), len(options.Normalize().Ports)))
	discovered, err := engine.Discover(context.Background(), allowed, options)
	if err != nil {
		return nil, err
	}
	session := &model.Session{
		ID:         utilities.NewID("ses"),
		Name:       utilities.FirstNonEmpty(request.Name, "discover"),
		Mode:       "discover",
		Language:   a.language,
		Status:     "completed",
		Authorized: request.Authorized,
		StartedAt:  time.Now().UTC(),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	now := time.Now().UTC()
	session.EndedAt = &now
	database.SetSessionScope(session, request.Scope)
	if !request.Options.DryRun {
		if err := a.store.CreateSession(session); err != nil {
			return nil, err
		}
	}
	persisted := make([]*model.Target, 0, len(discovered.Targets))
	for _, target := range discovered.Targets {
		target.ID = utilities.NewID("tgt")
		target.SessionID = session.ID
		persisted = append(persisted, &target)
	}
	if !request.Options.DryRun {
		_ = a.store.SaveTargets(persisted)
		_, _ = a.store.UpdateSessionCounts(session)
	}
	a.log.Successf("%s", utilities.TfIn(a.language, "msg.discovery.done", utilities.FormatDuration(discovered.Duration), len(discovered.OpenPorts)))
	return discovered, nil
}

// Report 为会话生成报告。
//
// 参数 sessionID 为会话主键，options 为格式与路径。
// 返回渲染文本；指定 Path 时写入文件并返回空文本。
func (a *App) Report(sessionID string, options model.ReportOptions) (string, error) {
	bundle, err := a.store.SessionBundle(sessionID)
	if err != nil {
		return "", err
	}
	if options.Language == "" {
		options.Language = a.language
	}
	builder := report.New(options.Language)
	built := builder.Build(bundle, a.catalog.All())
	if options.Path != "" {
		if err := builder.Write(built, options); err != nil {
			return "", err
		}
		a.log.Successf("%s", utilities.TfIn(a.language, "msg.report.written", options.Path))
		return "", nil
	}
	return builder.Render(built, options.Format)
}

// ListSessions 分页列出会话。
//
// 参数 limit 与 offset 控制分页。
// 返回会话切片与总数。
func (a *App) ListSessions(limit, offset int) ([]*model.Session, int64, error) {
	return a.store.ListSessions(limit, offset)
}

// DeleteSession 删除会话及其关联证据。
//
// 参数 sessionID 为会话主键；返回删除错误。
func (a *App) DeleteSession(sessionID string) error {
	return a.store.DeleteSession(sessionID)
}

// SessionBundle 返回会话聚合数据。
//
// 参数 sessionID 为会话主键；返回聚合结果。
func (a *App) SessionBundle(sessionID string) (*model.SessionBundle, error) {
	return a.store.SessionBundle(sessionID)
}

// Advisories 返回公告目录副本。
//
// 返回按风险等级排序的公告切片。
func (a *App) Advisories() []model.Advisory {
	return a.catalog.All()
}

// Version 返回版本信息文本。
//
// 返回工具名、版本与定位说明。
func (a *App) Version() string {
	return fmt.Sprintf("%s %s — %s", constant.Name, constant.Version, constant.Tagline)
}

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ctkqiang/vecmap/internal/model"
	"github.com/ctkqiang/vecmap/internal/utilities"
)

// ProbeSpec 描述一条只读探测请求。
//
// Sensitive 表示成功响应可能包含集合、文档或运行元数据；
// Core 表示即使未启用路径模糊测试也应执行的基线探测。
type ProbeSpec struct {
	Method    string
	Path      string
	Category  string
	Body      any
	Core      bool
	Sensitive bool
	Headers   map[string]string
}

// destructivePathTokens 是硬性拒绝列表，用于防止任何破坏性请求被探测目录带入。
var destructivePathTokens = []string{
	"/management/stop",
	"/delete",
	"/drop",
	"/truncate",
	"/recover",
	"/restore",
	"/snapshots/create",
	"/snapshot/create",
	"/snapshot/upload",
	"/compact",
	"/flush",
	"/optimize",
	"/shutdown",
	"/reset",
	"/upsert",
	"/insert",
	"/update",
	"/write",
	"_delete_by_query",
}

// IsDestructivePath 判断路径是否命中破坏性拒绝列表。
//
// 参数 path 为待检查路径；返回 true 表示该路径禁止被探测执行。
func IsDestructivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, token := range destructivePathTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

// Fuzzer 执行受控的只读端点探测。
type Fuzzer struct {
	runtime *Runtime
}

// NewFuzzer 创建探测执行器。
//
// 参数 runtime 提供共享 HTTP 客户端；返回可复用的执行器。
func NewFuzzer(runtime *Runtime) *Fuzzer {
	return &Fuzzer{runtime: runtime}
}

// Run 执行探测目录中的请求。
//
// 参数 ctx 控制整体生命周期，target 为目标，vendor 为厂商标识，
// options 控制认证与模糊测试开关，specs 为候选探测。
// 返回探测结果；单个请求失败会记录为带错误摘要的结果而不是中断整体。
func (f *Fuzzer) Run(ctx context.Context, target *model.Target, vendor model.Vendor, options model.ScanOptions, specs []ProbeSpec) ([]*model.ProbeResult, error) {
	if f == nil || f.runtime == nil || f.runtime.HTTP == nil || target == nil {
		return nil, fmt.Errorf("fuzzer runtime is not initialized")
	}
	deep := options.Fuzz || options.Mode == model.ModeDeep
	results := make([]*model.ProbeResult, 0, len(specs))
	seen := map[string]struct{}{}
	headers := AuthHeaders(vendor, options.Credentials)
	limit := 0
	for _, spec := range specs {
		if !spec.Core && !deep {
			continue
		}
		if IsDestructivePath(spec.Path) {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(spec.Method))
		if method == "" {
			method = http.MethodGet
		}
		if !allowedProbeMethod(method) {
			continue
		}
		key := method + " " + spec.Path
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if limit >= 256 {
			break
		}
		limit++
		merged := MergeHeaders(headers, spec.Headers)
		probeCtx, cancel := context.WithTimeout(ctx, options.Timeout)
		exchange, err := f.execute(probeCtx, method, target, spec, merged)
		cancel()
		result := &model.ProbeResult{
			ID:        utilities.NewID("prb"),
			TargetID:  target.ID,
			Vendor:    vendor,
			Protocol:  "http",
			Method:    method,
			Path:      spec.Path,
			Category:  spec.Category,
			CreatedAt: time.Now().UTC(),
		}
		if exchange != nil {
			result.StatusCode = exchange.StatusCode
			result.ExchangeID = exchange.ID
			result.AuthRequired = IsAuthRequired(exchange.StatusCode)
			result.Sensitive = spec.Sensitive && IsSuccess(exchange.StatusCode) && strings.TrimSpace(exchange.ResponseBody) != ""
		}
		if err != nil {
			result.Summary = fmt.Sprintf("%s %s -> network error", method, spec.Path)
			result.SummaryZH = fmt.Sprintf("%s %s -> 网络错误", method, spec.Path)
			results = append(results, result)
			continue
		}
		result.Summary = probeSummary(method, spec.Path, exchange, "en")
		result.SummaryZH = probeSummary(method, spec.Path, exchange, "zh")
		results = append(results, result)
	}
	if deep {
		if cors := f.checkCORS(ctx, target, vendor, options); cors != nil {
			results = append(results, cors)
		}
	}
	return results, nil
}

func (f *Fuzzer) execute(ctx context.Context, method string, target *model.Target, spec ProbeSpec, headers map[string]string) (*model.HTTPExchange, error) {
	rawURL := TargetURL(*target, spec.Path)
	if method == http.MethodPost && spec.Body != nil {
		return f.runtime.HTTP.PostJSON(ctx, rawURL, spec.Body, headers)
	}
	return f.runtime.HTTP.Do(ctx, method, rawURL, nil, headers)
}

func (f *Fuzzer) checkCORS(ctx context.Context, target *model.Target, vendor model.Vendor, options model.ScanOptions) *model.ProbeResult {
	origin := "https://vecmap.invalid"
	headers := MergeHeaders(AuthHeaders(vendor, options.Credentials), map[string]string{
		"Origin":                        origin,
		"Access-Control-Request-Method": "GET",
	})
	probeCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	exchange, err := f.runtime.HTTP.Do(probeCtx, http.MethodOptions, strings.TrimRight(target.BaseURL(), "/")+"/", nil, headers)
	result := &model.ProbeResult{
		ID:        utilities.NewID("prb"),
		TargetID:  target.ID,
		Vendor:    vendor,
		Protocol:  "http",
		Method:    http.MethodOptions,
		Path:      "/",
		Category:  "cors",
		CreatedAt: time.Now().UTC(),
	}
	if exchange != nil {
		result.StatusCode = exchange.StatusCode
		result.ExchangeID = exchange.ID
	}
	if err != nil {
		return nil
	}
	responseHeaders := map[string]string{}
	_ = json.Unmarshal([]byte(exchange.ResponseHeaders), &responseHeaders)
	allowOrigin := headerValue(responseHeaders, "Access-Control-Allow-Origin")
	allowCredentials := strings.EqualFold(headerValue(responseHeaders, "Access-Control-Allow-Credentials"), "true")
	if allowOrigin == "" || !allowCredentials {
		return nil
	}
	if allowOrigin != "*" && allowOrigin != origin {
		return nil
	}
	result.Sensitive = true
	result.Summary = fmt.Sprintf("permissive CORS: origin=%s credentials=true", allowOrigin)
	result.SummaryZH = fmt.Sprintf("宽松 CORS：origin=%s credentials=true", allowOrigin)
	return result
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func probeSummary(method, path string, exchange *model.HTTPExchange, language string) string {
	status := "no response"
	contentType := ""
	if exchange != nil {
		status = fmt.Sprintf("%d", exchange.StatusCode)
		contentType = exchange.ContentType
	}
	if language == "zh" {
		if IsAuthRequired(statusCode(exchange)) {
			return fmt.Sprintf("%s %s -> %s（需要认证）", method, path, status)
		}
		if contentType != "" {
			return fmt.Sprintf("%s %s -> %s %s", method, path, status, contentType)
		}
		return fmt.Sprintf("%s %s -> %s", method, path, status)
	}
	if IsAuthRequired(statusCode(exchange)) {
		return fmt.Sprintf("%s %s -> %s (authentication required)", method, path, status)
	}
	if contentType != "" {
		return fmt.Sprintf("%s %s -> %s %s", method, path, status, contentType)
	}
	return fmt.Sprintf("%s %s -> %s", method, path, status)
}

func statusCode(exchange *model.HTTPExchange) int {
	if exchange == nil {
		return 0
	}
	return exchange.StatusCode
}

func allowedProbeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost:
		return true
	default:
		return false
	}
}

// ProbeCatalog 返回厂商对应的只读探测目录。
//
// 参数 vendor 为厂商标识；返回按基线优先排列的探测列表，
// 所有条目均为只读操作，破坏性路径会在执行前被再次拒绝。
func ProbeCatalog(vendor model.Vendor) []ProbeSpec {
	switch vendor {
	case model.VendorQdrant:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/", Category: "root", Core: true},
			{Method: http.MethodGet, Path: "/healthz", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/collections", Category: "collections", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/metrics", Category: "metrics", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/telemetry", Category: "telemetry", Sensitive: true},
			{Method: http.MethodGet, Path: "/cluster", Category: "cluster", Sensitive: true},
			{Method: http.MethodGet, Path: "/snapshots", Category: "snapshot", Sensitive: true},
			{Method: http.MethodGet, Path: "/openapi.json", Category: "docs"},
			{Method: http.MethodGet, Path: "/docs", Category: "docs"},
		}
	case model.VendorMilvus:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/healthz", Category: "health", Core: true},
			{Method: http.MethodPost, Path: "/v2/vectordb/collections/list", Category: "collections", Core: true, Sensitive: true, Body: map[string]any{"dbName": "default"}},
			{Method: http.MethodGet, Path: "/api/v1/health", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/metrics", Category: "metrics", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/openapi.json", Category: "docs"},
			{Method: http.MethodGet, Path: "/docs", Category: "docs"},
		}
	case model.VendorWeaviate:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/v1/meta", Category: "meta", Core: true},
			{Method: http.MethodGet, Path: "/v1/.well-known/ready", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/v1/schema", Category: "schema", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/metrics", Category: "metrics", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/v1/nodes", Category: "nodes", Sensitive: true},
			{Method: http.MethodGet, Path: "/v1/objects?limit=1", Category: "objects", Sensitive: true},
			{Method: http.MethodGet, Path: "/v1/backups", Category: "snapshot", Sensitive: true},
			{Method: http.MethodGet, Path: "/v1/.well-known/openid-configuration", Category: "auth"},
		}
	case model.VendorChroma:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/api/v1/heartbeat", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/api/v2/heartbeat", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/api/v1/version", Category: "version", Core: true},
			{Method: http.MethodGet, Path: "/api/v1/collections", Category: "collections", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/api/v2/tenants/default_tenant/databases/default_database/collections", Category: "collections", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/openapi.json", Category: "docs"},
			{Method: http.MethodGet, Path: "/docs", Category: "docs"},
		}
	case model.VendorElasticsearch, model.VendorOpenSearch:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/", Category: "root", Core: true},
			{Method: http.MethodGet, Path: "/_cluster/health", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/_cat/indices?format=json", Category: "indices", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/_nodes", Category: "nodes", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/_security/_authenticate", Category: "auth"},
			{Method: http.MethodGet, Path: "/_plugins/_security/authinfo", Category: "auth"},
			{Method: http.MethodGet, Path: "/_cat/aliases?format=json", Category: "aliases", Sensitive: true},
		}
	case model.VendorTypesense:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/health", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/debug", Category: "version", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/collections", Category: "collections", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/metrics.json", Category: "metrics", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/stats.json", Category: "stats", Sensitive: true},
		}
	case model.VendorPinecone:
		return []ProbeSpec{
			{Method: http.MethodPost, Path: "/describe_index_stats", Category: "stats", Core: true, Sensitive: true, Body: map[string]any{}},
			{Method: http.MethodGet, Path: "/vectors/list?limit=1", Category: "objects", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/", Category: "root", Core: true},
		}
	case model.VendorVespa:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/state/v1/health", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/state/v1/version", Category: "version", Core: true},
			{Method: http.MethodGet, Path: "/state/v1/metrics", Category: "metrics", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/metrics/v2/values", Category: "metrics", Sensitive: true},
			{Method: http.MethodGet, Path: "/ApplicationStatus", Category: "status", Sensitive: true},
			{Method: http.MethodGet, Path: "/search/?yql=select%20*%20from%20sources%20*%20where%20true%3B&hits=1", Category: "objects", Sensitive: true},
		}
	default:
		return []ProbeSpec{
			{Method: http.MethodGet, Path: "/", Category: "root", Core: true},
			{Method: http.MethodGet, Path: "/health", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/healthz", Category: "health", Core: true},
			{Method: http.MethodGet, Path: "/metrics", Category: "metrics", Core: true, Sensitive: true},
			{Method: http.MethodGet, Path: "/openapi.json", Category: "docs"},
			{Method: http.MethodGet, Path: "/docs", Category: "docs"},
			{Method: http.MethodGet, Path: "/version", Category: "version"},
		}
	}
}

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// FingerprintResult 表示指纹识别结果及其命中的适配器。
type FingerprintResult struct {
	Fingerprint *model.Fingerprint
	Adapter     Adapter
}

// Identify 依次调用候选适配器识别目标产品。
//
// 参数 ctx 控制识别生命周期，registry 为厂商注册表，runtime 为共享客户端，
// target 为待识别目标，options 为扫描配置。
// 返回最佳指纹与适配器；所有候选均未识别时回退到通用 HTTP/gRPC 指纹。
func Identify(ctx context.Context, registry *Registry, runtime *Runtime, target *model.Target, options model.ScanOptions) (*FingerprintResult, error) {
	if target == nil {
		return nil, fmt.Errorf("target is nil")
	}
	candidates := registry.Candidates(target)
	var failures []string
	for _, adapter := range candidates {
		fingerprint, err := adapter.Fingerprint(ctx, target, options)
		if err != nil {
			if !errors.Is(err, ErrNotMatched) && !errors.Is(err, ErrUnauthorized) {
				failures = append(failures, fmt.Sprintf("%s: %s", adapter.Vendor(), err))
			}
			continue
		}
		if fingerprint == nil {
			continue
		}
		ApplyFingerprint(target, fingerprint)
		return &FingerprintResult{Fingerprint: fingerprint, Adapter: adapter}, nil
	}
	fingerprint, err := genericFingerprint(ctx, runtime, target, options)
	if err != nil {
		if len(failures) > 0 {
			return nil, fmt.Errorf("%w (%s)", err, strings.Join(failures, "; "))
		}
		return nil, err
	}
	ApplyFingerprint(target, fingerprint)
	return &FingerprintResult{Fingerprint: fingerprint}, nil
}

// ApplyFingerprint 将指纹字段写回目标实体。
//
// 参数 target 为目标，fingerprint 为识别结果；返回值为空。
func ApplyFingerprint(target *model.Target, fingerprint *model.Fingerprint) {
	if target == nil || fingerprint == nil {
		return
	}
	if fingerprint.Vendor != "" {
		target.Vendor = fingerprint.Vendor
	}
	target.Product = fingerprint.Product
	target.Version = fingerprint.Version
	target.AuthRequired = fingerprint.AuthRequired
	target.Server = fingerprint.Server
	target.Banner = fingerprint.Banner
	target.TLS = fingerprint.TLS
	if target.Transport == "" {
		if fingerprint.GRPC != nil {
			target.Transport = string(model.ProtocolGRPC)
		} else {
			target.Transport = strings.TrimPrefix(target.Scheme, "s")
		}
	}
	payload, err := json.Marshal(fingerprint)
	if err == nil {
		target.FingerprintJSON = string(payload)
	}
}

func genericFingerprint(ctx context.Context, runtime *Runtime, target *model.Target, options model.ScanOptions) (*model.Fingerprint, error) {
	if target.Scheme == "grpc" {
		return genericGRPCFingerprint(ctx, runtime, target)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("no adapter matched target %s", TargetKey(*target))
	}
	if runtime == nil || runtime.HTTP == nil {
		return nil, fmt.Errorf("http runtime is not initialized")
	}
	probeCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	exchange, err := runtime.HTTP.Get(probeCtx, TargetURL(*target, "/"), AuthHeaders(model.VendorUnknown, options.Credentials))
	if err != nil {
		return nil, fmt.Errorf("generic HTTP fingerprint: %w", err)
	}
	fingerprint := &model.Fingerprint{
		Vendor:       model.VendorUnknown,
		Confidence:   model.ConfidenceLow,
		AuthRequired: IsAuthRequired(exchange.StatusCode),
		TLS:          exchange.TLS,
		HTTP: &model.HTTPInfo{
			StatusCode:  exchange.StatusCode,
			Title:       htmlTitle(exchange.ResponseBody),
			ContentType: exchange.ContentType,
			BodyPreview: utilities.Truncate(exchange.ResponseBody, 600),
		},
		Evidence: []string{fmt.Sprintf("GET / -> %d", exchange.StatusCode)},
	}
	headers := map[string]string{}
	_ = json.Unmarshal([]byte(exchange.ResponseHeaders), &headers)
	for key, value := range headers {
		if strings.EqualFold(key, "Server") {
			fingerprint.Server = value
		}
	}
	if fingerprint.Server != "" {
		fingerprint.Evidence = append(fingerprint.Evidence, "Server: "+fingerprint.Server)
	}
	switch {
	case strings.Contains(strings.ToLower(exchange.ResponseBody), "qdrant"):
		fingerprint.Vendor = model.VendorQdrant
	case strings.Contains(strings.ToLower(exchange.ResponseBody), "weaviate"):
		fingerprint.Vendor = model.VendorWeaviate
	case strings.Contains(strings.ToLower(exchange.ResponseBody), "milvus"):
		fingerprint.Vendor = model.VendorMilvus
	case strings.Contains(strings.ToLower(exchange.ResponseBody), "chroma"):
		fingerprint.Vendor = model.VendorChroma
	case strings.Contains(strings.ToLower(exchange.ResponseBody), "typesense"):
		fingerprint.Vendor = model.VendorTypesense
	case strings.Contains(strings.ToLower(exchange.ResponseBody), "you know, for search"):
		fingerprint.Vendor = model.VendorElasticsearch
	}
	if fingerprint.Vendor != model.VendorUnknown {
		fingerprint.Product = string(fingerprint.Vendor)
		fingerprint.Confidence = model.ConfidenceMedium
	}
	return fingerprint, nil
}

func genericGRPCFingerprint(ctx context.Context, runtime *Runtime, target *model.Target) (*model.Fingerprint, error) {
	if runtime == nil || runtime.GRPC == nil {
		return nil, fmt.Errorf("gRPC runtime is not initialized")
	}
	info, err := runtime.GRPC.Probe(ctx, TargetAddress(*target), target.TLS)
	if err != nil && info == nil {
		return nil, fmt.Errorf("gRPC fingerprint: %w", err)
	}
	fingerprint := &model.Fingerprint{
		Vendor:     model.VendorUnknown,
		Confidence: model.ConfidenceLow,
		TLS:        info.TLS,
		GRPC:       info,
	}
	if info.Reachable {
		fingerprint.Evidence = append(fingerprint.Evidence, "gRPC endpoint reachable")
	}
	for _, service := range info.Services {
		name := strings.ToLower(service.Name)
		switch {
		case strings.Contains(name, "milvus"):
			fingerprint.Vendor = model.VendorMilvus
			fingerprint.Product = "milvus"
			fingerprint.Confidence = model.ConfidenceHigh
		case strings.Contains(name, "qdrant"):
			fingerprint.Vendor = model.VendorQdrant
			fingerprint.Product = "qdrant"
			fingerprint.Confidence = model.ConfidenceHigh
		case strings.Contains(name, "weaviate"):
			fingerprint.Vendor = model.VendorWeaviate
			fingerprint.Product = "weaviate"
			fingerprint.Confidence = model.ConfidenceHigh
		}
		if fingerprint.Vendor != model.VendorUnknown {
			fingerprint.Evidence = append(fingerprint.Evidence, "service: "+service.Name)
			break
		}
	}
	return fingerprint, nil
}

func htmlTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start < 0 {
		return ""
	}
	end := strings.Index(lower[start+7:], "</title>")
	if end < 0 {
		return ""
	}
	title := body[start+7 : start+7+end]
	return strings.TrimSpace(strings.Join(strings.Fields(title), " "))
}

// StatusError 将状态码信息附加到错误。
//
// 参数 action 为动作描述，status 为 HTTP 状态码，body 为响应摘要。
// 返回包含状态与摘要的错误，用于适配器失败路径。
func StatusError(action string, status int, body string) error {
	return fmt.Errorf("%s: status %d: %s", action, status, utilities.Truncate(strings.TrimSpace(body), 200))
}

// AuthHeadersFor 返回厂商与凭据对应的认证头。
//
// 参数 vendor 为厂商标识，credentials 为凭据；返回可合并到请求的头映射。
func AuthHeadersFor(vendor model.Vendor, credentials model.Credentials) map[string]string {
	return AuthHeaders(vendor, credentials)
}

// EnsureJSON 判断响应是否成功且包含 JSON 内容。
//
// 参数 exchange 为 HTTP 证据；返回状态码是否成功。
func EnsureJSON(exchange *model.HTTPExchange) error {
	if exchange == nil {
		return fmt.Errorf("empty HTTP response")
	}
	if IsAuthRequired(exchange.StatusCode) {
		return ErrUnauthorized
	}
	if !IsSuccess(exchange.StatusCode) {
		return StatusError("unexpected status", exchange.StatusCode, exchange.ResponseBody)
	}
	return nil
}

// RequireMethod 判断探测方法是否为允许的只读方法。
//
// 参数 method 为 HTTP 方法；返回是否属于 GET、HEAD、OPTIONS 或 POST。
func RequireMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost:
		return true
	default:
		return false
	}
}

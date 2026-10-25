package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/ctkqiang/vecmap/internal/constant"
	"github.com/ctkqiang/vecmap/internal/model"
	"github.com/ctkqiang/vecmap/internal/utilities"
)

// HTTPClient 是带证据记录、限速与脱敏能力的共享 HTTP 客户端。
type HTTPClient struct {
	client   *http.Client
	options  model.HTTPOptions
	limiter  *rate.Limiter
	mu       sync.RWMutex
	records  []*model.HTTPExchange
	recorder func(*model.HTTPExchange)
}

// NewHTTPClient 创建共享 HTTP 客户端。
//
// 参数 options 为超时、代理、TLS 与限速配置。
// 返回可直接复用的客户端；空闲连接由 Close 释放。
func NewHTTPClient(options model.HTTPOptions) *HTTPClient {
	if options.Timeout <= 0 {
		options.Timeout = constant.DefaultTimeout
	}
	if options.MaxBody <= 0 {
		options.MaxBody = constant.DefaultMaxBody
	}
	if options.UserAgent == "" {
		options.UserAgent = constant.DefaultUserAgent
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 64
	transport.MaxIdleConnsPerHost = 8
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = options.Timeout
	transport.ResponseHeaderTimeout = options.Timeout
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: options.Insecure} //nolint:gosec
	if options.Proxy != "" {
		if parsed, err := url.Parse(options.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			if len(via) > 0 && !strings.EqualFold(request.URL.Host, via[0].URL.Host) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	limiter := rate.NewLimiter(rate.Inf, 1)
	if options.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(options.RateLimit), 1)
	}
	return &HTTPClient{client: client, options: options, limiter: limiter}
}

// SetRecorder 设置 HTTP 证据记录回调。
//
// 参数 recorder 接收每条脱敏证据；传 nil 可关闭记录。
func (c *HTTPClient) SetRecorder(recorder func(*model.HTTPExchange)) {
	c.mu.Lock()
	c.recorder = recorder
	c.mu.Unlock()
}

// Close 关闭空闲连接。
//
// 返回值为空，仅用于满足资源清理接口。
func (c *HTTPClient) Close() {
	c.client.CloseIdleConnections()
}

// Do 执行一次 HTTP 请求并返回脱敏证据。
//
// 参数 method 为请求方法，rawURL 为完整 URL，body 为请求体，headers 为附加头。
// 返回证据记录与网络错误；HTTP 4xx/5xx 不会作为错误返回。
func (c *HTTPClient) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (*model.HTTPExchange, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("empty URL")
	}
	if method == "" {
		method = http.MethodGet
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for key, value := range c.options.Headers {
		request.Header.Set(key, value)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", c.options.UserAgent)
	}
	if request.Header.Get("Accept") == "" {
		request.Header.Set("Accept", "*/*")
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}
	started := time.Now()
	exchange := &model.HTTPExchange{
		ID:             utilities.NewID("ex"),
		Method:         request.Method,
		URL:            utilities.SanitizeURL(rawURL),
		Path:           utilities.Truncate(request.URL.RequestURI(), 1024),
		RequestHeaders: marshalHeaders(request.Header),
		RequestBody:    utilities.Truncate(string(body), 64*1024),
		RequestBytes:   int64(len(body)),
		CreatedAt:      time.Now().UTC(),
	}
	response, err := c.client.Do(request)
	if err != nil {
		exchange.Error = err.Error()
		exchange.DurationMS = time.Since(started).Milliseconds()
		c.record(exchange)
		return exchange, err
	}
	defer response.Body.Close()
	exchange.StatusCode = response.StatusCode
	exchange.ResponseHeaders = marshalHeaders(response.Header)
	exchange.ContentType = response.Header.Get("Content-Type")
	exchange.TLS = response.TLS != nil
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, c.options.MaxBody+1))
	if readErr != nil {
		exchange.Error = readErr.Error()
	}
	if int64(len(payload)) > c.options.MaxBody {
		payload = payload[:c.options.MaxBody]
		exchange.Truncated = true
	}
	exchange.ResponseBody = string(payload)
	exchange.ResponseBytes = int64(len(payload))
	exchange.BodySHA256 = utilities.SHA256Hex(payload)
	exchange.DurationMS = time.Since(started).Milliseconds()
	c.record(exchange)
	if readErr != nil {
		return exchange, readErr
	}
	return exchange, nil
}

// Get 执行 GET 请求。
//
// 参数 rawURL 为目标地址，headers 为附加头；返回证据与网络错误。
func (c *HTTPClient) Get(ctx context.Context, rawURL string, headers map[string]string) (*model.HTTPExchange, error) {
	return c.Do(ctx, http.MethodGet, rawURL, nil, headers)
}

// PostJSON 执行 JSON POST 请求。
//
// 参数 rawURL 为目标地址，payload 为待序列化对象，headers 为附加头。
// 返回证据与网络或序列化错误。
func (c *HTTPClient) PostJSON(ctx context.Context, rawURL string, payload any, headers map[string]string) (*model.HTTPExchange, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode JSON payload: %w", err)
	}
	merged := MergeHeaders(headers, map[string]string{"Content-Type": "application/json"})
	return c.Do(ctx, http.MethodPost, rawURL, body, merged)
}

// DecodeJSON 将响应正文解析为通用 JSON 值。
//
// 参数 exchange 为 HTTP 证据；返回解析值，空正文返回 nil。
func DecodeJSON(exchange *model.HTTPExchange) (any, error) {
	if exchange == nil || strings.TrimSpace(exchange.ResponseBody) == "" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(exchange.ResponseBody))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON response: %w", err)
	}
	return value, nil
}

// DecodeJSONMap 将响应正文解析为 JSON 对象。
//
// 参数 exchange 为 HTTP 证据；返回对象映射与解析错误。
func DecodeJSONMap(exchange *model.HTTPExchange) (map[string]any, error) {
	value, err := DecodeJSON(exchange)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return map[string]any{}, nil
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON response is not an object")
	}
	return result, nil
}

// DecodeJSONArray 将响应正文解析为 JSON 数组。
//
// 参数 exchange 为 HTTP 证据；返回数组与解析错误。
func DecodeJSONArray(exchange *model.HTTPExchange) ([]any, error) {
	value, err := DecodeJSON(exchange)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	result, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("JSON response is not an array")
	}
	return result, nil
}

// IsSuccess 判断 HTTP 状态码是否表示成功。
//
// 参数 status 为状态码；返回 200 到 299 范围的判断结果。
func IsSuccess(status int) bool {
	return status >= 200 && status < 300
}

// IsAuthRequired 判断状态码是否表示认证或授权失败。
//
// 参数 status 为状态码；返回 401 或 403 的判断结果。
func IsAuthRequired(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func (c *HTTPClient) record(exchange *model.HTTPExchange) {
	c.mu.Lock()
	c.records = append(c.records, exchange)
	recorder := c.recorder
	c.mu.Unlock()
	if recorder != nil {
		recorder(exchange)
	}
}

// Exchanges 返回已记录的 HTTP 证据副本。
//
// 返回按创建顺序排列的证据切片；调用方可安全修改返回值。
func (c *HTTPClient) Exchanges() []*model.HTTPExchange {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*model.HTTPExchange, len(c.records))
	copy(result, c.records)
	return result
}

// ResetExchanges 清空内部证据缓冲。
//
// 返回值为空；通常在单个目标处理完成后调用，避免跨目标混淆。
func (c *HTTPClient) ResetExchanges() {
	c.mu.Lock()
	c.records = nil
	c.mu.Unlock()
}

func marshalHeaders(headers http.Header) string {
	redacted := utilities.RedactHTTPHeaders(headers)
	payload, err := json.Marshal(redacted)
	if err != nil {
		return "{}"
	}
	return string(payload)
}

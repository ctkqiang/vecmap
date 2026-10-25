package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecmap/internal/constant"
	"vecmap/internal/model"
)

// maxHTTPBody 限制单次响应读取量，避免恶意服务用超大响应耗尽内存。
const maxHTTPBody = 2 << 20

// 指纹置信度，写入 model.Fingerprint.Confidence。
const (
	confidenceHigh   = "high"
	confidenceMedium = "medium"
	confidenceLow    = "low"
)

// httpResult 是一次 HTTP 探测的原始结果。
type httpResult struct {
	Status int
	Header http.Header
	Body   []byte
}

// httpProber 封装带超时与协议追踪的 HTTP 调用，指纹与枚举共用同一套逻辑。
type httpProber struct {
	opts   Options
	client *http.Client
}

// newHTTPProber 按扫描参数创建复用连接的 HTTP 客户端。
func newHTTPProber(opts Options) *httpProber {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		// 审计场景常遇到自签证书，--insecure 时允许跳过校验。
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.Insecure},
		MaxIdleConns:        opts.Workers,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &httpProber{
		opts:   opts,
		client: &http.Client{Timeout: opts.Timeout, Transport: transport},
	}
}

// primaryScheme 选择首次尝试的传输协议。
func primaryScheme(ep model.Endpoint) string {
	if ep.Port == 443 || ep.Port == 8443 || strings.EqualFold(ep.Protocol, "HTTPS") {
		return "https"
	}
	return "http"
}

// endpointURL 拼接探测 URL。
func endpointURL(ep model.Endpoint, scheme, path string) string {
	return scheme + "://" + net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)) + path
}

// fetch 先按主协议请求，失败后换另一种协议重试一次。
// 返回实际成功的协议，供后续枚举复用，避免每个请求都重复探测。
func (p *httpProber) fetch(ctx context.Context, ep model.Endpoint, method, path string, payload []byte) (*httpResult, string, error) {
	primary := primaryScheme(ep)
	schemes := []string{primary}
	if primary == "http" {
		schemes = append(schemes, "https")
	} else {
		schemes = append(schemes, "http")
	}

	var lastErr error
	for _, scheme := range schemes {
		rawURL := endpointURL(ep, scheme, path)
		res, err := p.request(ctx, method, rawURL, payload)
		if err == nil {
			return res, scheme, nil
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		lastErr = err
		p.opts.trace(string(constant.ProtocolHTTP), rawURL, method, err.Error())
	}
	return nil, "", lastErr
}

// request 发送一次 HTTP 请求并读完响应体。
func (p *httpProber) request(ctx context.Context, method, rawURL string, payload []byte) (*httpResult, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", p.opts.UserAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return nil, err
	}

	p.opts.trace(string(constant.ProtocolHTTP), rawURL, method,
		fmt.Sprintf("HTTP %d (%d bytes)", resp.StatusCode, len(data)))
	return &httpResult{Status: resp.StatusCode, Header: resp.Header, Body: data}, nil
}

// denied 判断响应是否表示需要认证。
func denied(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// Fingerprinter 通过 REST 接口与 PostgreSQL 握手包识别向量数据库及其版本。
type Fingerprinter struct {
	*httpProber
}

// NewFingerprinter 创建指纹探测器。
func NewFingerprinter(opts Options) *Fingerprinter {
	return &Fingerprinter{httpProber: newHTTPProber(opts.normalized())}
}

// Probe 对单个端点做指纹识别。端点自带厂商时只探测该厂商，
// 否则按 Weaviate → Qdrant → Chroma → Milvus → pgvector 的顺序逐一尝试。
func (f *Fingerprinter) Probe(ctx context.Context, ep model.Endpoint) model.Fingerprint {
	switch constant.Vendor(NormalizeVendor(ep.Vendor)) {
	case constant.VendorWeaviate:
		return f.probeWeaviate(ctx, ep)
	case constant.VendorQdrant:
		return f.probeQdrant(ctx, ep)
	case constant.VendorChroma:
		return f.probeChroma(ctx, ep)
	case constant.VendorMilvus:
		return f.probeMilvus(ctx, ep)
	case constant.VendorPgVector:
		return f.probePostgres(ctx, ep)
	}
	return f.detect(ctx, ep)
}

// detect 在没有厂商提示时逐个试探，命中即返回。
func (f *Fingerprinter) detect(ctx context.Context, ep model.Endpoint) model.Fingerprint {
	probes := []func(context.Context, model.Endpoint) model.Fingerprint{
		f.probeWeaviate,
		f.probeQdrant,
		f.probeChroma,
		f.probeMilvus,
		f.probePostgres,
	}
	for _, probe := range probes {
		fp := probe(ctx, ep)
		if fp.Vendor != "" {
			return fp
		}
		if ctx.Err() != nil {
			break
		}
	}
	return newFingerprint(ep)
}

// newFingerprint 返回只带端点信息的空指纹。
func newFingerprint(ep model.Endpoint) model.Fingerprint {
	return model.Fingerprint{
		Endpoint:   ep,
		Confidence: confidenceLow,
		ProbedAt:   time.Now(),
	}
}

// probeWeaviate 通过 /v1/meta 识别 Weaviate，并用 /v1/schema 判断匿名访问。
func (f *Fingerprinter) probeWeaviate(ctx context.Context, ep model.Endpoint) model.Fingerprint {
	fp := newFingerprint(ep)

	res, scheme, err := f.fetch(ctx, ep, http.MethodGet, "/v1/meta", nil)
	if err != nil || res.Status != http.StatusOK {
		return fp
	}

	var meta struct {
		Version  string          `json:"version"`
		Hostname string          `json:"hostname"`
		Modules  json.RawMessage `json:"modules"`
	}
	if err := json.Unmarshal(res.Body, &meta); err != nil {
		return fp
	}
	if meta.Version == "" && meta.Hostname == "" && len(meta.Modules) == 0 {
		return fp
	}

	fp.Vendor = string(constant.VendorWeaviate)
	fp.Product = "Weaviate REST"
	fp.Version = meta.Version
	fp.Scheme = scheme
	fp.APIBase = "/v1"
	fp.Confidence = confidenceHigh
	fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET /v1/meta -> 200 (version %q, hostname %q)", meta.Version, meta.Hostname))

	schema, _, err := f.fetch(ctx, ep, http.MethodGet, "/v1/schema", nil)
	if err != nil {
		return fp
	}
	switch {
	case schema.Status == http.StatusOK:
		fp.AnonymousAccess = true
		fp.Evidence = append(fp.Evidence, "GET /v1/schema -> 200 (anonymous access allowed)")
	case denied(schema.Status):
		fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET /v1/schema -> %d (authentication required)", schema.Status))
	default:
		fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET /v1/schema -> %d", schema.Status))
	}
	return fp
}

// probeQdrant 通过根路径的产品标题识别 Qdrant，并用 /collections 判断匿名访问。
func (f *Fingerprinter) probeQdrant(ctx context.Context, ep model.Endpoint) model.Fingerprint {
	fp := newFingerprint(ep)

	res, scheme, err := f.fetch(ctx, ep, http.MethodGet, "/", nil)
	if err != nil || res.Status != http.StatusOK {
		return fp
	}

	var root struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(res.Body, &root); err != nil {
		return fp
	}
	if !strings.Contains(strings.ToLower(root.Title), "qdrant") {
		return fp
	}

	fp.Vendor = string(constant.VendorQdrant)
	fp.Product = "Qdrant REST"
	fp.Version = root.Version
	fp.Scheme = scheme
	fp.Confidence = confidenceHigh
	fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET / -> 200 (title %q, version %q)", root.Title, root.Version))

	collections, _, err := f.fetch(ctx, ep, http.MethodGet, "/collections", nil)
	if err != nil {
		return fp
	}
	switch {
	case collections.Status == http.StatusOK:
		fp.AnonymousAccess = true
		fp.Evidence = append(fp.Evidence, "GET /collections -> 200 (anonymous access allowed)")
	case denied(collections.Status):
		fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET /collections -> %d (authentication required)", collections.Status))
	}
	return fp
}

// probeChroma 依次尝试 v2 与 v1 版本接口，失败时退化为心跳接口。
func (f *Fingerprinter) probeChroma(ctx context.Context, ep model.Endpoint) model.Fingerprint {
	fp := newFingerprint(ep)

	paths := []struct {
		Version string
		Base    string
		Product string
	}{
		{"/api/v2/version", "/api/v2", "Chroma API v2"},
		{"/api/v1/version", "/api/v1", "Chroma API v1"},
	}

	for _, candidate := range paths {
		res, scheme, err := f.fetch(ctx, ep, http.MethodGet, candidate.Version, nil)
		if err != nil || res.Status != http.StatusOK {
			continue
		}
		var version struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(res.Body, &version); err != nil || version.Version == "" {
			continue
		}

		fp.Vendor = string(constant.VendorChroma)
		fp.Product = candidate.Product
		fp.Version = version.Version
		fp.Scheme = scheme
		fp.APIBase = candidate.Base
		fp.Confidence = confidenceHigh
		fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET %s -> 200 (version %q)", candidate.Version, version.Version))
		fp.AnonymousAccess = f.chromaAnonymous(ctx, ep, candidate.Base, &fp)
		return fp
	}

	// 版本接口在部分版本上不可用，用特征明显的心跳响应兜底。
	for _, candidate := range paths {
		path := candidate.Base + "/heartbeat"
		res, scheme, err := f.fetch(ctx, ep, http.MethodGet, path, nil)
		if err != nil || res.Status != http.StatusOK {
			continue
		}
		if !bytes.Contains(res.Body, []byte("nanosecond")) {
			continue
		}
		fp.Vendor = string(constant.VendorChroma)
		fp.Product = candidate.Product
		fp.Scheme = scheme
		fp.APIBase = candidate.Base
		fp.Confidence = confidenceMedium
		fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET %s -> 200 (heartbeat)", path))
		fp.AnonymousAccess = f.chromaAnonymous(ctx, ep, candidate.Base, &fp)
		return fp
	}
	return fp
}

// chromaAnonymous 检查默认租户下的集合列表是否需要认证，并记录证据。
func (f *Fingerprinter) chromaAnonymous(ctx context.Context, ep model.Endpoint, base string, fp *model.Fingerprint) bool {
	path := chromaCollectionsPath(base)
	res, _, err := f.fetch(ctx, ep, http.MethodGet, path, nil)
	if err != nil {
		return false
	}
	switch {
	case res.Status == http.StatusOK:
		fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET %s -> 200 (anonymous access allowed)", path))
		return true
	case denied(res.Status):
		fp.Evidence = append(fp.Evidence, fmt.Sprintf("GET %s -> %d (authentication required)", path, res.Status))
	}
	return false
}

// chromaCollectionsPath 返回默认租户与默认数据库下的集合列表路径。
func chromaCollectionsPath(base string) string {
	if base == "/api/v2" {
		return base + "/tenants/default_tenant/databases/default_database/collections"
	}
	return base + "/collections"
}

// probeMilvus 通过 REST v2 的集合列表接口识别 Milvus。
// code 字段存在即视为命中；code=0 说明接口在无凭证情况下可用。
func (f *Fingerprinter) probeMilvus(ctx context.Context, ep model.Endpoint) model.Fingerprint {
	fp := newFingerprint(ep)

	res, scheme, err := f.fetch(ctx, ep, http.MethodPost, "/v2/vectordb/collections/list", []byte("{}"))
	if err != nil || res.Status != http.StatusOK {
		return fp
	}

	var out struct {
		Code    *int            `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil || out.Code == nil {
		return fp
	}

	fp.Vendor = string(constant.VendorMilvus)
	fp.Product = "Milvus REST v2"
	fp.Scheme = scheme
	fp.APIBase = "/v2/vectordb"
	fp.Confidence = confidenceHigh
	if *out.Code == 0 {
		fp.AnonymousAccess = true
		fp.Evidence = append(fp.Evidence, "POST /v2/vectordb/collections/list -> 200 (code 0, anonymous access allowed)")
	} else {
		fp.Confidence = confidenceMedium
		fp.Evidence = append(fp.Evidence, fmt.Sprintf(
			"POST /v2/vectordb/collections/list -> 200 (code %d, message %q)", *out.Code, out.Message))
	}
	return fp
}

// probePostgres 发送 PostgreSQL SSLRequest 并检查应答字节。
// 'S' 或 'N' 只可能来自 PostgreSQL 有线协议；pgvector 扩展本身
// 需要认证后查询 pg_extension 才能确认，因此置信度只给 medium。
func (f *Fingerprinter) probePostgres(ctx context.Context, ep model.Endpoint) model.Fingerprint {
	fp := newFingerprint(ep)

	address := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	dialCtx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	if err != nil {
		return fp
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(f.opts.Timeout))

	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request[0:], 8)
	binary.BigEndian.PutUint32(request[4:], 80877103) // SSLRequest
	if _, err := conn.Write(request); err != nil {
		return fp
	}

	reply := make([]byte, 1)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fp
	}
	if reply[0] != 'S' && reply[0] != 'N' {
		return fp
	}

	fp.Vendor = string(constant.VendorPgVector)
	fp.Product = "PostgreSQL wire protocol"
	fp.Scheme = "tcp"
	fp.Confidence = confidenceMedium
	fp.Evidence = append(fp.Evidence,
		fmt.Sprintf("PostgreSQL SSLRequest -> %q", reply[0]),
		"pgvector extension cannot be confirmed before authentication")
	return fp
}

// NormalizeVendor 把用户或厂商字段里的名称规范成常量中的写法，
// 无法识别时返回空字符串。
func NormalizeVendor(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	for vendor := range constant.SupportedVendors {
		if strings.EqualFold(string(vendor), name) {
			return string(vendor)
		}
	}
	if strings.EqualFold(string(constant.VendorPgVector), name) {
		return string(constant.VendorPgVector)
	}
	return ""
}

// semver 是版本号的内部表示：核心数字段 + 预发布标识。
type semver struct {
	core []int
	pre  []string
}

// parseSemver 解析 "v1.30.19-rc.1" 这类版本号，忽略构建元数据。
// 只接受纯数字核心段，避免把 "1.2.3-alpine" 之类的标签当成版本。
func parseSemver(raw string) (semver, bool) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "v")
	value = strings.TrimPrefix(value, "V")
	if i := strings.IndexByte(value, '+'); i >= 0 {
		value = value[:i]
	}

	var pre []string
	if i := strings.IndexByte(value, '-'); i >= 0 {
		if i == len(value)-1 {
			return semver{}, false
		}
		pre = strings.Split(value[i+1:], ".")
		value = value[:i]
	}
	if value == "" {
		return semver{}, false
	}

	parts := strings.Split(value, ".")
	core := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return semver{}, false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return semver{}, false
		}
		core = append(core, number)
	}
	return semver{core: core, pre: pre}, true
}

// compareSemver 按 SemVer 规则比较两个版本，缺失的段按 0 处理。
func compareSemver(a, b semver) int {
	width := len(a.core)
	if len(b.core) > width {
		width = len(b.core)
	}
	for i := 0; i < width; i++ {
		left, right := 0, 0
		if i < len(a.core) {
			left = a.core[i]
		}
		if i < len(b.core) {
			right = b.core[i]
		}
		if left != right {
			if left < right {
				return -1
			}
			return 1
		}
	}

	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}

	width = len(a.pre)
	if len(b.pre) < width {
		width = len(b.pre)
	}
	for i := 0; i < width; i++ {
		left, right := a.pre[i], b.pre[i]
		leftNumber, leftErr := strconv.Atoi(left)
		rightNumber, rightErr := strconv.Atoi(right)

		switch {
		case leftErr == nil && rightErr == nil:
			if leftNumber != rightNumber {
				if leftNumber < rightNumber {
					return -1
				}
				return 1
			}
		case leftErr == nil:
			return -1 // 数字标识优先级低于字母标识
		case rightErr == nil:
			return 1
		default:
			if left != right {
				if left < right {
					return -1
				}
				return 1
			}
		}
	}

	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

// CompareVersions 比较两个版本号。第二个返回值表示两侧是否都是可解析的版本。
func CompareVersions(a, b string) (int, bool) {
	left, ok := parseSemver(a)
	if !ok {
		return 0, false
	}
	right, ok := parseSemver(b)
	if !ok {
		return 0, false
	}
	return compareSemver(left, right), true
}

// MatchCVEs 返回与给定厂商和版本匹配的公告条目。
// 版本为空或无法解析时不做任何猜测，直接返回空结果。
func MatchCVEs(vendor, version string) []constant.CVEEntry {
	canonical := NormalizeVendor(vendor)
	if canonical == "" {
		return nil
	}
	current, ok := parseSemver(version)
	if !ok {
		return nil
	}

	hits := make([]constant.CVEEntry, 0, 2)
	for _, entry := range constant.CVEs {
		if string(entry.Vendor) != canonical {
			continue
		}
		for _, affected := range entry.Ranges {
			if versionInRange(current, affected) {
				hits = append(hits, entry)
				break
			}
		}
	}
	return hits
}

// versionInRange 判断版本是否落在左闭右闭区间内。
func versionInRange(current semver, affected constant.VersionRange) bool {
	if affected.Min != "" {
		minimum, ok := parseSemver(affected.Min)
		if !ok {
			return false
		}
		if compareSemver(current, minimum) < 0 {
			return false
		}
	}
	if affected.Max != "" {
		maximum, ok := parseSemver(affected.Max)
		if !ok {
			return false
		}
		if compareSemver(current, maximum) > 0 {
			return false
		}
	}
	return true
}

package test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"vecmap/internal/engine"
	"vecmap/internal/model"
)

// endpointFromServer 把 httptest 的地址拆成扫描用的端点。
func endpointFromServer(t *testing.T, raw string) model.Endpoint {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	return model.Endpoint{Host: parsed.Hostname(), Port: port, Protocol: "TCP"}
}

// TestParseScope 覆盖单个主机、CIDR、区间、去重与上限。
func TestParseScope(t *testing.T) {
	cases := []struct {
		name  string
		input string
		limit int
		want  []string
	}{
		{"host", "127.0.0.1", 16, []string{"127.0.0.1"}},
		{"hostname", "Example.COM", 16, []string{"example.com"}},
		{"cidr", "192.168.1.0/30", 16, []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}},
		{"short range", "10.0.0.1-3", 16, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"full range", "10.0.0.1-10.0.0.2", 16, []string{"10.0.0.1", "10.0.0.2"}},
		{"dedupe", "127.0.0.1,127.0.0.1", 16, []string{"127.0.0.1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, err := engine.ParseScope(tc.input, tc.limit)
			if err != nil {
				t.Fatalf("ParseScope(%q): %v", tc.input, err)
			}
			if len(hosts) != len(tc.want) {
				t.Fatalf("hosts = %v, want %v", hosts, tc.want)
			}
			for i := range tc.want {
				if hosts[i] != tc.want[i] {
					t.Fatalf("hosts[%d] = %q, want %q", i, hosts[i], tc.want[i])
				}
			}
		})
	}

	if _, err := engine.ParseScope("10.0.0.0/8", 16); err == nil {
		t.Fatal("expected a ScopeTooLargeError for /8 with limit 16")
	} else if _, ok := err.(*engine.ScopeTooLargeError); !ok {
		t.Fatalf("error type = %T, want *engine.ScopeTooLargeError", err)
	}
	if _, err := engine.ParseScope("::1/126", 16); err == nil {
		t.Fatal("expected an error for an IPv6 CIDR")
	}
	if _, err := engine.ParseScope("bad host!", 16); err == nil {
		t.Fatal("expected an error for an invalid hostname")
	}
	if _, err := engine.ParseScope("  ", 16); err == nil {
		t.Fatal("expected an error for an empty scope")
	}
}

// TestParsePorts 覆盖列表、区间、去重与越界检查。
func TestParsePorts(t *testing.T) {
	ports, err := engine.ParsePorts("8080,6333,8000-8002")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	want := []int{6333, 8000, 8001, 8002, 8080}
	if len(ports) != len(want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports[%d] = %d, want %d", i, ports[i], want[i])
		}
	}

	for _, input := range []string{"0", "70000", "abc", "9000-8000", ""} {
		if _, err := engine.ParsePorts(input); err == nil {
			t.Fatalf("ParsePorts(%q) should fail", input)
		}
	}
}

// TestCompareVersions 覆盖等值、补零、预发布与非法输入。
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.30.19", "1.30.19", 0},
		{"1.30.19", "1.30.18", 1},
		{"1.30", "1.30.0", 0},
		{"v2.4.24", "2.4.23", 1},
		{"1.38.0-rc.0", "1.37.7", 1},
		{"1.38.0-rc.0", "1.38.0", -1},
		{"1.2.3+build.5", "1.2.3", 0},
	}
	for _, tc := range cases {
		got, ok := engine.CompareVersions(tc.left, tc.right)
		if !ok {
			t.Fatalf("CompareVersions(%q, %q) is not parseable", tc.left, tc.right)
		}
		if got != tc.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}

	for _, bad := range []string{"", "1.2.x", "1.2.3-", "latest"} {
		if _, ok := engine.CompareVersions(bad, "1.0.0"); ok {
			t.Fatalf("CompareVersions(%q) should fail", bad)
		}
	}
}

// TestMatchCVEs 校验真实公告区间与版本匹配，包含边界与未知版本。
func TestMatchCVEs(t *testing.T) {
	cases := []struct {
		vendor  string
		version string
		want    []string
	}{
		{"Weaviate", "1.30.10", []string{"CVE-2025-67818", "CVE-2025-67819", "CVE-2026-11500"}},
		{"weaviate", "1.38.0", nil},
		{"Weaviate", "1.38.0-rc.0", nil},
		{"Qdrant", "1.15.5", []string{"CVE-2026-25628", "GHSA-frc7-44gm-99qq"}},
		{"Qdrant", "1.20.0", nil},
		{"Milvus", "2.6.4", []string{"CVE-2025-64513", "CVE-2026-26190", "CVE-2026-69111"}},
		{"Chroma", "1.5.9", []string{"CVE-2026-45829", "CVE-2026-45831", "CVE-2026-92782", "CVE-2026-85664"}},
		{"Chroma", "2.0.0", nil},
		{"pgvector", "0.7.0", nil},
		{"Weaviate", "", nil},
		{"Unknown", "1.0.0", nil},
	}

	for _, tc := range cases {
		hits := engine.MatchCVEs(tc.vendor, tc.version)
		if len(hits) != len(tc.want) {
			ids := make([]string, 0, len(hits))
			for _, hit := range hits {
				ids = append(ids, hit.ID)
			}
			t.Fatalf("MatchCVEs(%q, %q) = %v, want %v", tc.vendor, tc.version, ids, tc.want)
		}
		for i, id := range tc.want {
			if hits[i].ID != id {
				t.Fatalf("MatchCVEs(%q, %q)[%d] = %q, want %q", tc.vendor, tc.version, i, hits[i].ID, id)
			}
		}
	}
}

// TestWeaviateFingerprintAndDump 用本地假服务验证真实 HTTP 探测链路。
func TestWeaviateFingerprintAndDump(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/meta":
			_, _ = w.Write([]byte(`{"version":"1.30.10","hostname":"lab"}`))
		case "/v1/schema":
			_, _ = w.Write([]byte(`{"classes":[{"class":"Article","vectorIndexConfig":{"distance":"cosine"},` +
				`"properties":[{"name":"title","dataType":["text"]}]}]}`))
		case "/v1/objects":
			_, _ = w.Write([]byte(`{"objects":[{"vector":[0.1,0.2,0.3],"properties":{"title":"hello"}}]}`))
		case "/v1/graphql":
			_, _ = w.Write([]byte(`{"data":{"Aggregate":{"Article":[{"meta":{"count":42}}]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := engine.DefaultOptions()
	opts.Timeout = 2 * time.Second
	var traces []string
	opts.Trace = func(protocol, target, action, detail string) {
		traces = append(traces, protocol+" "+target+" "+action)
	}

	endpoint := endpointFromServer(t, server.URL)
	fp := engine.NewFingerprinter(opts).Probe(context.Background(), endpoint)

	if fp.Vendor != "Weaviate" {
		t.Fatalf("vendor = %q, want Weaviate (evidence: %v)", fp.Vendor, fp.Evidence)
	}
	if fp.Version != "1.30.10" {
		t.Fatalf("version = %q, want 1.30.10", fp.Version)
	}
	if !fp.AnonymousAccess {
		t.Fatalf("anonymous access not detected: %v", fp.Evidence)
	}
	if len(traces) == 0 {
		t.Fatal("tracer received no protocol event")
	}

	dump := engine.NewDumper(opts).Dump(context.Background(), fp, engine.DefaultDumpOptions())
	if len(dump.Errors) != 0 {
		t.Fatalf("dump errors: %v", dump.Errors)
	}
	if !dump.Anonymous || len(dump.Collections) != 1 {
		t.Fatalf("collections = %d, anonymous = %v", len(dump.Collections), dump.Anonymous)
	}

	collection := dump.Collections[0]
	if collection.Name != "Article" || collection.Dimension != 3 || collection.Points != 42 || collection.Metric != "cosine" {
		t.Fatalf("collection = %+v", collection)
	}
	if dump.Samples != 1 {
		t.Fatalf("samples = %d, want 1", dump.Samples)
	}
	if len(collection.Fields) == 0 || collection.Fields[0].Name != "title" {
		t.Fatalf("fields = %+v", collection.Fields)
	}
}

// TestQdrantFingerprintAndDump 覆盖 Qdrant 的配置解析、scroll 与 k-NN 检索。
func TestQdrantFingerprintAndDump(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{"title":"qdrant - vector search engine","version":"1.15.5"}`))
		case "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"docs"}]}}`))
		case "/collections/docs":
			_, _ = w.Write([]byte(`{"result":{"points_count":10,"config":{"params":{"vectors":{"size":4,"distance":"Cosine"}}}}}`))
		case "/collections/docs/points/scroll":
			_, _ = w.Write([]byte(`{"result":{"points":[{"payload":{"title":"a","year":2026}}]}}`))
		case "/collections/docs/points/search":
			_, _ = w.Write([]byte(`{"result":[{"id":1,"payload":{"title":"a"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	opts := engine.DefaultOptions()
	opts.Timeout = 2 * time.Second

	endpoint := endpointFromServer(t, server.URL)
	fp := engine.NewFingerprinter(opts).Probe(context.Background(), endpoint)
	if fp.Vendor != "Qdrant" || fp.Version != "1.15.5" {
		t.Fatalf("fingerprint = %q %q", fp.Vendor, fp.Version)
	}
	if !fp.AnonymousAccess {
		t.Fatalf("anonymous access not detected: %v", fp.Evidence)
	}

	dump := engine.NewDumper(opts).Dump(context.Background(), fp, engine.DefaultDumpOptions())
	if len(dump.Errors) != 0 {
		t.Fatalf("dump errors: %v", dump.Errors)
	}

	collection := dump.Collections[0]
	if collection.Dimension != 4 || collection.Metric != "cosine" || collection.Points != 10 {
		t.Fatalf("collection = %+v", collection)
	}
	if dump.Samples != 1 || !dump.Searched || dump.KnnHits != 1 {
		t.Fatalf("samples=%d searched=%v hits=%d", dump.Samples, dump.Searched, dump.KnnHits)
	}

	names := make([]string, 0, len(collection.Fields))
	for _, field := range collection.Fields {
		names = append(names, field.Name)
	}
	if !strings.Contains(strings.Join(names, ","), "title") {
		t.Fatalf("payload fields = %v", names)
	}
}

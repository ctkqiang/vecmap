package test

import (
	"context"
	"testing"

	"github.com/ctkqiang/vecmap/internal/engine"
	"github.com/ctkqiang/vecmap/internal/model"
)

// TestRemoteTargetParsing 证明目标是任意主机而非本地专属：
// 公网域名、生产环境域名、公网 IP 均可正常解析为扫描目标。
func TestRemoteTargetParsing(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
		port   int
	}{
		{"https://vecdb.prod.example.com:6333", "https", "vecdb.prod.example.com", 6333},
		{"http://api.qdrant-cloud.com", "http", "api.qdrant-cloud.com", 0},
		{"8.8.8.8:9200", "http", "8.8.8.8", 9200},
		{"grpc://milvus.example.org:19530", "grpc", "milvus.example.org", 19530},
		{"redis://cache.prod.example.com:6380", "redis", "cache.prod.example.com", 6380},
	}
	for _, testCase := range cases {
		target, _, err := engine.ParseTarget(testCase.raw)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", testCase.raw, err)
		}
		if target.Scheme != testCase.scheme || target.Host != testCase.host || target.Port != testCase.port {
			t.Fatalf("ParseTarget(%q) = %+v, want scheme=%s host=%s port=%d",
				testCase.raw, target, testCase.scheme, testCase.host, testCase.port)
		}
	}
}

// TestRemoteTargetScopePermissive 证明未配置允许列表时（仅排除列表），
// 公网域名与公网 IP 均可通过范围校验——与 sqlmap 一致的远程扫描能力。
func TestRemoteTargetScopePermissive(t *testing.T) {
	scoper, err := engine.NewScoper(model.Scope{ExcludeCIDRs: []string{"10.99.0.0/16"}})
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	for _, host := range []string{"vecdb.prod.example.com", "8.8.8.8", "api.pinecone.io"} {
		if err := scoper.Check(context.Background(), host, 6333); err != nil {
			t.Fatalf("expected remote host %s to be scannable, got %v", host, err)
		}
	}
}

// TestRemoteTargetURLJoin 证明远程目标与 API 路径可正确拼接成请求 URL。
func TestRemoteTargetURLJoin(t *testing.T) {
	target, _, err := engine.ParseTarget("https://vecdb.prod.example.com:8443")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got := engine.TargetURL(target, "/collections"); got != "https://vecdb.prod.example.com:8443/collections" {
		t.Fatalf("TargetURL = %q", got)
	}
}

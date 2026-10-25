package test

import (
	"testing"

	"github.com/ctkqiang/vecmap/internal/engine"
)

func TestParseSearchReply(t *testing.T) {
	reply := engine.RespValue{
		Kind: engine.RespArray,
		Array: []engine.RespValue{
			{Kind: engine.RespInteger, Int: 2},
			{Kind: engine.RespBulk, Text: "doc:1"},
			{Kind: engine.RespArray, Array: []engine.RespValue{
				{Kind: engine.RespBulk, Text: "title"},
				{Kind: engine.RespBulk, Text: "hello"},
				{Kind: engine.RespBulk, Text: "score"},
				{Kind: engine.RespBulk, Text: "0.9"},
			}},
			{Kind: engine.RespBulk, Text: "doc:2"},
			{Kind: engine.RespArray, Array: []engine.RespValue{
				{Kind: engine.RespBulk, Text: "title"},
				{Kind: engine.RespBulk, Text: "world"},
			}},
		},
	}
	documents := engine.ParseSearchReply(reply)
	if len(documents) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(documents))
	}
	if documents[0].ID != "doc:1" || documents[0].Fields["title"] != "hello" {
		t.Fatalf("unexpected first document: %+v", documents[0])
	}
	if documents[1].Fields["title"] != "world" {
		t.Fatalf("unexpected second document: %+v", documents[1])
	}
}

func TestParseSearchReplyEmpty(t *testing.T) {
	if documents := engine.ParseSearchReply(engine.RespValue{}); len(documents) != 0 {
		t.Fatalf("expected no documents from empty reply")
	}
}

func TestRespPairs(t *testing.T) {
	pairs := engine.RespPairs([]any{"name", "idx", "num_docs", int64(42), "skip"})
	if pairs["name"] != "idx" {
		t.Fatalf("unexpected name: %v", pairs["name"])
	}
	if pairs["num_docs"] != int64(42) {
		t.Fatalf("unexpected num_docs: %v", pairs["num_docs"])
	}
	if _, exists := pairs["skip"]; exists {
		t.Fatalf("expected dangling key to be ignored")
	}
}

func TestRespIntConversions(t *testing.T) {
	if engine.RespInt(int64(7)) != 7 {
		t.Fatalf("expected int64 conversion")
	}
	if engine.RespInt("123") != 123 {
		t.Fatalf("expected string conversion")
	}
	if engine.RespInt(nil) != 0 {
		t.Fatalf("expected zero for nil")
	}
}

func TestRespValueAny(t *testing.T) {
	value := engine.RespValue{
		Kind: engine.RespArray,
		Array: []engine.RespValue{
			{Kind: engine.RespBulk, Text: "a"},
			{Kind: engine.RespInteger, Int: 9},
			{Kind: engine.RespBulk, Null: true},
		},
	}
	converted, ok := value.Any().([]any)
	if !ok || len(converted) != 3 {
		t.Fatalf("unexpected conversion: %v", value.Any())
	}
	if converted[0] != "a" || converted[1] != int64(9) || converted[2] != nil {
		t.Fatalf("unexpected converted values: %v", converted)
	}
}

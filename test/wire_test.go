package test

import (
	"testing"

	"vecmap/internal/engine"
)

func TestWireRoundTrip(t *testing.T) {
	payload := engine.EncodeRawMessage([]engine.RawField{
		{Number: 1, Bytes: []byte("qdrant")},
		{Number: 2, Bytes: []byte("1.9.0")},
		{Number: 3, Varint: 42},
	})
	fields := engine.ParseProtobuf(payload)
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}
	if string(fields[0].Bytes) != "qdrant" {
		t.Fatalf("unexpected field 1: %q", fields[0].Bytes)
	}
	if fields[2].Varint != 42 {
		t.Fatalf("unexpected varint: %d", fields[2].Varint)
	}
}

func TestWireStrings(t *testing.T) {
	payload := engine.EncodeRawMessage([]engine.RawField{
		{Number: 1, Bytes: []byte("milvus.proto.milvus.MilvusService")},
		{Number: 2, Bytes: []byte("2.5.10")},
		{Number: 3, Varint: 12345678},
	})
	stringsFound := engine.ProtobufStrings(payload)
	if !contains(stringsFound, "milvus.proto.milvus.MilvusService") {
		t.Fatalf("expected service string, got %v", stringsFound)
	}
	if !contains(stringsFound, "2.5.10") {
		t.Fatalf("expected version string, got %v", stringsFound)
	}
	if !contains(stringsFound, "12345678") {
		t.Fatalf("expected varint text, got %v", stringsFound)
	}
}

func TestWireNestedMessage(t *testing.T) {
	inner := engine.EncodeRawMessage([]engine.RawField{{Number: 1, Varint: 5}})
	outer := engine.EncodeRawMessage([]engine.RawField{{Number: 2, Bytes: inner}})
	fields := engine.ParseProtobuf(outer)
	if len(fields) != 1 || len(fields[0].Children) == 0 {
		t.Fatalf("expected nested message to parse, got %+v", fields)
	}
	if fields[0].Children[0].Varint != 5 {
		t.Fatalf("unexpected nested value: %+v", fields[0].Children[0])
	}
}

func TestWirePlainStringNotMessage(t *testing.T) {
	payload := engine.EncodeRawMessage([]engine.RawField{{Number: 1, Bytes: []byte("milvus.proto.milvus.MilvusService")}})
	fields := engine.ParseProtobuf(payload)
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if len(fields[0].Children) != 0 {
		t.Fatalf("expected plain ASCII to not parse as nested message: %+v", fields[0])
	}
	if string(fields[0].Bytes) != "milvus.proto.milvus.MilvusService" {
		t.Fatalf("expected raw bytes preserved")
	}
}

func TestWireTruncatedData(t *testing.T) {
	fields := engine.ParseProtobuf([]byte{0x0a, 0x10, 0x01})
	if len(fields) != 0 {
		t.Fatalf("expected truncated data to yield no fields, got %+v", fields)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

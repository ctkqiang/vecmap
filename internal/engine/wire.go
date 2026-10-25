package engine

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ProtobufField 表示解析出的一条 protobuf wire 字段。
type ProtobufField struct {
	Number   int
	WireType int
	Varint   uint64
	Bytes    []byte
	Children []ProtobufField
}

// RawField 表示用于编码原始 protobuf 消息的字段。
type RawField struct {
	Number int
	Varint uint64
	Bytes  []byte
}

// ParseProtobuf 解析 protobuf wire 格式数据。
//
// 参数 data 为原始字节；返回顶层字段列表。
// 长度字段（wire type 2）仅在内容可被完整、严格解析为嵌套消息时
// 才填充 Children；否则保留原始字节供字符串提取。
func ParseProtobuf(data []byte) []ProtobufField {
	fields, _ := parseProtobufStrict(data)
	return fields
}

func parseProtobufStrict(data []byte) ([]ProtobufField, bool) {
	fields := make([]ProtobufField, 0, 8)
	for offset := 0; offset < len(data); {
		key, size := consumeVarint(data[offset:])
		if size <= 0 {
			return fields, false
		}
		offset += size
		number := int(key >> 3)
		wireType := int(key & 0x7)
		if number <= 0 || number > 536_870_911 {
			return fields, false
		}
		field := ProtobufField{Number: number, WireType: wireType}
		switch wireType {
		case 0:
			value, consumed := consumeVarint(data[offset:])
			if consumed <= 0 {
				return fields, false
			}
			field.Varint = value
			offset += consumed
		case 1:
			if offset+8 > len(data) {
				return fields, false
			}
			field.Varint = binary.LittleEndian.Uint64(data[offset : offset+8])
			offset += 8
		case 2:
			length, consumed := consumeVarint(data[offset:])
			if consumed <= 0 {
				return fields, false
			}
			offset += consumed
			if length > uint64(len(data)-offset) {
				return fields, false
			}
			field.Bytes = data[offset : offset+int(length)]
			offset += int(length)
			if children, ok := parseProtobufStrict(field.Bytes); ok && len(children) > 0 {
				field.Children = children
			}
		case 5:
			if offset+4 > len(data) {
				return fields, false
			}
			field.Varint = uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
			offset += 4
		default:
			return fields, false
		}
		fields = append(fields, field)
	}
	return fields, true
}

// ProtobufStrings 从 protobuf 数据中提取人类可读字符串。
//
// 参数 data 为原始字节；返回去重后的字符串切片。
// 字符串来自长度字段中的 UTF-8 文本与较大数值字段的十进制表示。
func ProtobufStrings(data []byte) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, 8)
	var walk func(fields []ProtobufField)
	walk = func(fields []ProtobufField) {
		for _, field := range fields {
			switch field.WireType {
			case 0:
				if field.Varint >= 1_000_000 {
					text := strconv.FormatUint(field.Varint, 10)
					addString(&result, seen, text)
				}
			case 2:
				if len(field.Children) > 0 {
					walk(field.Children)
					continue
				}
				if utf8.Valid(field.Bytes) && hasPrintable(field.Bytes) {
					addString(&result, seen, string(field.Bytes))
				}
			}
		}
	}
	walk(ParseProtobuf(data))
	return result
}

// EncodeRawMessage 将原始字段列表编码为 protobuf 消息。
//
// 参数 fields 为字段编号到值的列表；返回编码后的字节。
// Varint 与 Bytes 同时为零值时字段被跳过。
func EncodeRawMessage(fields []RawField) []byte {
	result := make([]byte, 0, 64)
	for _, field := range fields {
		if field.Number <= 0 {
			continue
		}
		switch {
		case field.Varint != 0:
			result = appendVarint(result, uint64(field.Number)<<3)
			result = appendVarint(result, field.Varint)
		case len(field.Bytes) > 0:
			result = appendVarint(result, uint64(field.Number)<<3|2)
			result = appendVarint(result, uint64(len(field.Bytes)))
			result = append(result, field.Bytes...)
		}
	}
	return result
}

func consumeVarint(data []byte) (uint64, int) {
	var value uint64
	for index := 0; index < len(data) && index < 10; index++ {
		value |= uint64(data[index]&0x7f) << (7 * index)
		if data[index]&0x80 == 0 {
			return value, index + 1
		}
	}
	return 0, 0
}

func appendVarint(buffer []byte, value uint64) []byte {
	for value >= 0x80 {
		buffer = append(buffer, byte(value)|0x80)
		value >>= 7
	}
	return append(buffer, byte(value))
}

func hasPrintable(data []byte) bool {
	printable := 0
	for _, value := range data {
		if value >= 0x20 && value < 0x7f {
			printable++
		}
	}
	return printable*100/len(data) >= 60
}

func addString(result *[]string, seen map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	*result = append(*result, value)
}

// FormatWireField 返回字段的可读表示。
//
// 参数 field 为已解析字段；返回用于调试与日志的摘要文本。
func FormatWireField(field ProtobufField) string {
	switch field.WireType {
	case 0, 1, 5:
		return fmt.Sprintf("field %d varint=%d", field.Number, field.Varint)
	case 2:
		return fmt.Sprintf("field %d bytes=%dB", field.Number, len(field.Bytes))
	default:
		return fmt.Sprintf("field %d type=%d", field.Number, field.WireType)
	}
}

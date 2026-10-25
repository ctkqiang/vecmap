package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/vecmap/internal/constant"
)

// RespKind 表示 RESP 应答类型。
type RespKind byte

const (
	// RespSimple 表示简单字符串应答。
	RespSimple RespKind = '+'
	// RespError 表示错误应答。
	RespError RespKind = '-'
	// RespInteger 表示整数应答。
	RespInteger RespKind = ':'
	// RespBulk 表示批量字符串应答。
	RespBulk RespKind = '$'
	// RespArray 表示数组应答。
	RespArray RespKind = '*'
)

// RespValue 表示一条已解析的 RESP 应答。
//
// Null 为 true 时表示批量字符串或数组的空值；Error 保留服务端返回的错误文本。
type RespValue struct {
	Kind  RespKind
	Text  string
	Int   int64
	Array []RespValue
	Null  bool
}

// String 返回 RESP 应答的文本表示。
//
// 返回简单字符串、批量字符串或错误内容；其他类型返回空字符串。
func (v RespValue) String() string {
	switch v.Kind {
	case RespSimple, RespBulk, RespError:
		return v.Text
	default:
		return ""
	}
}

// IsError 判断应答是否为服务端错误。
//
// 返回 true 表示 Kind 为 RespError。
func (v RespValue) IsError() bool {
	return v.Kind == RespError
}

// Any 将 RESP 应答转换为通用 Go 值。
//
// 返回 string、int64、[]any 或 nil；嵌套数组会递归转换。
func (v RespValue) Any() any {
	switch v.Kind {
	case RespSimple, RespBulk:
		if v.Null {
			return nil
		}
		return v.Text
	case RespInteger:
		return v.Int
	case RespArray:
		if v.Null {
			return nil
		}
		result := make([]any, 0, len(v.Array))
		for _, item := range v.Array {
			result = append(result, item.Any())
		}
		return result
	case RespError:
		return v.Text
	default:
		return nil
	}
}

// RespOptions 控制 Redis 连接行为。
type RespOptions struct {
	Timeout  time.Duration
	TLS      bool
	Insecure bool
	Username string
	Password string
	Database int
}

// RespClient 是只读 Redis 协议客户端。
//
// 客户端顺序复用单条 TCP 连接，适用于枚举与提取，不适用于高并发业务。
type RespClient struct {
	conn    net.Conn
	reader  *bufio.Reader
	timeout time.Duration
}

// DialRESP 建立 Redis 连接并完成认证。
//
// 参数 ctx 控制拨号超时，address 为 host:port，options 为认证与 TLS 配置。
// 返回已认证客户端；调用方负责关闭。
func DialRESP(ctx context.Context, address string, options RespOptions) (*RespClient, error) {
	if options.Timeout <= 0 {
		options.Timeout = constant.DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: options.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial redis: %w", err)
	}
	if options.TLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         HostFromAddress(address),
			InsecureSkipVerify: options.Insecure, //nolint:gosec
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("redis TLS handshake: %w", err)
		}
		conn = tlsConn
	}
	client := &RespClient{
		conn:    conn,
		reader:  bufio.NewReaderSize(conn, 32*1024),
		timeout: options.Timeout,
	}
	if options.Password != "" || options.Username != "" {
		args := []string{"AUTH"}
		if options.Username != "" {
			args = append(args, options.Username)
		}
		args = append(args, options.Password)
		reply, err := client.Do(ctx, args...)
		if err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("redis auth: %w", err)
		}
		if reply.IsError() {
			_ = client.Close()
			return nil, fmt.Errorf("redis auth rejected: %s", reply.Text)
		}
	}
	if options.Database > 0 {
		if _, err := client.Do(ctx, "SELECT", strconv.Itoa(options.Database)); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("redis select database: %w", err)
		}
	}
	return client, nil
}

// Do 执行一条 Redis 命令（只读使用方）。
//
// 参数 ctx 控制本次读写超时，args 为命令与参数。
// 返回服务端应答；协议错误或网络错误会作为 error 返回，业务错误保留在应答中。
func (c *RespClient) Do(ctx context.Context, args ...string) (RespValue, error) {
	if len(args) == 0 {
		return RespValue{}, fmt.Errorf("empty redis command")
	}
	if err := c.setDeadline(ctx); err != nil {
		return RespValue{}, err
	}
	if err := c.writeCommand(args); err != nil {
		return RespValue{}, err
	}
	return c.readReply(0)
}

// Close 关闭底层连接。
//
// 返回关闭错误；重复关闭由 net.Conn 安全处理。
func (c *RespClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Ping 发送 PING 并返回是否得到 PONG。
//
// 参数 ctx 控制调用超时；返回服务端状态文本。
func (c *RespClient) Ping(ctx context.Context) (string, error) {
	reply, err := c.Do(ctx, "PING")
	if err != nil {
		return "", err
	}
	if reply.IsError() {
		return "", fmt.Errorf("redis ping: %s", reply.Text)
	}
	return reply.String(), nil
}

// Info 读取服务端信息。
//
// 参数 ctx 控制调用超时，section 为空时读取默认段。
// 返回 INFO 文本；服务端错误会作为 error 返回。
func (c *RespClient) Info(ctx context.Context, section string) (string, error) {
	args := []string{"INFO"}
	if strings.TrimSpace(section) != "" {
		args = append(args, section)
	}
	reply, err := c.Do(ctx, args...)
	if err != nil {
		return "", err
	}
	if reply.IsError() {
		return "", fmt.Errorf("redis info: %s", reply.Text)
	}
	return reply.String(), nil
}

// Modules 读取已加载模块列表。
//
// 参数 ctx 控制调用超时；返回模块名到版本等字段的映射。
func (c *RespClient) Modules(ctx context.Context) ([]map[string]string, error) {
	reply, err := c.Do(ctx, "MODULE", "LIST")
	if err != nil {
		return nil, err
	}
	if reply.IsError() {
		return nil, fmt.Errorf("redis module list: %s", reply.Text)
	}
	result := make([]map[string]string, 0, len(reply.Array))
	for _, module := range reply.Array {
		entry := map[string]string{}
		for index := 0; index+1 < len(module.Array); index += 2 {
			entry[module.Array[index].String()] = module.Array[index+1].String()
		}
		if len(entry) > 0 {
			result = append(result, entry)
		}
	}
	return result, nil
}

// SearchIndexes 列出 RediSearch 索引。
//
// 参数 ctx 控制调用超时；返回索引名列表；未加载 RediSearch 时返回错误。
func (c *RespClient) SearchIndexes(ctx context.Context) ([]string, error) {
	reply, err := c.Do(ctx, "FT._LIST")
	if err != nil {
		return nil, err
	}
	if reply.IsError() {
		return nil, fmt.Errorf("redis FT._LIST: %s", reply.Text)
	}
	result := make([]string, 0, len(reply.Array))
	for _, item := range reply.Array {
		if name := item.String(); name != "" {
			result = append(result, name)
		}
	}
	return result, nil
}

// SearchInfo 读取 RediSearch 索引详情。
//
// 参数 ctx 控制调用超时，index 为索引名。
// 返回交替键值转换后的映射；服务端错误会作为 error 返回。
func (c *RespClient) SearchInfo(ctx context.Context, index string) (map[string]any, error) {
	reply, err := c.Do(ctx, "FT.INFO", index)
	if err != nil {
		return nil, err
	}
	if reply.IsError() {
		return nil, fmt.Errorf("redis FT.INFO %s: %s", index, reply.Text)
	}
	value, _ := reply.Any().([]any)
	return RespPairs(value), nil
}

// Search 执行只读全文/向量索引查询。
//
// 参数 ctx 控制调用超时，index 为索引名，query 为查询表达式，
// offset 与 limit 控制分页，fields 为可选返回字段。
// 返回命中文档、总数与错误；查询本身不修改任何数据。
func (c *RespClient) Search(ctx context.Context, index, query string, offset, limit int, fields []string) ([]RespDocument, int64, error) {
	args := []string{"FT.SEARCH", index, query}
	if offset > 0 {
		args = append(args, "LIMIT", strconv.Itoa(offset), strconv.Itoa(limit))
	} else {
		args = append(args, "LIMIT", "0", strconv.Itoa(limit))
	}
	if len(fields) > 0 {
		args = append(args, "RETURN", strconv.Itoa(len(fields)))
		args = append(args, fields...)
	}
	reply, err := c.Do(ctx, args...)
	if err != nil {
		return nil, 0, err
	}
	if reply.IsError() {
		return nil, 0, fmt.Errorf("redis FT.SEARCH %s: %s", index, reply.Text)
	}
	return ParseSearchReply(reply), searchTotal(reply), nil
}

// RespDocument 表示 RediSearch 返回的一条文档。
type RespDocument struct {
	ID     string
	Fields map[string]string
}

// ParseSearchReply 将 FT.SEARCH 应答解析为文档列表。
//
// 参数 reply 为服务端应答；返回文档切片，无法识别的片段会被跳过。
func ParseSearchReply(reply RespValue) []RespDocument {
	if len(reply.Array) < 2 {
		return nil
	}
	result := make([]RespDocument, 0, len(reply.Array)/2)
	for index := 1; index+1 < len(reply.Array); index += 2 {
		id := reply.Array[index].String()
		fields := map[string]string{}
		values := reply.Array[index+1].Array
		for fieldIndex := 0; fieldIndex+1 < len(values); fieldIndex += 2 {
			fields[values[fieldIndex].String()] = values[fieldIndex+1].String()
		}
		result = append(result, RespDocument{ID: id, Fields: fields})
	}
	return result
}

// RespPairs 将交替键值数组转换为映射。
//
// 参数 value 为 []any 形式的数组；返回键到值的映射，非字符串键会被忽略。
func RespPairs(value []any) map[string]any {
	result := make(map[string]any, len(value)/2)
	for index := 0; index+1 < len(value); index += 2 {
		key, ok := value[index].(string)
		if !ok || key == "" {
			continue
		}
		result[key] = value[index+1]
	}
	return result
}

// RespStrings 将 []any 转换为字符串切片。
//
// 参数 value 为通用数组；返回可打印字符串，非字符串项会被跳过。
func RespStrings(value []any) []string {
	result := make([]string, 0, len(value))
	for _, item := range value {
		if text, ok := item.(string); ok && text != "" {
			result = append(result, text)
		}
	}
	return result
}

// RespInt 将通用值转换为 int64。
//
// 参数 value 为 int64、string 或 float64；无法转换时返回 0。
func RespInt(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case string:
		parsed, _ := strconv.ParseInt(typed, 10, 64)
		return parsed
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func searchTotal(reply RespValue) int64 {
	if len(reply.Array) == 0 {
		return 0
	}
	if reply.Array[0].Kind == RespInteger {
		return reply.Array[0].Int
	}
	parsed, _ := strconv.ParseInt(reply.Array[0].String(), 10, 64)
	return parsed
}

func (c *RespClient) setDeadline(ctx context.Context) error {
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, hasDeadline := ctx.Deadline(); hasDeadline && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return c.conn.SetDeadline(deadline)
}

func (c *RespClient) writeCommand(args []string) error {
	buffer := make([]byte, 0, 64)
	buffer = append(buffer, '*')
	buffer = strconv.AppendInt(buffer, int64(len(args)), 10)
	buffer = append(buffer, '\r', '\n')
	for _, arg := range args {
		buffer = append(buffer, '$')
		buffer = strconv.AppendInt(buffer, int64(len(arg)), 10)
		buffer = append(buffer, '\r', '\n')
		buffer = append(buffer, arg...)
		buffer = append(buffer, '\r', '\n')
	}
	_, err := c.conn.Write(buffer)
	return err
}

func (c *RespClient) readReply(depth int) (RespValue, error) {
	if depth > 12 {
		return RespValue{}, fmt.Errorf("RESP nesting too deep")
	}
	prefix, err := c.reader.ReadByte()
	if err != nil {
		return RespValue{}, err
	}
	switch RespKind(prefix) {
	case RespSimple, RespError, RespInteger:
		line, err := c.readLine()
		if err != nil {
			return RespValue{}, err
		}
		value := RespValue{Kind: RespKind(prefix), Text: line}
		if RespKind(prefix) == RespInteger {
			parsed, err := strconv.ParseInt(line, 10, 64)
			if err != nil {
				return RespValue{}, fmt.Errorf("invalid RESP integer %q", line)
			}
			value.Int = parsed
		}
		return value, nil
	case RespBulk:
		line, err := c.readLine()
		if err != nil {
			return RespValue{}, err
		}
		size, err := strconv.Atoi(line)
		if err != nil {
			return RespValue{}, fmt.Errorf("invalid RESP bulk length %q", line)
		}
		if size < 0 {
			return RespValue{Kind: RespBulk, Null: true}, nil
		}
		if size > 64<<20 {
			return RespValue{}, fmt.Errorf("RESP bulk length %d exceeds limit", size)
		}
		payload := make([]byte, size+2)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return RespValue{}, err
		}
		return RespValue{Kind: RespBulk, Text: string(payload[:size])}, nil
	case RespArray:
		line, err := c.readLine()
		if err != nil {
			return RespValue{}, err
		}
		size, err := strconv.Atoi(line)
		if err != nil {
			return RespValue{}, fmt.Errorf("invalid RESP array length %q", line)
		}
		if size < 0 {
			return RespValue{Kind: RespArray, Null: true}, nil
		}
		if size > 1_000_000 {
			return RespValue{}, fmt.Errorf("RESP array length %d exceeds limit", size)
		}
		result := RespValue{Kind: RespArray, Array: make([]RespValue, 0, size)}
		for index := 0; index < size; index++ {
			item, err := c.readReply(depth + 1)
			if err != nil {
				return RespValue{}, err
			}
			result.Array = append(result.Array, item)
		}
		return result, nil
	default:
		return RespValue{}, fmt.Errorf("unsupported RESP prefix %q", prefix)
	}
}

func (c *RespClient) readLine() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

// RespFloat 将通用值转换为 float64。
//
// 参数 value 为 string、int64 或 float64；无法转换时返回 0 与 false。
func RespFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		return parsed, err == nil
	case int64:
		return float64(typed), true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return 0, false
		}
		return typed, true
	default:
		return 0, false
	}
}

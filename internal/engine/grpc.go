package engine

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	reflectiongrpc "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/ctkqiang/vecmap/internal/model"
)

// GRPCClient 提供 gRPC 健康检查、反射与描述符驱动调用能力。
//
// 客户端不依赖任何厂商生成桩，反射优先；反射不可用时回退到
// 原始 wire 编码调用，用于版本探测与字符串提取。
type GRPCClient struct {
	options model.GRPCOptions
}

// NewGRPCClient 创建 gRPC 客户端。
//
// 参数 options 为超时、TLS 与消息大小配置。
// 返回可复用的客户端。
func NewGRPCClient(options model.GRPCOptions) *GRPCClient {
	if options.Timeout <= 0 {
		options.Timeout = 8 * time.Second
	}
	if options.MaxMsgSize <= 0 {
		options.MaxMsgSize = 4 << 20
	}
	if options.UserAgent == "" {
		options.UserAgent = "github.com/ctkqiang/vecmap/1.0"
	}
	return &GRPCClient{options: options}
}

// Probe 执行健康检查与服务反射探测。
//
// 参数 ctx 控制整体超时，address 为 host:port，tls 表示服务是否加密。
// 返回探测信息；连接失败时返回不可达信息而不返回错误，
// 仅当参数非法时才返回错误。
func (g *GRPCClient) Probe(ctx context.Context, address string, tls bool) (*model.GRPCInfo, error) {
	info := &model.GRPCInfo{TLS: tls}
	if strings.TrimSpace(address) == "" {
		return info, fmt.Errorf("address is empty")
	}
	probeCtx, cancel := context.WithTimeout(ctx, g.options.Timeout)
	defer cancel()
	conn, err := g.dial(probeCtx, address, tls)
	if err != nil {
		return info, err
	}
	defer conn.Close()
	info.Reachable = true
	if status := g.checkHealth(probeCtx, conn); status != "" {
		info.Status = "health"
		info.ServingStatus = status
	}
	if files, listErr := g.reflectServices(probeCtx, conn); listErr == nil {
		info.Reflection = true
		info.Services = grpcServiceList(files)
	} else {
		info.RawMessages = append(info.RawMessages, listErr.Error())
	}
	return info, nil
}

// InvokeDynamic 使用反射描述符调用 gRPC 方法。
//
// 参数 ctx 控制调用超时，address 为 host:port，service 为完整服务名，
// method 为方法名，request 为 JSON 风格请求对象，tls 表示服务是否加密。
// 返回响应的 JSON 编码字节；反射不可用或调用失败时返回错误。
func (g *GRPCClient) InvokeDynamic(ctx context.Context, address, service, method string, request map[string]any, tls bool) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, g.options.Timeout)
	defer cancel()
	conn, err := g.dial(callCtx, address, tls)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	files, err := g.reflectServices(callCtx, conn)
	if err != nil {
		return nil, fmt.Errorf("server reflection: %w", err)
	}
	descriptor, err := files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return nil, fmt.Errorf("service %s: %w", service, err)
	}
	serviceDescriptor, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("symbol %s is not a service", service)
	}
	methodDescriptor := serviceDescriptor.Methods().ByName(protoreflect.Name(method))
	if methodDescriptor == nil {
		return nil, fmt.Errorf("method %s not found in %s", method, service)
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	input := dynamicpb.NewMessage(methodDescriptor.Input())
	if err := protojson.Unmarshal(requestBytes, input); err != nil {
		return nil, fmt.Errorf("bind request to %s: %w", methodDescriptor.Input().FullName(), err)
	}
	output := dynamicpb.NewMessage(methodDescriptor.Output())
	fullMethod := "/" + service + "/" + method
	if err := conn.Invoke(callCtx, fullMethod, input, output); err != nil {
		return nil, fmt.Errorf("invoke %s: %w", fullMethod, err)
	}
	marshaler := protojson.MarshalOptions{Resolver: filesResolver{files}}
	responseBytes, err := marshaler.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("encode response: %w", err)
	}
	return responseBytes, nil
}

// ProbeRawStrings 使用原始 wire 编码调用方法并提取响应字符串。
//
// 参数 ctx 控制调用超时，address 为 host:port，path 为完整方法路径，
// payload 为原始请求字节，tls 表示服务是否加密。
// 返回响应中的可读字符串；未注册编解码时由原始 codec 透传。
func (g *GRPCClient) ProbeRawStrings(ctx context.Context, address, path string, payload []byte, tls bool) ([]string, error) {
	callCtx, cancel := context.WithTimeout(ctx, g.options.Timeout)
	defer cancel()
	conn, err := g.dial(callCtx, address, tls)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	request := &rawMessage{Data: payload}
	response := &rawMessage{}
	if err := conn.Invoke(callCtx, path, request, response, grpc.ForceCodec(rawCodec{})); err != nil {
		return nil, err
	}
	return ProtobufStrings(response.Data), nil
}

// rawMessage 是原始 codec 的消息载体。
type rawMessage struct {
	Data []byte
}

// rawCodec 透传原始 protobuf 字节。
type rawCodec struct{}

// Name 返回 codec 名称。
func (rawCodec) Name() string {
	return "vecmap-raw"
}

// Marshal 返回消息原始字节。
func (rawCodec) Marshal(value any) ([]byte, error) {
	message, ok := value.(*rawMessage)
	if !ok {
		return nil, fmt.Errorf("raw codec expects *rawMessage")
	}
	return message.Data, nil
}

// Unmarshal 将响应字节存入消息。
func (rawCodec) Unmarshal(data []byte, value any) error {
	message, ok := value.(*rawMessage)
	if !ok {
		return fmt.Errorf("raw codec expects *rawMessage")
	}
	message.Data = data
	return nil
}

func (g *GRPCClient) dial(ctx context.Context, address string, tls bool) (*grpc.ClientConn, error) {
	transport := insecure.NewCredentials()
	if tls {
		transport = credentials.NewTLS(&cryptotls.Config{
			MinVersion:         cryptotls.VersionTLS12,
			InsecureSkipVerify: g.options.Insecure, //nolint:gosec
		})
	}
	options := []grpc.DialOption{
		grpc.WithTransportCredentials(transport),
		grpc.WithUserAgent(g.options.UserAgent),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(g.options.MaxMsgSize)),
	}
	conn, err := grpc.NewClient(address, options...)
	if err != nil {
		return nil, err
	}
	conn.Connect()
	stateCtx, cancel := context.WithTimeout(ctx, g.options.Timeout)
	defer cancel()
	for conn.GetState() != connectivity.Ready {
		if !conn.WaitForStateChange(stateCtx, conn.GetState()) {
			break
		}
	}
	return conn, nil
}

func (g *GRPCClient) checkHealth(ctx context.Context, conn *grpc.ClientConn) string {
	client := grpc_health_v1.NewHealthClient(conn)
	response, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return ""
	}
	return response.GetStatus().String()
}

func (g *GRPCClient) reflectServices(ctx context.Context, conn *grpc.ClientConn) (*protoregistry.Files, error) {
	client := reflectiongrpc.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&reflectiongrpc.ServerReflectionRequest{
		MessageRequest: &reflectiongrpc.ServerReflectionRequest_ListServices{ListServices: "*"},
	}); err != nil {
		return nil, err
	}
	response, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	services := response.GetListServicesResponse().GetService()
	if len(services) == 0 {
		return nil, fmt.Errorf("reflection returned no services")
	}
	fileSet := &descriptorpb.FileDescriptorSet{}
	seenFiles := map[string]struct{}{}
	for _, service := range services {
		name := service.GetName()
		if err := stream.Send(&reflectiongrpc.ServerReflectionRequest{
			MessageRequest: &reflectiongrpc.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: name},
		}); err != nil {
			return nil, err
		}
		fileResponse, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		for _, raw := range fileResponse.GetFileDescriptorResponse().GetFileDescriptorProto() {
			file := &descriptorpb.FileDescriptorProto{}
			if err := proto.Unmarshal(raw, file); err != nil {
				continue
			}
			if _, exists := seenFiles[file.GetName()]; exists {
				continue
			}
			seenFiles[file.GetName()] = struct{}{}
			fileSet.File = append(fileSet.File, file)
		}
	}
	files, err := protodesc.NewFiles(fileSet)
	if err != nil {
		return nil, err
	}
	return files, nil
}

func grpcServiceList(files *protoregistry.Files) []model.GRPCService {
	result := make([]model.GRPCService, 0, 8)
	files.RangeFiles(func(descriptor protoreflect.FileDescriptor) bool {
		services := descriptor.Services()
		for index := 0; index < services.Len(); index++ {
			service := services.Get(index)
			entry := model.GRPCService{
				Name:     string(service.Name()),
				Package:  string(service.ParentFile().Package()),
				FullName: string(service.FullName()),
			}
			methods := service.Methods()
			for methodIndex := 0; methodIndex < methods.Len(); methodIndex++ {
				method := methods.Get(methodIndex)
				entry.Methods = append(entry.Methods, model.GRPCMethod{
					Name:       string(method.Name()),
					FullName:   string(method.FullName()),
					InputType:  string(method.Input().FullName()),
					OutputType: string(method.Output().FullName()),
				})
			}
			result = append(result, entry)
		}
		return true
	})
	return result
}

// filesResolver 将 protoregistry.Files 适配为 protojson 所需的类型解析器。
type filesResolver struct {
	files *protoregistry.Files
}

// FindMessageByName 按完整名称解析消息类型。
func (r filesResolver) FindMessageByName(name protoreflect.FullName) (protoreflect.MessageType, error) {
	descriptor, err := r.files.FindDescriptorByName(name)
	if err != nil {
		return nil, err
	}
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("symbol %s is not a message", name)
	}
	return dynamicpb.NewMessageType(message), nil
}

// FindMessageByURL 不支持按 URL 解析，返回错误。
func (r filesResolver) FindMessageByURL(url string) (protoreflect.MessageType, error) {
	return nil, fmt.Errorf("message URL lookup is not supported: %s", url)
}

// FindExtensionByName 不支持扩展解析，返回错误。
func (r filesResolver) FindExtensionByName(name protoreflect.FullName) (protoreflect.ExtensionType, error) {
	return nil, fmt.Errorf("extension lookup is not supported: %s", name)
}

// FindExtensionByNumber 不支持扩展解析，返回错误。
func (r filesResolver) FindExtensionByNumber(message protoreflect.FullName, field protoreflect.FieldNumber) (protoreflect.ExtensionType, error) {
	return nil, fmt.Errorf("extension lookup is not supported: %s/%d", message, field)
}

// EnsureProtoMessage 将动态消息编码为 wire 字节。
//
// 参数 message 为 protobuf 消息；返回编码字节与错误。
func EnsureProtoMessage(message proto.Message) ([]byte, error) {
	return proto.Marshal(message)
}

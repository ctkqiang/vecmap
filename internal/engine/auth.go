package engine

import (
	"encoding/base64"
	"strings"

	"vecmap/internal/model"
)

// AuthHeaders 根据厂商与凭据生成认证请求头。
//
// 参数 vendor 为目标厂商，credentials 为运行期凭据。
// 返回可合并到 HTTP 请求的认证头；未提供凭据时返回空映射。
func AuthHeaders(vendor model.Vendor, credentials model.Credentials) map[string]string {
	headers := map[string]string{}
	if credentials.Bearer != "" {
		headers["Authorization"] = "Bearer " + credentials.Bearer
		return headers
	}
	if credentials.APIKey != "" {
		switch vendor {
		case model.VendorQdrant:
			headers["api-key"] = credentials.APIKey
		case model.VendorTypesense:
			headers["X-TYPESENSE-API-KEY"] = credentials.APIKey
		case model.VendorPinecone:
			headers["Api-Key"] = credentials.APIKey
		case model.VendorElasticsearch, model.VendorOpenSearch:
			headers["Authorization"] = "ApiKey " + credentials.APIKey
		default:
			headers["Authorization"] = "Bearer " + credentials.APIKey
		}
		return headers
	}
	if credentials.Username != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials.Username+":"+credentials.Password))
	}
	return headers
}

// MergeHeaders 合并请求头，后者覆盖前者。
//
// 参数 base 为基础头，extra 为附加头；返回新的映射。
func MergeHeaders(base, extra map[string]string) map[string]string {
	result := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		result[key] = value
	}
	for key, value := range extra {
		result[key] = value
	}
	return result
}

// HasAuth 判断凭据是否包含任何认证材料。
//
// 参数 credentials 为待判断凭据；返回 true 表示至少存在一种认证值。
func HasAuth(credentials model.Credentials) bool {
	return !credentials.Empty()
}

// AuthLabel 返回适合日志展示的认证方式。
//
// 参数 credentials 为运行期凭据；返回认证方式短文本。
func AuthLabel(credentials model.Credentials) string {
	switch {
	case credentials.Bearer != "":
		return "bearer"
	case credentials.APIKey != "":
		return "api_key"
	case credentials.Username != "":
		return "basic"
	case credentials.Password != "":
		return "password"
	default:
		return "anonymous"
	}
}

// NormalizeHeaderName 规范化请求头名称。
//
// 参数 name 为原始头名；返回去空格后的小写名称。
func NormalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

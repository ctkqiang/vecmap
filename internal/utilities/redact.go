package utilities

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// sensitiveHeaderNames 是需要在证据中脱敏的响应头名称。
var sensitiveHeaderNames = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"api-key":              {},
	"x-api-key":            {},
	"x-auth-token":         {},
	"x-amz-security-token": {},
	"www-authenticate":     {},
}

// sensitiveQueryKeys 是需要在 URL 中脱敏的查询参数名称。
var sensitiveQueryKeys = map[string]struct{}{
	"api_key":    {},
	"apikey":     {},
	"key":        {},
	"token":      {},
	"password":   {},
	"passwd":     {},
	"secret":     {},
	"signature":  {},
	"sig":        {},
	"auth":       {},
	"credential": {},
}

// SanitizeURL 返回移除凭据与敏感参数的 URL。
//
// 参数 raw 为原始 URL；返回 userinfo 已清除、敏感查询值已替换的文本。
func SanitizeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return RedactText(raw)
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		if isSensitiveQueryKey(key) {
			query.Set(key, "REDACTED")
		}
	}
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return parsed.String()
}

// RedactHTTPHeaders 将 HTTP 响应头转换为脱敏映射。
//
// 参数 headers 为 net/http 响应头；返回小写键到脱敏值的映射，
// 敏感头值统一替换为 REDACTED。
func RedactHTTPHeaders(headers http.Header) map[string]string {
	result := map[string]string{}
	for key, values := range headers {
		lower := strings.ToLower(key)
		if len(values) == 0 {
			continue
		}
		if isSensitiveHeaderName(lower) {
			result[lower] = "REDACTED"
			continue
		}
		result[lower] = strings.Join(values, ", ")
	}
	return result
}

// RedactHeaderMap 将字符串头映射转换为脱敏映射。
//
// 参数 headers 为头名到头值的映射；返回键保持原样的脱敏副本。
func RedactHeaderMap(headers map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range headers {
		if isSensitiveHeaderName(strings.ToLower(key)) {
			result[key] = "REDACTED"
			continue
		}
		result[key] = value
	}
	return result
}

// redactionPatterns 是 RedactText 使用的敏感模式。
var redactionPatterns = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._\-+/=]+`), `${1}REDACTED`},
	{regexp.MustCompile(`(?i)(api[_-]?key\s*[=:]\s*)[a-z0-9._\-]+`), `${1}REDACTED`},
	{regexp.MustCompile(`(?i)(token\s*[=:]\s*)[a-z0-9._\-]+`), `${1}REDACTED`},
	{regexp.MustCompile(`(?i)(password\s*[=:]\s*)[^\s&,;]+`), `${1}REDACTED`},
	{regexp.MustCompile(`(?i)(passwd\s*[=:]\s*)[^\s&,;]+`), `${1}REDACTED`},
	{regexp.MustCompile(`(?i)(secret\s*[=:]\s*)[a-z0-9._\-]+`), `${1}REDACTED`},
}

// RedactText 对任意文本执行保守脱敏。
//
// 参数 value 为原始文本；返回移除 Bearer 令牌、API Key、密码等
// 键值模式后的文本，用于请求摘要与错误信息的展示。
func RedactText(value string) string {
	for _, entry := range redactionPatterns {
		value = entry.pattern.ReplaceAllString(value, entry.replacement)
	}
	return value
}

func isSensitiveHeaderName(name string) bool {
	_, exists := sensitiveHeaderNames[name]
	return exists
}

func isSensitiveQueryKey(name string) bool {
	lower := strings.ToLower(name)
	_, exists := sensitiveQueryKeys[lower]
	return exists
}

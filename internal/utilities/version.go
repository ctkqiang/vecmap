package utilities

import (
	"strconv"
	"strings"
)

// Version 表示解析后的语义化版本。
type Version struct {
	Major int
	Minor int
	Patch int
	Pre   string
	Raw   string
	Valid bool
}

// ParseVersion 解析语义化版本字符串。
//
// 参数 raw 可带 v/V 前缀与预发布后缀（如 1.9.0-dev）。
// 返回解析结果；核心部分非数字时 Valid 为 false。
func ParseVersion(raw string) Version {
	version := Version{Raw: strings.TrimSpace(raw)}
	core := strings.TrimPrefix(strings.TrimPrefix(version.Raw, "v"), "V")
	if dash := strings.Index(core, "-"); dash >= 0 {
		version.Pre = core[dash+1:]
		core = core[:dash]
	}
	parts := strings.Split(core, ".")
	if len(parts) > 3 || len(parts) == 0 {
		return version
	}
	values := make([]int, len(parts))
	for index, part := range parts {
		number, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || number < 0 {
			return version
		}
		values[index] = number
	}
	if len(values) > 0 {
		version.Major = values[0]
	}
	if len(values) > 1 {
		version.Minor = values[1]
	}
	if len(values) > 2 {
		version.Patch = values[2]
	}
	version.Valid = true
	return version
}

// Compare 比较两个语义化版本。
//
// 返回 -1、0、1 分别表示小于、等于、大于。
// 预发布版本低于同核心的正式版本；预发布之间按字符串比较。
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		return compareInt(v.Major, other.Major)
	}
	if v.Minor != other.Minor {
		return compareInt(v.Minor, other.Minor)
	}
	if v.Patch != other.Patch {
		return compareInt(v.Patch, other.Patch)
	}
	switch {
	case v.Pre == other.Pre:
		return 0
	case v.Pre == "":
		return 1
	case other.Pre == "":
		return -1
	default:
		return compareText(v.Pre, other.Pre)
	}
}

// CompareVersions 比较两个原始版本字符串。
//
// 返回 -1、0、1 分别表示 a 小于、等于、大于 b。
func CompareVersions(a, b string) int {
	return ParseVersion(a).Compare(ParseVersion(b))
}

// VersionInRange 判断版本是否满足任一受影响区间。
//
// 参数 version 为识别到的版本，ranges 为公告声明的影响区间。
// 区间语法支持 <、<=、>、>=、==、= 单约束与逗号组合约束（AND），
// 支持 * 通配与 x 通配（如 1.9.x）以及预发布版本（如 1.9.0-dev）。
// 返回是否命中以及命中的区间描述；版本非法或 ranges 为空时返回 false。
func VersionInRange(version string, ranges []string) (bool, string) {
	parsed := ParseVersion(version)
	if !parsed.Valid || len(ranges) == 0 {
		return false, ""
	}
	for _, constraint := range ranges {
		reason := strings.TrimSpace(constraint)
		if reason == "" {
			continue
		}
		if rangeMatches(parsed, reason) {
			return true, reason
		}
	}
	return false, ""
}

func rangeMatches(version Version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "*" {
		return true
	}
	parts := strings.Split(constraint, ",")
	for _, rawPart := range parts {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		operator := "=="
		value := part
		for _, candidate := range []string{"<=", ">=", "==", "<", ">", "="} {
			if strings.HasPrefix(part, candidate) {
				operator = candidate
				value = strings.TrimSpace(strings.TrimPrefix(part, candidate))
				break
			}
		}
		if !constraintMatches(version, operator, value) {
			return false
		}
	}
	return true
}

func constraintMatches(version Version, operator, value string) bool {
	if strings.HasSuffix(value, ".x") || strings.HasSuffix(value, ".*") {
		prefix := strings.TrimSuffix(strings.TrimSuffix(value, "x"), ".")
		prefix = strings.TrimSuffix(prefix, "*")
		prefix = strings.TrimSuffix(prefix, ".")
		target := ParseVersion(prefix)
		if !target.Valid {
			return false
		}
		comparable := Version{Major: version.Major, Minor: version.Minor, Valid: true}
		trimmed := Version{Major: target.Major, Minor: target.Minor, Valid: true}
		switch operator {
		case "==", "=":
			return comparable.Compare(trimmed) == 0
		case "<":
			return comparable.Compare(trimmed) < 0
		case "<=":
			return comparable.Compare(trimmed) <= 0
		case ">":
			return comparable.Compare(trimmed) > 0
		case ">=":
			return comparable.Compare(trimmed) >= 0
		default:
			return false
		}
	}
	target := ParseVersion(value)
	if !target.Valid {
		return false
	}
	switch operator {
	case "<":
		return version.Compare(target) < 0
	case "<=":
		return version.Compare(target) <= 0
	case ">":
		return version.Compare(target) > 0
	case ">=":
		return version.Compare(target) >= 0
	case "==", "=":
		return version.Compare(target) == 0
	default:
		return false
	}
}

func compareInt(left, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareText(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

package engine

import (
	"fmt"
	"sort"
	"strings"

	"vecmap/internal/constant"
	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// AdvisoryCatalog 表示内置与外部导入公告的合并目录。
type AdvisoryCatalog struct {
	entries []model.Advisory
	byID    map[string]model.Advisory
}

// NewAdvisoryCatalog 创建公告目录。
//
// 参数 extra 为外部导入公告；相同 ID 的外部条目会覆盖内置条目。
// 返回已校验来源与匹配标志的目录实例。
func NewAdvisoryCatalog(extra []model.Advisory) *AdvisoryCatalog {
	catalog := &AdvisoryCatalog{byID: map[string]model.Advisory{}}
	for _, advisory := range constant.Advisories() {
		catalog.add(advisory)
	}
	for _, advisory := range extra {
		catalog.add(advisory)
	}
	return catalog
}

// LoadAdvisoryFile 从 JSON 文件读取外部公告。
//
// 参数 path 为文件路径；文件可为公告数组或 {"advisories": [...]} 对象。
// 返回通过基础校验的公告；未标记 Verified 的条目会保留但不会参与自动匹配。
func LoadAdvisoryFile(path string) ([]model.Advisory, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	var payload model.Payload
	if err := utilities.ReadJSONFile(path, &payload); err != nil {
		var list []model.Advisory
		if listErr := utilities.ReadJSONFile(path, &list); listErr != nil {
			return nil, fmt.Errorf("read advisories: %w", err)
		}
		payload.Advisories = list
	}
	if len(payload.Advisories) == 0 {
		return nil, fmt.Errorf("advisory file contains no entries")
	}
	result := make([]model.Advisory, 0, len(payload.Advisories))
	for index, advisory := range payload.Advisories {
		if err := validateAdvisory(advisory); err != nil {
			return nil, fmt.Errorf("advisory %d: %w", index+1, err)
		}
		result = append(result, advisory)
	}
	return result, nil
}

// All 返回目录中的全部公告。
//
// 返回按风险等级与编号排序的副本。
func (c *AdvisoryCatalog) All() []model.Advisory {
	if c == nil {
		return nil
	}
	result := make([]model.Advisory, len(c.entries))
	copy(result, c.entries)
	sort.SliceStable(result, func(left, right int) bool {
		leftRank := result[left].Severity.Rank()
		rightRank := result[right].Severity.Rank()
		if leftRank == rightRank {
			return result[left].ID < result[right].ID
		}
		return leftRank > rightRank
	})
	return result
}

// ByID 按内部 ID、CVE 或 CNVD 查找公告。
//
// 参数 id 为大小写不敏感标识；返回公告与是否存在标志。
func (c *AdvisoryCatalog) ByID(id string) (model.Advisory, bool) {
	if c == nil {
		return model.Advisory{}, false
	}
	value, exists := c.byID[strings.ToLower(strings.TrimSpace(id))]
	return value, exists
}

// Match 将产品版本与公告受影响区间进行关联。
//
// 参数 vendor 为厂商标识，product 为产品名，version 为识别出的版本。
// 返回按风险等级排序的匹配结果；版本为空或公告未标记 Matchable 时不会匹配。
func (c *AdvisoryCatalog) Match(vendor model.Vendor, product, version string) []model.AdvisoryMatch {
	if c == nil || strings.TrimSpace(version) == "" {
		return nil
	}
	product = strings.TrimSpace(product)
	matches := make([]model.AdvisoryMatch, 0, 4)
	for _, advisory := range c.entries {
		if !advisory.Verified || !advisory.Matchable {
			continue
		}
		if advisory.Vendor != vendor {
			continue
		}
		productMatch := advisory.Product == ""
		if !productMatch {
			productMatch = product == "" || productEquivalent(advisory.Product, product)
		}
		if !productMatch && product != "" {
			continue
		}
		affected, reason := utilities.VersionInRange(version, advisory.Affected)
		if !affected {
			continue
		}
		confidence := model.ConfidenceMedium
		if productMatch {
			confidence = model.ConfidenceHigh
		}
		matches = append(matches, model.AdvisoryMatch{
			AdvisoryID: advisory.ID,
			Vendor:     advisory.Vendor,
			Product:    advisory.Product,
			Version:    version,
			Severity:   advisory.Severity,
			Confidence: confidence,
			Reason:     fmt.Sprintf("version %s is within %s", version, reason),
			Advisory:   &advisory,
		})
	}
	sort.SliceStable(matches, func(left, right int) bool {
		leftRank := matches[left].Severity.Rank()
		rightRank := matches[right].Severity.Rank()
		if leftRank == rightRank {
			return matches[left].AdvisoryID < matches[right].AdvisoryID
		}
		return leftRank > rightRank
	})
	return matches
}

// MatchFingerprint 按指纹关联公告。
//
// 参数 fingerprint 为已识别的产品指纹；返回匹配结果。
func (c *AdvisoryCatalog) MatchFingerprint(fingerprint *model.Fingerprint) []model.AdvisoryMatch {
	if fingerprint == nil || fingerprint.Vendor == model.VendorUnknown {
		return nil
	}
	return c.Match(fingerprint.Vendor, fingerprint.Product, fingerprint.Version)
}

func (c *AdvisoryCatalog) add(advisory model.Advisory) {
	advisory.ID = strings.TrimSpace(advisory.ID)
	if advisory.ID == "" {
		advisory.ID = utilities.FirstNonEmpty(advisory.CVE, advisory.CNVD)
	}
	if advisory.ID == "" {
		return
	}
	if advisory.CVE == "" && strings.HasPrefix(strings.ToUpper(advisory.ID), "CVE-") {
		advisory.CVE = advisory.ID
	}
	if advisory.CNVD == "" && strings.HasPrefix(strings.ToUpper(advisory.ID), "CNVD-") {
		advisory.CNVD = advisory.ID
	}
	if !advisory.Severity.Valid() {
		advisory.Severity = model.SeverityForScore(advisory.CVSS.Score)
	}
	c.entries = append(c.entries, advisory)
	keys := []string{advisory.ID, advisory.CVE, advisory.CNVD, advisory.GHSA}
	for _, key := range keys {
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "" {
			c.byID[key] = advisory
		}
	}
}

func validateAdvisory(advisory model.Advisory) error {
	if strings.TrimSpace(advisory.ID) == "" && strings.TrimSpace(advisory.CVE) == "" && strings.TrimSpace(advisory.CNVD) == "" {
		return fmt.Errorf("missing advisory identifier")
	}
	if strings.TrimSpace(advisory.Title) == "" {
		return fmt.Errorf("missing title")
	}
	if advisory.Vendor == "" || advisory.Vendor == model.VendorUnknown {
		return fmt.Errorf("missing vendor")
	}
	if advisory.Matchable && len(advisory.References) == 0 {
		return fmt.Errorf("matchable advisory requires at least one reference")
	}
	for _, reference := range advisory.References {
		if !strings.HasPrefix(reference.URL, "https://") && !strings.HasPrefix(reference.URL, "http://") {
			return fmt.Errorf("invalid reference URL: %s", reference.URL)
		}
	}
	return nil
}

func productEquivalent(left, right string) bool {
	left = strings.ToLower(strings.TrimSpace(left))
	right = strings.ToLower(strings.TrimSpace(right))
	if left == right {
		return true
	}
	if left == "" || right == "" {
		return false
	}
	return strings.Contains(left, right) || strings.Contains(right, left)
}

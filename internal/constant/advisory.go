package constant

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ctkqiang/vecmap/internal/model"
)

// advisoryFiles 内嵌 GitHub Security Advisory 数据快照。
//
// GHSA-*.json 为 GitHub Advisory API 原始记录；extra.json 为无公开
// GHSA 记录的补充条目（字段同 API 模式）；meta.json 提供中文本地化、
// 厂商归属、匹配策略与影响区间校正。
//
//go:embed data/advisories/*.json
var advisoryFiles embed.FS

var (
	advisoryOnce  sync.Once
	advisoryCache []model.Advisory
	advisoryError error
)

// ghsaRecord 是 GitHub Advisory API 记录的视图。
//
// References 字段在官方 API 中可能是 URL 字符串数组或对象数组，
// 统一使用 RawMessage 并在 parseReferenceURLs 中兼容两种形态。
type ghsaRecord struct {
	GHSAID          string          `json:"ghsa_id"`
	CVEID           string          `json:"cve_id"`
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	Severity        string          `json:"severity"`
	PublishedAt     string          `json:"published_at"`
	HTMLURL         string          `json:"html_url"`
	References      json.RawMessage `json:"references"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    string `json:"first_patched_version"`
	} `json:"vulnerabilities"`
	CVSS struct {
		VectorString string   `json:"vector_string"`
		Score        *float64 `json:"score"`
	} `json:"cvss"`
}

// metaEntry 提供 GHSA 记录之外的公告元数据。
type metaEntry struct {
	ID            string   `json:"id"`
	Vendor        string   `json:"vendor,omitempty"`
	Product       string   `json:"product,omitempty"`
	TitleZH       string   `json:"title_zh,omitempty"`
	SummaryZH     string   `json:"summary_zh,omitempty"`
	Impact        string   `json:"impact,omitempty"`
	ImpactZH      string   `json:"impact_zh,omitempty"`
	Remediation   string   `json:"remediation,omitempty"`
	RemediationZH string   `json:"remediation_zh,omitempty"`
	CNVD          string   `json:"cnvd,omitempty"`
	MITRE         []string `json:"mitre,omitempty"`
	Matchable     *bool    `json:"matchable,omitempty"`
	Affected      []string `json:"affected,omitempty"`
	Source        string   `json:"source,omitempty"`
	CVSSScore     float64  `json:"cvss_score,omitempty"`
	CVSSVector    string   `json:"cvss_vector,omitempty"`
}

// packageVendors 将 GHSA 包（生态 + 包名）映射到厂商标识与产品名。
var packageVendors = []struct {
	Ecosystem string
	Prefix    string
	Vendor    model.Vendor
	Product   string
}{
	{Ecosystem: "rust", Prefix: "qdrant", Vendor: model.VendorQdrant, Product: "qdrant"},
	{Ecosystem: "pip", Prefix: "qdrant-client", Vendor: model.VendorQdrant, Product: "qdrant"},
	{Ecosystem: "go", Prefix: "github.com/milvus-io/milvus", Vendor: model.VendorMilvus, Product: "milvus"},
	{Ecosystem: "go", Prefix: "github.com/weaviate/weaviate", Vendor: model.VendorWeaviate, Product: "weaviate"},
	{Ecosystem: "pip", Prefix: "chromadb", Vendor: model.VendorChroma, Product: "chroma"},
	{Ecosystem: "maven", Prefix: "org.apache.logging.log4j:log4j-core", Vendor: model.VendorApache, Product: "log4j2"},
	{Ecosystem: "docker", Prefix: "typesense", Vendor: model.VendorTypesense, Product: "typesense"},
}

// Advisories 返回内置的漏洞公告目录。
//
// 目录由内嵌的 GitHub Security Advisory 快照（GHSA-*.json）与补充数据
// （extra.json、meta.json）在首次调用时解析生成，不包含任何 Go 源码级
// 硬编码条目；数据刷新请执行 scripts/refresh_advisories.sh。
// 返回按 ID 排序的公告副本；内嵌数据损坏时直接失败。
func Advisories() []model.Advisory {
	advisoryOnce.Do(loadAdvisories)
	if advisoryError != nil {
		panic(fmt.Sprintf("vecmap: built-in advisory data is broken: %v", advisoryError))
	}
	return append([]model.Advisory(nil), advisoryCache...)
}

func loadAdvisories() {
	meta, err := loadMeta()
	if err != nil {
		advisoryError = err
		return
	}
	entries, err := advisoryFiles.ReadDir("data/advisories")
	if err != nil {
		advisoryError = fmt.Errorf("read embedded advisory directory: %w", err)
		return
	}
	result := make([]model.Advisory, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == "meta.json" || !strings.HasSuffix(name, ".json") {
			continue
		}
		payload, err := advisoryFiles.ReadFile("data/advisories/" + name)
		if err != nil {
			advisoryError = fmt.Errorf("read %s: %w", name, err)
			return
		}
		records, err := parseRecords(payload)
		if err != nil {
			advisoryError = fmt.Errorf("parse %s: %w", name, err)
			return
		}
		for _, record := range records {
			advisory, err := convertAdvisory(record, meta)
			if err != nil {
				advisoryError = fmt.Errorf("convert %s: %w", name, err)
				return
			}
			result = append(result, advisory)
		}
	}
	sort.SliceStable(result, func(left, right int) bool {
		return result[left].ID < result[right].ID
	})
	advisoryCache = result
}

// parseRecords 兼容单条记录与记录数组两种数据文件形态。
//
// 参数 payload 为数据文件原始字节；返回 GHSA 记录切片。
func parseRecords(payload []byte) ([]ghsaRecord, error) {
	var single ghsaRecord
	if err := json.Unmarshal(payload, &single); err == nil {
		if single.GHSAID != "" || single.CVEID != "" {
			return []ghsaRecord{single}, nil
		}
	}
	var records []ghsaRecord
	if err := json.Unmarshal(payload, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func loadMeta() (map[string]metaEntry, error) {
	payload, err := advisoryFiles.ReadFile("data/advisories/meta.json")
	if err != nil {
		return nil, fmt.Errorf("read meta.json: %w", err)
	}
	var entries []metaEntry
	if err := json.Unmarshal(payload, &entries); err != nil {
		return nil, fmt.Errorf("parse meta.json: %w", err)
	}
	result := make(map[string]metaEntry, len(entries))
	for _, entry := range entries {
		keys := []string{entry.ID, strings.ToUpper(strings.TrimSpace(entry.CNVD))}
		for _, key := range keys {
			key = strings.ToUpper(strings.TrimSpace(key))
			if key != "" {
				result[key] = entry
			}
		}
	}
	return result, nil
}

func convertAdvisory(record ghsaRecord, meta map[string]metaEntry) (model.Advisory, error) {
	cve := strings.ToUpper(strings.TrimSpace(record.CVEID))
	ghsa := strings.ToUpper(strings.TrimSpace(record.GHSAID))
	id := cve
	if id == "" {
		id = ghsa
	}
	if id == "" {
		return model.Advisory{}, fmt.Errorf("record has neither CVE nor GHSA identifier")
	}
	entry := meta[cve]
	if entry.ID == "" {
		entry = meta[ghsa]
	}
	vendor, product := resolvePackageVendor(record.Vulnerabilities)
	if entry.Vendor != "" {
		vendor = model.ParseVendor(entry.Vendor)
	}
	if entry.Product != "" {
		product = entry.Product
	}
	if vendor == model.VendorUnknown {
		vendor = model.ParseVendor(strings.ToLower(product))
	}
	severity := parseGHSAseverity(record.Severity)
	score := 0.0
	if record.CVSS.Score != nil {
		score = *record.CVSS.Score
	}
	vector := record.CVSS.VectorString
	if entry.CVSSScore > 0 {
		score = entry.CVSSScore
	}
	if entry.CVSSVector != "" {
		vector = entry.CVSSVector
	}
	if !severity.Valid() {
		severity = model.SeverityForScore(score)
	}
	matchable := true
	if entry.Matchable != nil {
		matchable = *entry.Matchable
	}
	affected := entry.Affected
	if len(affected) == 0 {
		affected = collectRanges(record.Vulnerabilities, vendor)
	}
	source := entry.Source
	if source == "" {
		source = "GitHub Security Advisory"
	}
	return model.Advisory{
		ID:            id,
		GHSA:          ghsa,
		CVE:           cve,
		CNVD:          entry.CNVD,
		Vendor:        vendor,
		Product:       product,
		Title:         record.Summary,
		TitleZH:       entry.TitleZH,
		Summary:       record.Description,
		SummaryZH:     entry.SummaryZH,
		Impact:        entry.Impact,
		ImpactZH:      entry.ImpactZH,
		Remediation:   entry.Remediation,
		RemediationZH: entry.RemediationZH,
		Severity:      severity,
		CVSS:          model.CVSS{Score: score, Vector: vector, Version: cvssVersion(vector)},
		Affected:      affected,
		References:    buildReferences(record, cve),
		MITRE:         entry.MITRE,
		Verified:      true,
		Matchable:     matchable,
		Source:        source,
		PublishedAt:   datePart(record.PublishedAt),
	}, nil
}

func resolvePackageVendor(vulnerabilities []struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	FirstPatchedVersion    string `json:"first_patched_version"`
}) (model.Vendor, string) {
	best := model.VendorUnknown
	product := ""
	for _, vulnerability := range vulnerabilities {
		pkg := vulnerability.Package
		for _, mapping := range packageVendors {
			if pkg.Ecosystem != mapping.Ecosystem || !strings.HasPrefix(pkg.Name, mapping.Prefix) {
				continue
			}
			if best == model.VendorUnknown {
				best = mapping.Vendor
				product = mapping.Product
				continue
			}
			if best != mapping.Vendor {
				return model.VendorUnknown, ""
			}
		}
	}
	return best, product
}

func collectRanges(vulnerabilities []struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	FirstPatchedVersion    string `json:"first_patched_version"`
}, vendor model.Vendor) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, 4)
	for _, vulnerability := range vulnerabilities {
		pkg := vulnerability.Package
		if vendor == model.VendorApache && !strings.HasPrefix(pkg.Name, "org.apache.logging.log4j:") {
			continue
		}
		value := strings.TrimSpace(vulnerability.VulnerableVersionRange)
		if value == "" || isPseudoVersionRange(value) {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func isPseudoVersionRange(value string) bool {
	return strings.Contains(value, "-0.20")
}

func buildReferences(record ghsaRecord, cve string) []model.Reference {
	seen := map[string]struct{}{}
	result := make([]model.Reference, 0, 8)
	if record.HTMLURL != "" {
		result = append(result, model.Reference{Title: "GitHub Advisory", URL: record.HTMLURL, Source: "GitHub Advisory Database"})
		seen[record.HTMLURL] = struct{}{}
	}
	if cve != "" {
		url := "https://nvd.nist.gov/vuln/detail/" + cve
		result = append(result, model.Reference{Title: cve, URL: url, Source: "NVD"})
		seen[url] = struct{}{}
	}
	for _, url := range parseReferenceURLs(record.References) {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		if _, exists := seen[url]; exists {
			continue
		}
		seen[url] = struct{}{}
		result = append(result, model.Reference{Title: url, URL: url, Source: "GitHub Advisory Database"})
		if len(result) >= 12 {
			break
		}
	}
	return result
}

// parseReferenceURLs 兼容对象数组与字符串数组两种引用形态。
//
// 参数 raw 为 References 原始 JSON；返回 URL 字符串切片。
func parseReferenceURLs(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var objects []struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &objects); err == nil {
		result := make([]string, 0, len(objects))
		for _, object := range objects {
			if object.URL != "" {
				result = append(result, object.URL)
			}
		}
		return result
	}
	var urls []string
	if err := json.Unmarshal(raw, &urls); err == nil {
		return urls
	}
	return nil
}

func parseGHSAseverity(raw string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "moderate", "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func cvssVersion(vector string) string {
	if strings.HasPrefix(vector, "CVSS:4.") {
		return "4.0"
	}
	if strings.HasPrefix(vector, "CVSS:3.") {
		return "3.1"
	}
	return ""
}

func datePart(timestamp string) string {
	timestamp = strings.TrimSpace(timestamp)
	if len(timestamp) >= 10 {
		return timestamp[:10]
	}
	return timestamp
}

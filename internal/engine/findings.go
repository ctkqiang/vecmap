package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"vecmap/internal/model"
	"vecmap/internal/utilities"
)

// AnalysisInput 汇总构建风险发现所需的证据。
type AnalysisInput struct {
	SessionID     string
	Target        *model.Target
	Fingerprint   *model.Fingerprint
	Probes        []*model.ProbeResult
	Extraction    *model.Extraction
	Authenticated bool
}

// Analyzer 将指纹、探测与提取证据转换为结构化风险发现。
type Analyzer struct {
	catalog *AdvisoryCatalog
}

// NewAnalyzer 创建风险分析器。
//
// 参数 catalog 为公告目录；传 nil 时仅执行暴露面分析。
// 返回可复用的分析器。
func NewAnalyzer(catalog *AdvisoryCatalog) *Analyzer {
	return &Analyzer{catalog: catalog}
}

// Analyze 生成目标的风险发现。
//
// 参数 input 为目标证据集合；返回按风险等级排序并去重的发现列表。
func (a *Analyzer) Analyze(input AnalysisInput) []*model.Finding {
	findings := make([]*model.Finding, 0, 8)
	if input.Target == nil {
		return findings
	}
	sensitiveCategories := map[string][]*model.ProbeResult{}
	for _, probe := range input.Probes {
		if probe == nil {
			continue
		}
		if probe.TargetID != "" && input.Target.ID != "" && probe.TargetID != input.Target.ID {
			continue
		}
		if !probe.Sensitive || !IsSuccess(probe.StatusCode) || probe.AuthRequired {
			continue
		}
		sensitiveCategories[probe.Category] = append(sensitiveCategories[probe.Category], probe)
	}
	if !input.Authenticated {
		if probes := collectCategories(sensitiveCategories, "collections", "schema", "indices", "objects", "nodes", "aliases"); len(probes) > 0 {
			finding := a.build(input, "unauth_api", "unauth_api", model.SeverityHigh, model.ConfidenceHigh)
			attachProbes(finding, probes)
			findings = append(findings, finding)
		}
		if probes := sensitiveCategories["metrics"]; len(probes) > 0 {
			finding := a.build(input, "metrics", "metrics", model.SeverityLow, model.ConfidenceHigh)
			attachProbes(finding, probes)
			findings = append(findings, finding)
		}
		if probes := sensitiveCategories["docs"]; len(probes) > 0 {
			finding := a.build(input, "docs", "docs", model.SeverityLow, model.ConfidenceMedium)
			attachProbes(finding, probes)
			findings = append(findings, finding)
		}
		if probes := sensitiveCategories["snapshot"]; len(probes) > 0 {
			finding := a.build(input, "exposed_snapshot", "snapshot", model.SeverityMedium, model.ConfidenceHigh)
			attachProbes(finding, probes)
			findings = append(findings, finding)
		}
		if probes := sensitiveCategories["cors"]; len(probes) > 0 {
			finding := a.build(input, "cors", "cors", model.SeverityMedium, model.ConfidenceHigh)
			attachProbes(finding, probes)
			findings = append(findings, finding)
		}
		if probes := collectCategories(sensitiveCategories, "stats", "status", "telemetry", "cluster"); len(probes) > 0 {
			finding := a.build(input, "exposure", "exposure", model.SeverityMedium, model.ConfidenceMedium)
			attachProbes(finding, probes)
			findings = append(findings, finding)
		}
		if input.Extraction != nil && len(input.Extraction.Records) > 0 {
			finding := a.build(input, "unauth_extract", "extraction", model.SeverityHigh, model.ConfidenceHigh)
			finding.Description = fmt.Sprintf("%s (%d records extracted)", utilities.TIn("en", "finding.unauth_extract.desc"), len(input.Extraction.Records))
			finding.DescriptionZH = fmt.Sprintf("%s（已提取 %d 条记录）", utilities.TIn("zh", "finding.unauth_extract.desc"), len(input.Extraction.Records))
			finding.SetEvidence([]string{fmt.Sprintf("collections=%d records=%d", len(input.Extraction.Collections), len(input.Extraction.Records))})
			findings = append(findings, finding)
		}
	}
	if input.Fingerprint != nil && input.Fingerprint.GRPC != nil && input.Fingerprint.GRPC.Reflection {
		finding := a.build(input, "grpc_reflection", "grpc", model.SeverityMedium, model.ConfidenceHigh)
		finding.SetEvidence([]string{"gRPC server reflection returned service descriptors"})
		if services := input.Fingerprint.GRPC.Services; len(services) > 0 {
			names := make([]string, 0, len(services))
			for index, service := range services {
				if index >= 8 {
					break
				}
				names = append(names, service.Name)
			}
			finding.SetEvidence(append(finding.Evidence(), "services: "+strings.Join(names, ", ")))
		}
		findings = append(findings, finding)
	}
	if input.Target.Scheme == "http" && input.Fingerprint != nil && input.Fingerprint.Vendor != model.VendorUnknown {
		finding := a.build(input, "tls", "tls", model.SeverityLow, model.ConfidenceHigh)
		finding.SetEvidence([]string{"cleartext management endpoint: " + input.Target.BaseURL()})
		findings = append(findings, finding)
	}
	if a != nil && a.catalog != nil && input.Fingerprint != nil {
		findings = append(findings, a.advisoryFindings(input)...)
	}
	findings = dedupeFindings(findings)
	sort.SliceStable(findings, func(left, right int) bool {
		leftRank := findings[left].Severity.Rank()
		rightRank := findings[right].Severity.Rank()
		if leftRank == rightRank {
			return findings[left].Category < findings[right].Category
		}
		return leftRank > rightRank
	})
	return findings
}

func (a *Analyzer) advisoryFindings(input AnalysisInput) []*model.Finding {
	matches := a.catalog.MatchFingerprint(input.Fingerprint)
	result := make([]*model.Finding, 0, len(matches))
	for _, match := range matches {
		advisory := match.Advisory
		if advisory == nil {
			continue
		}
		finding := &model.Finding{
			ID:            utilities.NewID("fnd"),
			SessionID:     input.SessionID,
			TargetID:      input.Target.ID,
			AdvisoryID:    advisory.ID,
			CVE:           advisory.CVE,
			CNVD:          advisory.CNVD,
			Title:         utilities.TfIn("en", "finding.advisory.title", advisory.ID),
			TitleZH:       utilities.TfIn("zh", "finding.advisory.title", advisory.ID),
			Severity:      advisory.Severity,
			Confidence:    match.Confidence,
			Category:      "advisory",
			Description:   advisory.Summary,
			DescriptionZH: advisory.SummaryZH,
			Impact:        advisory.Impact,
			ImpactZH:      advisory.ImpactZH,
			Remediation:   advisory.Remediation,
			RemediationZH: advisory.RemediationZH,
			CVSSScore:     advisory.CVSS.Score,
			CVSSVector:    advisory.CVSS.Vector,
			CreatedAt:     time.Now().UTC(),
		}
		if finding.Description == "" {
			finding.Description = utilities.TfIn("en", "finding.advisory.desc", input.Fingerprint.Version, advisory.ID)
		}
		if finding.DescriptionZH == "" {
			finding.DescriptionZH = utilities.TfIn("zh", "finding.advisory.desc", input.Fingerprint.Version, advisory.ID)
		}
		if finding.Remediation == "" {
			finding.Remediation = utilities.TIn("en", "finding.advisory.remediation")
		}
		if finding.RemediationZH == "" {
			finding.RemediationZH = utilities.TIn("zh", "finding.advisory.remediation")
		}
		finding.SetMITRE(advisory.MITRE)
		finding.SetReferences(advisory.References)
		finding.SetEvidence([]string{
			fmt.Sprintf("product=%s version=%s", input.Fingerprint.Product, input.Fingerprint.Version),
			match.Reason,
			fmt.Sprintf("confidence=%s", match.Confidence),
		})
		result = append(result, finding)
	}
	return result
}

func (a *Analyzer) build(input AnalysisInput, key, category string, severity model.Severity, confidence model.Confidence) *model.Finding {
	finding := &model.Finding{
		ID:            utilities.NewID("fnd"),
		SessionID:     input.SessionID,
		TargetID:      input.Target.ID,
		Title:         utilities.TIn("en", "finding."+key+".title"),
		TitleZH:       utilities.TIn("zh", "finding."+key+".title"),
		Severity:      severity,
		Confidence:    confidence,
		Category:      category,
		Description:   utilities.TIn("en", "finding."+key+".desc"),
		DescriptionZH: utilities.TIn("zh", "finding."+key+".desc"),
		Impact:        utilities.TIn("en", "finding."+key+".impact"),
		ImpactZH:      utilities.TIn("zh", "finding."+key+".impact"),
		Remediation:   utilities.TIn("en", "finding."+key+".remediation"),
		RemediationZH: utilities.TIn("zh", "finding."+key+".remediation"),
		CreatedAt:     time.Now().UTC(),
	}
	finding.SetMITRE(mitreForCategory(category))
	return finding
}

func attachProbes(finding *model.Finding, probes []*model.ProbeResult) {
	evidence := make([]string, 0, len(probes))
	exchangeIDs := make([]string, 0, len(probes))
	for index, probe := range probes {
		if index >= 12 {
			break
		}
		evidence = append(evidence, probe.Summary)
		if probe.ExchangeID != "" {
			exchangeIDs = append(exchangeIDs, probe.ExchangeID)
		}
	}
	finding.SetEvidence(evidence)
	finding.SetExchangeIDs(exchangeIDs)
}

func mitreForCategory(category string) []string {
	switch category {
	case "unauth_api":
		return []string{"T1595", "T1046", "T1213"}
	case "extraction":
		return []string{"T1213", "T1119", "T1567"}
	case "metrics":
		return []string{"T1592"}
	case "docs":
		return []string{"T1595.002", "T1592"}
	case "cors":
		return []string{"T1185"}
	case "grpc":
		return []string{"T1595", "T1046"}
	case "tls":
		return []string{"T1040"}
	case "snapshot":
		return []string{"T1530", "T1213"}
	case "exposure":
		return []string{"T1592", "T1213"}
	default:
		return []string{"T1595"}
	}
}

func collectCategories(groups map[string][]*model.ProbeResult, categories ...string) []*model.ProbeResult {
	result := make([]*model.ProbeResult, 0, 8)
	for _, category := range categories {
		result = append(result, groups[category]...)
	}
	return result
}

func dedupeFindings(findings []*model.Finding) []*model.Finding {
	seen := map[string]struct{}{}
	result := make([]*model.Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Category + "|" + finding.AdvisoryID + "|" + finding.TargetID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, finding)
	}
	return result
}

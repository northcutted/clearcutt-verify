// Package scan normalizes grype vulnerability output into ClearCutt's catalog
// finding model: it classifies each finding's layer (runtime vs base), inclusion
// category, and remediation status, and emits findings in a stable order. The
// output shape — including explicit null fields and key order — is reproduced
// exactly so the catalog site, the remediation planner, and the release gate that
// consume it see no change. The `scan` command owns grype invocation, the SBOM
// cache walk, and concurrency; this package is the pure transform it calls.
package scan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

// -- grype input model -------------------------------------------------------

// GrypeResult is the subset of grype's JSON output the normalizer consumes.
type GrypeResult struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln     `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	DataSource  string      `json:"dataSource"`
	Namespace   string      `json:"namespace"`
	Description string      `json:"description"`
	Fix         grypeFix    `json:"fix"`
	Cvss        []grypeCvss `json:"cvss"`
	Epss        []grypeEpss `json:"epss"`
	Risk        *float64    `json:"risk"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeCvss struct {
	Type    string           `json:"type"`
	Version string           `json:"version"`
	Vector  string           `json:"vector"`
	Metrics grypeCvssMetrics `json:"metrics"`
}

type grypeCvssMetrics struct {
	BaseScore *float64 `json:"baseScore"`
}

type grypeEpss struct {
	Date       string   `json:"date"`
	Epss       *float64 `json:"epss"`
	Percentile *float64 `json:"percentile"`
}

type grypeArtifact struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	Purl       json.RawMessage `json:"purl"`
	SourceInfo string          `json:"sourceInfo"`
}

type KEVCatalog struct {
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	byCVE           map[string]KEVEntry
}

type KEVEntry struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

func ParseKEVCatalog(raw []byte) (*KEVCatalog, error) {
	var catalog KEVCatalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, err
	}
	catalog.byCVE = map[string]KEVEntry{}
	for _, entry := range catalog.Vulnerabilities {
		if entry.CVEID != "" {
			catalog.byCVE[strings.ToUpper(entry.CVEID)] = entry
		}
	}
	return &catalog, nil
}

func (kevCatalog *KEVCatalog) Info(cve string) *catalog.KEVInfo {
	if kevCatalog == nil {
		return nil
	}
	entry, ok := kevCatalog.byCVE[strings.ToUpper(cve)]
	if !ok {
		return nil
	}
	return &catalog.KEVInfo{
		KnownExploited:             true,
		CatalogVersion:             strOrNil(kevCatalog.CatalogVersion),
		DateReleased:               strOrNil(kevCatalog.DateReleased),
		DateAdded:                  strOrNil(entry.DateAdded),
		DueDate:                    strOrNil(entry.DueDate),
		VendorProject:              strOrNil(entry.VendorProject),
		Product:                    strOrNil(entry.Product),
		VulnerabilityName:          strOrNil(entry.VulnerabilityName),
		RequiredAction:             strOrNil(entry.RequiredAction),
		KnownRansomwareCampaignUse: strOrNil(entry.KnownRansomwareCampaignUse),
	}
}

// -- normalized output model -------------------------------------------------
//
// Distinct from catalog.FindingInfo (which is the omitempty-tolerant *consumer*
// shape). The producer emits explicit nulls and a fixed key order to match the
// retired .mjs byte-for-byte.

// Report is the normalized vulnerability scan output for one (tag, target, arch).
type Report struct {
	ScannedAt         string                 `json:"scannedAt"`
	Scanner           string                 `json:"scanner"`
	DBBuiltAt         *string                `json:"dbBuiltAt"`
	KEVStatus         string                 `json:"kevStatus"`
	KEVCatalogVersion *string                `json:"kevCatalogVersion"`
	CountsBySeverity  catalog.SeverityCounts `json:"countsBySeverity"`
	Findings          []finding              `json:"findings"`
}

type finding struct {
	ID             string                  `json:"id"`
	Severity       string                  `json:"severity"`
	PackageName    string                  `json:"packageName"`
	PackageVersion string                  `json:"packageVersion"`
	Purl           *string                 `json:"purl"`
	Layer          string                  `json:"layer"`
	FixedIn        *string                 `json:"fixedIn"`
	FixState       string                  `json:"fixState"`
	Remediation    catalog.RemediationInfo `json:"remediation"`
	Inclusion      catalog.InclusionInfo   `json:"inclusion"`
	DataSource     *string                 `json:"dataSource"`
	Namespace      *string                 `json:"namespace"`
	Description    *string                 `json:"description"`
	CvssScore      *float64                `json:"cvssScore"`
	CvssVersion    *string                 `json:"cvssVersion"`
	CvssVector     *string                 `json:"cvssVector"`
	EpssScore      *float64                `json:"epssScore"`
	EpssPercentile *float64                `json:"epssPercentile"`
	RiskScore      *float64                `json:"riskScore"`
	KEV            *catalog.KEVInfo        `json:"kev"`
}

type targetMeta struct {
	target   string
	runtime  string
	language string
	version  string
	tier     string
}

// -- pure classification (mirrors the .mjs predicates) -----------------------

func strOrNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

var targetRuntimeRe = regexp.MustCompile(`^([a-z]+)(.+)$`)

// TargetMetadata derives language/version/tier from a target id (e.g.
// "python3.13-slim" -> language python, version 3.13, tier slim).
func TargetMetadata(target string) targetMeta {
	idx := strings.LastIndex(target, "-")
	rt := target
	tier := "unknown"
	if idx != -1 {
		rt = target[:idx]
		tier = target[idx+1:]
	}
	m := targetRuntimeRe.FindStringSubmatch(rt)
	if m == nil {
		return targetMeta{target: target, runtime: rt, language: rt, version: "", tier: tier}
	}
	return targetMeta{target: target, runtime: rt, language: m[1], version: m[2], tier: tier}
}

func displayLanguage(language string) string {
	switch language {
	case "core":
		return "Core"
	case "java":
		return "Java"
	case "node":
		return "Node.js"
	case "python":
		return "Python"
	case "go":
		return "Go"
	case "dotnet":
		return ".NET"
	case "rust":
		return "Rust"
	case "cc":
		return "C/C++"
	default:
		return language
	}
}

var primaryGoUnderscoreRe = regexp.MustCompile(`^go_[0-9_]+$`)
var primaryPythonRe = regexp.MustCompile(`^python[0-9.]*$`)

func isPrimaryRuntimePackage(meta targetMeta, packageName string) bool {
	pkg := strings.ToLower(packageName)
	switch meta.language {
	case "python":
		return pkg == "python" || primaryPythonRe.MatchString(pkg)
	case "java":
		return strings.Contains(pkg, "jdk") || strings.Contains(pkg, "jre") || strings.Contains(pkg, "openjdk") || strings.Contains(pkg, "zulu")
	case "node":
		return pkg == "node" || pkg == "nodejs" || strings.HasPrefix(pkg, "nodejs")
	case "go":
		return pkg == "go" || strings.HasPrefix(pkg, "go-") || primaryGoUnderscoreRe.MatchString(pkg)
	case "dotnet":
		return strings.Contains(pkg, "dotnet") || strings.Contains(pkg, "aspnetcore")
	case "rust":
		return pkg == "rustc" || pkg == "cargo"
	case "cc":
		return pkg == "gcc" || pkg == "clang"
	default:
		return false
	}
}

func classifyLayer(meta targetMeta, name, sourceInfo string, purl *string) string {
	if purl != nil && (strings.HasPrefix(*purl, "pkg:nix") || strings.Contains(*purl, "outputhash=")) {
		return "runtime"
	}
	if strings.Contains(sourceInfo, "/nix/store/") {
		return "runtime"
	}
	if strings.HasPrefix(name, "nix") || strings.Contains(name, "clearcutt") {
		return "runtime"
	}
	if isPrimaryRuntimePackage(meta, name) {
		return "runtime"
	}
	return "base"
}

func remediationMetadata(layer, severityKey string, fixedIn *string) catalog.RemediationInfo {
	highPriority := severityKey == "critical" || severityKey == "high"
	if layer != "runtime" {
		return catalog.RemediationInfo{
			Status:  "deferred",
			Reason:  "base_layer",
			Summary: "This comes from the underlying base image, so ClearCutt lists it but cannot update it from the runtime layer.",
		}
	}
	if !highPriority {
		return catalog.RemediationInfo{
			Status:  "deferred",
			Reason:  "below_priority_threshold",
			Summary: "This is below the release-blocking severity threshold, so it is listed for awareness.",
		}
	}
	if fixedIn == nil {
		return catalog.RemediationInfo{
			Status:  "deferred",
			Reason:  "no_fixed_version",
			Summary: "No safe fixed version is currently listed for this package. We keep it visible until an upstream fix is available.",
		}
	}
	return catalog.RemediationInfo{
		Status:  "eligible",
		Reason:  "fix_available",
		Summary: "A safe fixed version is available for a package ClearCutt adds to this image.",
	}
}

func inclusionMetadata(meta targetMeta, name, layer string) catalog.InclusionInfo {
	pkg := strings.ToLower(name)
	lang := displayLanguage(meta.language)
	version := ""
	if meta.version != "" {
		version = " " + meta.version
	}
	variant := fmt.Sprintf("%s%s %s", lang, version, meta.tier)

	if layer == "base" {
		return catalog.InclusionInfo{
			Category: "base_image",
			Summary:  "Inherited from the enterprise base image underneath the ClearCutt runtime layer.",
		}
	}
	if isPrimaryRuntimePackage(meta, pkg) {
		return catalog.InclusionInfo{
			Category: "primary_runtime",
			Summary:  fmt.Sprintf("Primary %s%s runtime required by this image variant.", lang, version),
		}
	}
	if pkg == "cacert" || pkg == "nss-cacert" {
		return catalog.InclusionInfo{
			Category: "trust_store",
			Summary:  "TLS CA trust store required by networked runtimes.",
		}
	}
	if meta.tier == "slim" && (pkg == "bash" || pkg == "bash-interactive" || pkg == "busybox") {
		return catalog.InclusionInfo{
			Category: "tier_tooling",
			Summary:  "Intentional slim-tier diagnostic utility. Distroless variants remove shells and core utilities.",
		}
	}
	if meta.language == "java" && pkg == "cups" {
		return catalog.InclusionInfo{
			Category: "java_compatibility",
			Summary:  "Pulled by the selected Java runtime closure for printing/AWT compatibility. Candidate for a headless-minimal profile.",
		}
	}
	if meta.language == "java" && pkg == "libtiff" {
		return catalog.InclusionInfo{
			Category: "java_compatibility",
			Summary:  "Pulled by the selected Java runtime closure for image/font stack compatibility. Candidate for a headless-minimal profile.",
		}
	}
	switch pkg {
	case "glibc", "gcc-unwrapped", "libgcc", "zlib", "bzip2", "xz", "openssl":
		return catalog.InclusionInfo{
			Category: "runtime_dependency",
			Summary:  fmt.Sprintf("Runtime library required by the selected %s closure.", variant),
		}
	}
	return catalog.InclusionInfo{
		Category: "transitive_runtime",
		Summary:  fmt.Sprintf("Transitive dependency of the selected %s Nix runtime closure.", variant),
	}
}

func pickCvss(arr []grypeCvss) (score *float64, version *string, vector *string) {
	if len(arr) == 0 {
		return nil, nil, nil
	}
	candidates := arr
	for _, c := range arr {
		if strings.ToLower(c.Type) == "primary" {
			candidates = []grypeCvss{c}
			break
		}
	}
	var best *grypeCvss
	for i := range candidates {
		c := candidates[i]
		if c.Metrics.BaseScore == nil {
			continue
		}
		if best == nil || *c.Metrics.BaseScore > *best.Metrics.BaseScore {
			cp := c
			best = &cp
		}
	}
	if best == nil {
		return nil, nil, nil
	}
	return best.Metrics.BaseScore, strOrNil(best.Version), strOrNil(best.Vector)
}

func pickEpss(arr []grypeEpss) (score *float64, percentile *float64) {
	if len(arr) == 0 {
		return nil, nil
	}
	sorted := make([]grypeEpss, len(arr))
	copy(sorted, arr)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Date > sorted[j].Date
	})
	e := sorted[0]
	if e.Epss == nil {
		return nil, nil
	}
	return e.Epss, e.Percentile
}

func parsePurl(raw json.RawMessage) *string {
	if len(raw) == 0 {
		return nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return &asString
	}
	var asArray []string
	if err := json.Unmarshal(raw, &asArray); err == nil {
		if len(asArray) == 0 {
			return nil
		}
		return &asArray[0]
	}
	return nil
}

var scanSevKeys = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "negligible": true}
var scanSevOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}

type NormalizeOptions struct {
	KEVCatalog        *KEVCatalog
	KEVStatus         string
	KEVCatalogVersion *string
}

// NormalizeGrype transforms a grype result into the catalog finding model for the
// given target, classifying each finding's layer, inclusion, and remediation and
// sorting findings by severity, CVSS, package, then ID.
func NormalizeGrype(result GrypeResult, scannedAt, scanner string, dbBuiltAt *string, meta targetMeta) Report {
	return NormalizeGrypeWithOptions(result, scannedAt, scanner, dbBuiltAt, meta, NormalizeOptions{})
}

func NormalizeGrypeWithOptions(result GrypeResult, scannedAt, scanner string, dbBuiltAt *string, meta targetMeta, opts NormalizeOptions) Report {
	kevStatus := opts.KEVStatus
	if kevStatus == "" {
		kevStatus = "unavailable"
	}
	counts := catalog.SeverityCounts{}
	findings := make([]finding, 0, len(result.Matches))
	for _, m := range result.Matches {
		v := m.Vulnerability
		a := m.Artifact
		sev := strings.ToLower(v.Severity)
		if sev == "" {
			sev = "unknown"
		}
		sevKey := "unknown"
		if scanSevKeys[sev] {
			sevKey = sev
		}
		switch sevKey {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		case "negligible":
			counts.Negligible++
		default:
			counts.Unknown++
		}

		purl := parsePurl(a.Purl)
		var fixedIn *string
		if len(v.Fix.Versions) > 0 {
			joined := strings.Join(v.Fix.Versions, ", ")
			fixedIn = &joined
		}
		fixState := v.Fix.State
		if fixState == "" {
			fixState = "unknown"
		}
		layer := classifyLayer(meta, a.Name, a.SourceInfo, purl)
		cvssScore, cvssVersion, cvssVector := pickCvss(v.Cvss)
		epssScore, epssPercentile := pickEpss(v.Epss)

		id := v.ID
		if id == "" {
			id = "UNKNOWN"
		}
		severity := v.Severity
		if severity == "" {
			severity = "Unknown"
		}

		findings = append(findings, finding{
			ID:             id,
			Severity:       severity,
			PackageName:    a.Name,
			PackageVersion: a.Version,
			Purl:           purl,
			Layer:          layer,
			FixedIn:        fixedIn,
			FixState:       fixState,
			Remediation:    remediationMetadata(layer, sevKey, fixedIn),
			Inclusion:      inclusionMetadata(meta, a.Name, layer),
			DataSource:     strOrNil(v.DataSource),
			Namespace:      strOrNil(v.Namespace),
			Description:    strOrNil(v.Description),
			CvssScore:      cvssScore,
			CvssVersion:    cvssVersion,
			CvssVector:     cvssVector,
			EpssScore:      epssScore,
			EpssPercentile: epssPercentile,
			RiskScore:      v.Risk,
			KEV:            opts.KEVCatalog.Info(id),
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		sa, ok := scanSevOrder[strings.ToLower(a.Severity)]
		if !ok {
			sa = 99
		}
		sb, ok := scanSevOrder[strings.ToLower(b.Severity)]
		if !ok {
			sb = 99
		}
		if sa != sb {
			return sa < sb
		}
		csa := -1.0
		if a.CvssScore != nil {
			csa = *a.CvssScore
		}
		csb := -1.0
		if b.CvssScore != nil {
			csb = *b.CvssScore
		}
		if csa != csb {
			return csa > csb
		}
		if a.PackageName != b.PackageName {
			return a.PackageName < b.PackageName
		}
		return a.ID < b.ID
	})

	return Report{
		ScannedAt:         scannedAt,
		Scanner:           scanner,
		DBBuiltAt:         dbBuiltAt,
		KEVStatus:         kevStatus,
		KEVCatalogVersion: opts.KEVCatalogVersion,
		CountsBySeverity:  counts,
		Findings:          findings,
	}
}

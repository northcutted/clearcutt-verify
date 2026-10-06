package estateverify

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/northcutted/clearcutt/internal/report"
)

// grypeResult is the part of grype's JSON output the report uses.
type grypeResult struct {
	Matches []grypeMatch `json:"matches"`
	// IgnoredMatches are matches a VEX statement or ignore rule suppressed.
	IgnoredMatches []grypeMatch `json:"ignoredMatches"`
	Descriptor     struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Fix      struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"artifact"`
}

// vulnScan is one platform's vulnerability attestation, read.
type vulnScan struct {
	Scanner   string
	ScannedAt string
	Result    grypeResult
}

// readVulnPredicate reads a cosign vuln/v1 predicate holding grype output.
func readVulnPredicate(pred json.RawMessage) (vulnScan, bool) {
	var p struct {
		Scanner struct {
			URI     string          `json:"uri"`
			Version string          `json:"version"`
			Result  json.RawMessage `json:"result"`
		} `json:"scanner"`
		Metadata struct {
			ScanFinishedOn string `json:"scanFinishedOn"`
			ScanStartedOn  string `json:"scanStartedOn"`
		} `json:"metadata"`
	}
	if json.Unmarshal(pred, &p) != nil || len(p.Scanner.Result) == 0 {
		return vulnScan{}, false
	}
	var r grypeResult
	if json.Unmarshal(p.Scanner.Result, &r) != nil {
		return vulnScan{}, false
	}
	name := r.Descriptor.Name
	if name == "" {
		name = scannerName(p.Scanner.URI)
	}
	version := firstNonEmpty(r.Descriptor.Version, p.Scanner.Version)
	return vulnScan{
		Scanner:   strings.TrimSpace(name + " " + version),
		ScannedAt: firstNonEmpty(p.Metadata.ScanFinishedOn, p.Metadata.ScanStartedOn),
		Result:    r,
	}, true
}

func scannerName(uri string) string {
	// pkg:github/anchore/grype@0.118.0 → grype
	uri = strings.TrimPrefix(uri, "pkg:github/")
	uri, _, _ = strings.Cut(uri, "@")
	return uri[strings.LastIndex(uri, "/")+1:]
}

// mergeVulnerabilities combines per-platform scans into the image's
// findings, counting each finding once however many platforms have it.
func mergeVulnerabilities(scans map[string]vulnScan) *report.Vulnerabilities {
	if len(scans) == 0 {
		return nil
	}
	out := &report.Vulnerabilities{Source: "attestation", Findings: []report.Finding{}}
	byKey := map[string]*report.Finding{}
	var keys []string
	add := func(platform string, m grypeMatch, suppressed bool) {
		key := m.Vulnerability.ID + "|" + m.Artifact.Name + "|" + m.Artifact.Version
		f, ok := byKey[key]
		if !ok {
			f = &report.Finding{
				ID: m.Vulnerability.ID, Severity: normalizeSeverity(m.Vulnerability.Severity),
				Package: m.Artifact.Name, Version: m.Artifact.Version,
				FixedIn: m.Vulnerability.Fix.Versions, Suppressed: suppressed,
			}
			byKey[key] = f
			keys = append(keys, key)
		}
		f.Platforms = appendUnique(f.Platforms, platform)
		f.Suppressed = f.Suppressed && suppressed
	}
	platforms := make([]string, 0, len(scans))
	for p := range scans {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, p := range platforms {
		s := scans[p]
		if out.ScannedAt == "" || s.ScannedAt > out.ScannedAt {
			out.ScannedAt = s.ScannedAt
		}
		out.Scanner = firstNonEmpty(out.Scanner, s.Scanner)
		for _, m := range s.Result.Matches {
			add(p, m, false)
		}
		for _, m := range s.Result.IgnoredMatches {
			add(p, m, true)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := byKey[keys[i]], byKey[keys[j]]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		f := byKey[k]
		sort.Strings(f.Platforms)
		out.Findings = append(out.Findings, *f)
		if f.Suppressed {
			continue
		}
		addSeverity(&out.Counts, f.Severity)
		if len(f.FixedIn) > 0 {
			addSeverity(&out.Fixable, f.Severity)
		}
	}
	return out
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low", "negligible":
		return strings.ToLower(s)
	}
	return "unknown"
}

// SeverityRank orders severities; unknown ranks lowest.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	}
	return 0
}

func addSeverity(c *report.SeverityCounts, s string) {
	switch s {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	case "negligible":
		c.Negligible++
	default:
		c.Unknown++
	}
}

// pkg is one package version read from an SBOM.
type pkg struct {
	Name, Version, Type, PURL string
}

// readSBOM lists the packages in a CycloneDX or SPDX document (the
// attestation predicate, or a raw document).
func readSBOM(doc json.RawMessage) ([]pkg, bool) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if json.Unmarshal(doc, &probe) != nil {
		return nil, false
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		var bom struct {
			Components []struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Version string `json:"version"`
				PURL    string `json:"purl"`
			} `json:"components"`
		}
		if json.Unmarshal(doc, &bom) != nil {
			return nil, false
		}
		var out []pkg
		for _, c := range bom.Components {
			// Files, the image itself, and other non-package entries have no purl.
			if c.PURL == "" || c.Type == "file" || c.Type == "container" {
				continue
			}
			out = append(out, pkg{Name: c.Name, Version: c.Version, Type: purlType(c.PURL), PURL: c.PURL})
		}
		return out, true
	case probe.SPDXVersion != "":
		var spdx struct {
			Packages []struct {
				Name         string `json:"name"`
				VersionInfo  string `json:"versionInfo"`
				ExternalRefs []struct {
					ReferenceType    string `json:"referenceType"`
					ReferenceLocator string `json:"referenceLocator"`
				} `json:"externalRefs"`
			} `json:"packages"`
		}
		if json.Unmarshal(doc, &spdx) != nil {
			return nil, false
		}
		var out []pkg
		for _, p := range spdx.Packages {
			for _, ref := range p.ExternalRefs {
				if ref.ReferenceType == "purl" && strings.HasPrefix(ref.ReferenceLocator, "pkg:") {
					out = append(out, pkg{Name: p.Name, Version: p.VersionInfo, Type: purlType(ref.ReferenceLocator), PURL: ref.ReferenceLocator})
					break
				}
			}
		}
		return out, true
	}
	return nil, false
}

// purlType returns a purl's type (pkg:apk/wolfi/x@1 → apk).
func purlType(purl string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	return t
}

// pinnedImage is an image reference and the digest a lock pins it at.
type pinnedImage struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// readRecipe reads a clearcutt-factory recipe predicate: the factory
// details, and the base its lock pins.
func readRecipe(pred json.RawMessage) (*report.Factory, *pinnedImage, bool) {
	var r struct {
		Factory struct {
			Version string `json:"version"`
		} `json:"factory"`
		Build struct {
			SourceDateEpoch int64 `json:"sourceDateEpoch"`
		} `json:"build"`
		Manifest string `json:"manifest"`
		Lock     string `json:"lock"`
	}
	if json.Unmarshal(pred, &r) != nil || r.Manifest == "" {
		return nil, nil, false
	}
	var m struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Stack *struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"stack"`
	}
	_ = yaml.Unmarshal([]byte(r.Manifest), &m)
	f := &report.Factory{Kind: m.Kind, Name: m.Metadata.Name, Version: r.Factory.Version, SourceDateEpoch: r.Build.SourceDateEpoch}
	if m.Stack != nil {
		f.Stack = m.Stack.Metadata.Name
	}
	var base *pinnedImage
	var l struct {
		Builder  map[string]json.RawMessage `json:"builder"`
		Base     json.RawMessage            `json:"base"`
		Packages struct {
			Platforms map[string][]json.RawMessage `json:"platforms"`
		} `json:"packages"`
		Tools []struct {
			Image json.RawMessage `json:"image"`
		} `json:"tools"`
		App *struct {
			Build json.RawMessage `json:"build"`
		} `json:"app"`
	}
	// The base is read on its own, so a lock whose other sections changed
	// shape still names its base.
	var pin struct {
		Base pinnedImage `json:"base"`
	}
	if yaml.Unmarshal([]byte(r.Lock), &pin) == nil && pin.Base.Ref != "" && strings.HasPrefix(pin.Base.Digest, "sha256:") {
		base = &pin.Base
	}
	if yaml.Unmarshal([]byte(r.Lock), &l) == nil {
		in := &report.FactoryInputs{Tools: len(l.Tools), Images: len(l.Builder)}
		if len(l.Base) > 0 {
			in.Images++
		}
		if l.App != nil {
			in.Images++
		}
		for _, t := range l.Tools {
			if len(t.Image) > 0 && string(t.Image) != "null" {
				in.Images++
			}
		}
		for _, pkgs := range l.Packages.Platforms {
			in.Packages = max(in.Packages, len(pkgs))
		}
		f.Inputs = in
	}
	if f.Kind == "" || f.Name == "" {
		return nil, nil, false
	}
	return f, base, true
}

// readRebase reads a clearcutt-factory rebase record.
func readRebase(pred json.RawMessage) (*report.Factory, bool) {
	var r struct {
		Factory struct {
			Version string `json:"version"`
		} `json:"factory"`
		Image string `json:"image"`
	}
	if json.Unmarshal(pred, &r) != nil || r.Image == "" {
		return nil, false
	}
	return &report.Factory{Version: r.Factory.Version, RebasedFrom: r.Image}, true
}

// readProvenanceSource reads the source repository and revision from SLSA
// provenance (v1 GitHub Actions builds, and v0.2).
func readProvenanceSource(pred json.RawMessage) (*report.SourceRef, bool) {
	var p struct {
		BuildDefinition struct {
			ExternalParameters struct {
				Workflow struct {
					Repository string `json:"repository"`
					Ref        string `json:"ref"`
				} `json:"workflow"`
			} `json:"externalParameters"`
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		Invocation struct {
			ConfigSource struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"configSource"`
		} `json:"invocation"`
	}
	if json.Unmarshal(pred, &p) != nil {
		return nil, false
	}
	s := &report.SourceRef{Basis: "provenance", URL: p.BuildDefinition.ExternalParameters.Workflow.Repository}
	for _, d := range p.BuildDefinition.ResolvedDependencies {
		if c := d.Digest["gitCommit"]; c != "" {
			s.Revision = c
			if s.URL == "" {
				s.URL = gitURL(d.URI)
			}
			break
		}
	}
	if s.URL == "" && p.Invocation.ConfigSource.URI != "" {
		s.URL = gitURL(p.Invocation.ConfigSource.URI)
		s.Revision = p.Invocation.ConfigSource.Digest["sha1"]
	}
	if s.URL == "" {
		return nil, false
	}
	return s, true
}

// gitURL turns git+https://github.com/o/r@refs/heads/main into
// https://github.com/o/r.
func gitURL(uri string) string {
	uri = strings.TrimPrefix(uri, "git+")
	uri, _, _ = strings.Cut(uri, "@")
	if u, err := url.Parse(uri); err == nil && u.Scheme != "" {
		return strings.TrimSuffix(uri, ".git")
	}
	return ""
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

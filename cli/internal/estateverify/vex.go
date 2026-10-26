package estateverify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// OpenVEX documents a policy names (vex:) are applied to this run's rescans.
// grype applies VEX itself, but when it scans an SBOM (not an image) it knows
// nothing about the image, so a statement whose product is the image
// (pkg:oci/…) is never applied, and a statement whose product is a package
// purl applies to every image scanned. So the scoping is done here, before
// grype sees anything: for each image, the statements about that image are
// selected and rewritten as package-scoped statements, and the ones about a
// package pass through to every image, as grype would apply them.
//
// The scoping rule, which clearcutt-factory applies the same way:
//
//   - A product that is an image purl (pkg:oci/… or pkg:docker/…) applies to
//     the image when its version (percent-decoded) is the image's digest or
//     one of its platform images' digests (then to that platform only), or,
//     with no version, when its repository_url qualifier is the image's
//     repository (and its tag qualifier, if any, one of the image's tags).
//   - A product that isn't a purl applies when it is the image's repository,
//     repository:tag, repository@digest, or a bare digest the image or one of
//     its platform images has.
//   - A product that is any other purl is a package: it applies to every image,
//     to the packages grype matches it to.
//   - A statement about an image applies to the packages its subcomponents
//     name; with no subcomponents, to every package in the image's SBOM for
//     that vulnerability.
//
// A bare image purl with neither a version nor a repository_url
// (pkg:oci/app) names no image and applies nowhere; the run warns about it.

// VEXDocument is an OpenVEX document, read.
type VEXDocument struct {
	// File is the path the policy named, as written; Path where it was read.
	File, Path string
	ID         string
	Author     string
	Statements []VEXStatement
}

// VEXStatement is one OpenVEX statement.
type VEXStatement struct {
	Vulnerability vexVulnerability `json:"vulnerability"`
	Products      []vexProduct     `json:"products"`
	Status        string           `json:"status"`
	Justification string           `json:"justification,omitempty"`
	// Other fields OpenVEX allows are kept as they are for grype.
	Timestamp       string `json:"timestamp,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
}

type vexVulnerability struct {
	ID      string   `json:"@id,omitempty"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// names lists the vulnerability's name and aliases.
func (v vexVulnerability) names() []string {
	return append([]string{v.Name}, v.Aliases...)
}

type vexProduct struct {
	ID            string         `json:"@id"`
	Identifiers   map[string]any `json:"identifiers,omitempty"`
	Subcomponents []vexComponent `json:"subcomponents,omitempty"`
}

type vexComponent struct {
	ID          string         `json:"@id"`
	Identifiers map[string]any `json:"identifiers,omitempty"`
}

// UnmarshalJSON reads a product as an object, or as the plain string older
// documents use.
func (p *vexProduct) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		p.ID = s
		return nil
	}
	type plain vexProduct
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = vexProduct(v)
	if p.ID == "" {
		if purl, ok := p.Identifiers["purl"].(string); ok {
			p.ID = purl
		}
	}
	return nil
}

func (c *vexComponent) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		c.ID = s
		return nil
	}
	type plain vexComponent
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*c = vexComponent(v)
	if c.ID == "" {
		if purl, ok := c.Identifiers["purl"].(string); ok {
			c.ID = purl
		}
	}
	return nil
}

// ReadVEX reads the OpenVEX documents a policy names, each relative to dir
// (the policy file's directory), and refuses anything that isn't one.
func ReadVEX(dir string, files []string) ([]VEXDocument, error) {
	var out []VEXDocument
	for _, f := range files {
		p := f
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, f)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("vex %s: %w", f, err)
		}
		var doc struct {
			Context    string         `json:"@context"`
			ID         string         `json:"@id"`
			Author     string         `json:"author"`
			Statements []VEXStatement `json:"statements"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("vex %s: not an OpenVEX document: %w", f, err)
		}
		if !strings.HasPrefix(doc.Context, "https://openvex.dev/ns") {
			return nil, fmt.Errorf("vex %s: not an OpenVEX document (@context %q)", f, doc.Context)
		}
		for i, st := range doc.Statements {
			switch {
			case st.Vulnerability.Name == "":
				return nil, fmt.Errorf("vex %s: statements[%d] names no vulnerability", f, i)
			case len(st.Products) == 0:
				return nil, fmt.Errorf("vex %s: statements[%d] (%s) names no product", f, i, st.Vulnerability.Name)
			case st.Status == "":
				return nil, fmt.Errorf("vex %s: statements[%d] (%s) has no status", f, i, st.Vulnerability.Name)
			}
			for j, p := range st.Products {
				if p.ID == "" {
					return nil, fmt.Errorf("vex %s: statements[%d] (%s) products[%d] has no @id", f, i, st.Vulnerability.Name, j)
				}
			}
		}
		out = append(out, VEXDocument{File: f, Path: p, ID: doc.ID, Author: doc.Author, Statements: doc.Statements})
	}
	return out, nil
}

// Described lists the documents as the report records them.
func describeVEX(docs []VEXDocument) []report.VEXDocument {
	var out []report.VEXDocument
	for _, d := range docs {
		out = append(out, report.VEXDocument{File: d.File, ID: d.ID, Author: d.Author, Statements: len(d.Statements)})
	}
	return out
}

// imageIdentity is what a VEX product can name about an image.
type imageIdentity struct {
	repository string
	tags       []string
	digest     string // the index, or the single manifest
	// platform is the platform image being scanned and platformDigest its
	// digest; a product naming it applies to this scan only.
	platform, platformDigest string
}

// scopedStatement is a statement rewritten for one scan, with the statement
// it came from for the report.
type scopedStatement struct {
	VEXStatement
	// origin is the product as written in the policy's document, and the
	// document, for report.Suppression.
	origin report.Suppression
	// anyPackage says the statement applies to every package (an image
	// product with no subcomponents).
	anyPackage bool
}

// scopeVEX selects and rewrites the statements that apply to one scan: the
// image img's platform image, whose verified SBOM lists purls. It returns the
// OpenVEX document to hand grype (nil when no statement applies) and the
// statements in it, for attributing what grype suppressed.
func scopeVEX(docs []VEXDocument, img imageIdentity, purls []string) ([]byte, []scopedStatement) {
	var scoped []scopedStatement
	for _, d := range docs {
		for _, st := range d.Statements {
			for _, p := range st.Products {
				origin := report.Suppression{Source: "vex", File: d.File, Document: d.ID, Product: p.ID, Status: st.Status, Justification: st.Justification}
				switch kind := productKind(p.ID); {
				case kind == productPackage:
					s := scopedStatement{VEXStatement: st, origin: origin}
					s.Products = []vexProduct{{ID: p.ID}}
					scoped = append(scoped, s)
				case kind == productImage && productNamesImage(p.ID, img):
					s := scopedStatement{VEXStatement: st, origin: origin}
					s.Products = nil
					for _, c := range p.Subcomponents {
						if c.ID != "" {
							s.Products = append(s.Products, vexProduct{ID: c.ID})
						}
					}
					if len(p.Subcomponents) == 0 {
						s.anyPackage = true
						for _, purl := range purls {
							s.Products = append(s.Products, vexProduct{ID: purl})
						}
					}
					if len(s.Products) > 0 {
						scoped = append(scoped, s)
					}
				}
			}
		}
	}
	if len(scoped) == 0 {
		return nil, nil
	}
	statements := make([]VEXStatement, 0, len(scoped))
	for _, s := range scoped {
		statements = append(statements, s.VEXStatement)
	}
	doc, _ := json.Marshal(map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "https://clearcutt.dev/vex/rescan/" + strings.TrimPrefix(firstNonEmpty(img.platformDigest, img.digest), "sha256:"),
		"author":     "clearcutt-verify (statements scoped from the policy's OpenVEX documents)",
		"timestamp":  "1970-01-01T00:00:00Z",
		"version":    1,
		"statements": statements,
	})
	return doc, scoped
}

// Kinds of VEX product.
const (
	productImage   = "image"
	productPackage = "package"
	productOther   = "other"
)

// productKind says what a product @id names: an image (a pkg:oci or
// pkg:docker purl, or a reference that isn't a purl), or a package (any other
// purl).
func productKind(id string) string {
	id = strings.TrimSpace(id)
	switch {
	case id == "":
		return productOther
	case strings.HasPrefix(id, "pkg:oci/"), strings.HasPrefix(id, "pkg:docker/"):
		return productImage
	case strings.HasPrefix(id, "pkg:"):
		return productPackage
	}
	return productImage
}

// productNamesImage reports whether an image product names img (or the
// platform image being scanned).
func productNamesImage(id string, img imageIdentity) bool {
	id = strings.TrimSpace(id)
	digests := []string{img.digest, img.platformDigest}
	isDigest := func(d string) bool {
		d = strings.ToLower(strings.TrimSpace(d))
		for _, x := range digests {
			if x != "" && d == strings.ToLower(x) {
				return true
			}
		}
		return false
	}
	repo := normalizeRepo(img.repository)
	sameRepo := func(r string) bool {
		r = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(r), "https://"), "oci://"), "/")
		return r != "" && normalizeRepo(qualify(r)) == repo
	}
	if !strings.HasPrefix(id, "pkg:") {
		// A reference: repository, repository:tag, repository@digest, or a digest.
		if isDigest(id) {
			return true
		}
		ref, digest, hasDigest := strings.Cut(id, "@")
		if hasDigest {
			return sameRepo(ref) && isDigest(digest)
		}
		if sameRepo(id) {
			return true
		}
		if tag := tagOf(id); tag != "" {
			return sameRepo(repoOf(id)) && contains(img.tags, tag)
		}
		return false
	}
	// An image purl: pkg:oci/NAME[@VERSION][?QUALIFIERS].
	rest := id[strings.Index(id, "/")+1:]
	rest, query, _ := strings.Cut(rest, "?")
	_, version, hasVersion := strings.Cut(rest, "@")
	q, _ := url.ParseQuery(query)
	if hasVersion {
		if v, err := url.PathUnescape(version); err == nil {
			version = v
		}
		return isDigest(version)
	}
	repoURL := q.Get("repository_url")
	if repoURL == "" || !sameRepo(repoURL) {
		return false
	}
	if tag := q.Get("tag"); tag != "" && !contains(img.tags, tag) {
		return false
	}
	return true
}

// unusedVEX lists the image products in the policy's documents that named
// none of the estate's images, so a statement that applies nowhere (a typo,
// or an image no longer in the estate) is seen, not silently dropped.
func unusedVEX(docs []VEXDocument, images []report.Image) []string {
	var out []string
	for _, d := range docs {
		for i, st := range d.Statements {
			for _, p := range st.Products {
				if productKind(p.ID) != productImage {
					continue
				}
				used := false
				for _, img := range images {
					id := imageIdentity{repository: img.Repository, tags: img.Tags, digest: img.Digest}
					if productNamesImage(p.ID, id) {
						used = true
						break
					}
					for _, pl := range img.Platforms {
						id.platform, id.platformDigest = pl.Platform, pl.Digest
						if productNamesImage(p.ID, id) {
							used = true
							break
						}
					}
					if used {
						break
					}
				}
				if !used {
					out = append(out, fmt.Sprintf("VEX statement %s[%d] (%s) names product %q, which is none of the estate's images; it was applied to nothing", d.File, i, st.Vulnerability.Name, p.ID))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// attributeSuppressions names the statement that suppressed each of grype's
// ignored matches: the one whose vulnerability is the match's (or an alias
// of it) and whose product is the match's package, as grype matches purls
// (type, namespace, and name equal; the version, when the product has one;
// each qualifier the product has). Matches grype ignored by its own rules
// are attributed to the scanner.
func attributeSuppressions(scoped []scopedStatement, m grypeMatch) *report.Suppression {
	ids := []string{m.Vulnerability.ID}
	for _, r := range m.RelatedVulnerabilities {
		ids = append(ids, r.ID)
	}
	vex := false
	for _, rule := range m.AppliedIgnoreRules {
		if rule.Namespace == "vex" {
			vex = true
		}
	}
	if !vex {
		kinds := []string{}
		for _, rule := range m.AppliedIgnoreRules {
			kinds = appendUnique(kinds, firstNonEmpty(rule.Namespace, rule.MatchType, "ignore rule"))
		}
		return &report.Suppression{Source: "scanner", Justification: "ignored by grype's own rules (" + strings.Join(kinds, ", ") + ")"}
	}
	for _, s := range scoped {
		if !namesAny(s.Vulnerability.names(), ids) {
			continue
		}
		if s.anyPackage {
			return &s.origin
		}
		for _, p := range s.Products {
			if purlMatches(p.ID, m.Artifact.PURL) {
				return &s.origin
			}
		}
	}
	return &report.Suppression{Source: "vex", Justification: "a VEX statement grype applied, which couldn't be matched to one the policy named"}
}

func namesAny(names, ids []string) bool {
	for _, n := range names {
		for _, id := range ids {
			if strings.EqualFold(strings.TrimSpace(n), strings.TrimSpace(id)) {
				return true
			}
		}
	}
	return false
}

// purlMatches reports whether a VEX product purl names a package purl the
// way grype matches them: the type, namespace, and name are equal; the
// version, when the product has one; and every qualifier the product has.
func purlMatches(product, artifact string) bool {
	pName, pVersion, pQ := splitPURL(product)
	aName, aVersion, aQ := splitPURL(artifact)
	if pName == "" || pName != aName {
		return false
	}
	if pVersion != "" && pVersion != aVersion {
		return false
	}
	for k, v := range pQ {
		if aQ[k] != v {
			return false
		}
	}
	return true
}

// splitPURL splits pkg:type/namespace/name@version?qualifiers#subpath into
// the type/namespace/name path, the version, and the qualifiers.
func splitPURL(purl string) (name, version string, qualifiers map[string]string) {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", nil
	}
	purl, _, _ = strings.Cut(purl, "#")
	purl, query, _ := strings.Cut(purl, "?")
	name, version, _ = strings.Cut(strings.TrimPrefix(purl, "pkg:"), "@")
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	name = strings.ToLower(path.Clean("/" + name))[1:]
	qualifiers = map[string]string{}
	for k, vs := range mustQuery(query) {
		if len(vs) > 0 {
			qualifiers[strings.ToLower(k)] = vs[0]
		}
	}
	return name, version, qualifiers
}

func mustQuery(q string) url.Values {
	v, err := url.ParseQuery(q)
	if err != nil {
		return url.Values{}
	}
	return v
}

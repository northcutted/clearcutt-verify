// Package report defines the estate report: everything one clearcutt-verify
// run found and proved about an image estate, in one document that a portal
// (clearcutt-portal) or any other consumer can read without talking to a
// registry. It is a public contract: the JSON Schema in contract/ is
// generated from these types, and contract/README.md explains the meaning
// of every status.
//
// The report never overclaims. Evidence is "verified" only when it was found
// and checked against a trusted signer; "present" when found but not checked;
// "unknown" when it could not be looked for. Unknown is never reported as a
// pass, and never as zero.
package report

// Contract identifiers.
const (
	APIVersion  = "clearcutt.dev/v1"
	KindReport  = "EstateReport"
	KindHistory = "EstateHistory"

	// ReportFile and HistoryFile are the file names of a report bundle: a
	// directory a portal is pointed at.
	ReportFile  = "estate-report.json"
	HistoryFile = "estate-history.json"
)

// Report is one verification run over an image estate.
type Report struct {
	// APIVersion is clearcutt.dev/v1.
	APIVersion string `json:"apiVersion"`
	// Kind is EstateReport.
	Kind     string   `json:"kind"`
	Metadata Metadata `json:"metadata"`
	// Policy is what images were held to in this run.
	Policy  Policy  `json:"policy"`
	Summary Summary `json:"summary"`
	// Images are the observed images, one per repository and digest.
	Images []Image `json:"images"`
	// Bases are the base-image repositories that images were found to be
	// built on, with their newest observed version.
	Bases []Base `json:"bases"`
	// Packages index which images ship which package versions. Only images
	// whose package set could be read appear here; the rest are counted in
	// summary.packages.unknown, so a package's absence is not proof that no
	// image ships it.
	Packages []PackageUse `json:"packages"`
	// Warnings are estate-wide problems the run hit.
	Warnings []string `json:"warnings"`
}

// Metadata identifies the estate and the run.
type Metadata struct {
	// Name identifies the estate, e.g. acme-production.
	Name string `json:"name"`
	// GeneratedAt is when the run finished (RFC 3339).
	GeneratedAt string    `json:"generatedAt"`
	Generator   Generator `json:"generator"`
	// Sources are the registries and repositories that were read.
	Sources []Source `json:"sources"`
}

// Generator is the tool that wrote the report.
type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Source is a registry namespace that was read.
type Source struct {
	// Registry is a host, e.g. ghcr.io.
	Registry string `json:"registry"`
	// Namespace is a repository path prefix, e.g. acme/images.
	Namespace string `json:"namespace,omitempty"`
	// Repositories are the repositories read, when they were named rather
	// than enumerated.
	Repositories []string `json:"repositories,omitempty"`
}

// Policy is what images were held to.
type Policy struct {
	// Required lists the evidence kinds an image needs, verified, to pass:
	// any of signature, sbom, vulnerabilityScan, provenance, recipe, tests.
	Required []string `json:"required" enum:"signature,sbom,vulnerabilityScan,provenance,recipe,tests"`
	// TrustedSigners are the identities whose signatures and attestations
	// count as verified. Empty means nothing can be verified, only present.
	TrustedSigners []Signer `json:"trustedSigners"`
	// FailOn fails images with vulnerabilities at or above this severity
	// (negligible, low, medium, high, critical); empty never fails.
	FailOn string `json:"failOn,omitempty" enum:"negligible,low,medium,high,critical"`
	// OnlyFixed counts only vulnerabilities that have a fix toward FailOn.
	OnlyFixed bool `json:"onlyFixed,omitempty"`
	// MaxDaysBehind fails images whose base is more than this many days
	// behind its newest version; 0 never fails.
	MaxDaysBehind int `json:"maxDaysBehind,omitempty"`
	// MaxScanAgeDays leaves images unverified whose vulnerability scan is
	// older than this many days at the time of the report (what was found
	// since is unknown); 0 accepts any age.
	MaxScanAgeDays int `json:"maxScanAgeDays,omitempty"`
	// Reproduce reports whether this run rebuilt images to check them.
	Reproduce bool `json:"reproduce"`
}

// Signer is a signing identity: a keyless certificate identity (exact or as
// a regular expression) with its OIDC issuer, or a public key. In the policy
// it is who is trusted; on evidence, who signed it, as the certificate says.
//
// The source fields matter for reusable GitHub workflows. Their certificate
// identity is the called workflow, which any repository can call, so a
// trusted signer for one should say which calling repositories it accepts.
type Signer struct {
	Identity       string `json:"identity,omitempty"`
	IdentityRegexp string `json:"identityRegexp,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	// Key names a public key (a file name or KMS URI), never key material.
	Key string `json:"key,omitempty"`
	// SourceRepository is the repository whose workflow run signed, e.g.
	// https://github.com/acme/billing (the certificate's Source Repository
	// URI). In the policy, signatures must come from runs in it.
	SourceRepository string `json:"sourceRepository,omitempty"`
	// SourceRepositoryOwner, in the policy, accepts runs in any of the
	// owner's repositories, e.g. https://github.com/acme.
	SourceRepositoryOwner string `json:"sourceRepositoryOwner,omitempty"`
	// SourceRef is the ref the run was on, e.g. refs/heads/main. In the
	// policy, signatures must come from runs on it.
	SourceRef string `json:"sourceRef,omitempty"`
	// SourceMatchesImage, in the policy, requires the run to be in the
	// repository the image names as its source
	// (org.opencontainers.image.source).
	SourceMatchesImage bool `json:"sourceMatchesImage,omitempty"`
}

// Summary holds the estate's headline numbers.
type Summary struct {
	// Images is the number of images in the report.
	Images int `json:"images"`
	// Verdicts counts images by verdict.status.
	Verdicts VerdictCounts `json:"verdicts"`
	// Evidence counts images by status for each evidence kind (keys:
	// signature, sbom, vulnerabilityScan, provenance, recipe, rebase, tests).
	Evidence map[string]StatusCounts `json:"evidence"`
	Bases    BaseSummary             `json:"bases"`
	// Vulnerabilities totals findings over scanned images.
	Vulnerabilities VulnerabilitySummary `json:"vulnerabilities"`
	Packages        PackageSummary       `json:"packages"`
	// Reproducibility counts images by reproducibility.status.
	Reproducibility ReproducibilityCounts `json:"reproducibility"`
}

// VerdictCounts counts images by verdict.
type VerdictCounts struct {
	Verified   int `json:"verified"`
	Failed     int `json:"failed"`
	Unverified int `json:"unverified"`
}

// StatusCounts counts images by evidence status.
type StatusCounts struct {
	Verified      int `json:"verified"`
	Present       int `json:"present"`
	Failed        int `json:"failed"`
	Missing       int `json:"missing"`
	Unknown       int `json:"unknown"`
	NotApplicable int `json:"notApplicable"`
}

// BaseSummary counts images by how their base is known and how current it is.
type BaseSummary struct {
	// Proven bases were established by layer digests.
	Proven int `json:"proven"`
	// Claimed bases rest on something the image's author wrote (labels,
	// annotations, build history).
	Claimed int `json:"claimed"`
	// Unresolved images have no base that could be determined (see each
	// image's unresolved reasons).
	Unresolved int `json:"unresolved"`
	// Roots have no parent: base images, or images built from scratch or by
	// composing layers (Nix, apko).
	Roots   int `json:"roots"`
	Current int `json:"current"`
	Stale   int `json:"stale"`
}

// VulnerabilitySummary totals findings over the images that were scanned.
type VulnerabilitySummary struct {
	Counts SeverityCounts `json:"counts"`
	// Fixable counts the findings that have a fix.
	Fixable SeverityCounts `json:"fixable"`
	// Scanned is how many images have vulnerability data; NotScanned how
	// many don't (their vulnerabilities are unknown, not zero).
	Scanned    int `json:"scanned"`
	NotScanned int `json:"notScanned"`
}

// SeverityCounts counts findings by severity.
type SeverityCounts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
}

// PackageSummary counts images by whether their package set is known.
type PackageSummary struct {
	Known   int `json:"known"`
	Unknown int `json:"unknown"`
}

// ReproducibilityCounts counts images by reproducibility.status.
type ReproducibilityCounts struct {
	Reproduced    int `json:"reproduced"`
	NotReproduced int `json:"notReproduced"`
	NotChecked    int `json:"notChecked"`
	NoRecipe      int `json:"noRecipe"`
}

// Image is one image: a repository at the digest its tags point at.
type Image struct {
	// ID is unique within the report and stable across runs for the same
	// repository, e.g. ghcr-io-acme-images-billing.
	ID string `json:"id"`
	// Repository is registry/path without tag or digest.
	Repository string `json:"repository"`
	// Tags point at Digest.
	Tags []string `json:"tags"`
	// Digest is what the tags point at: a multi-platform index or a single
	// image manifest.
	Digest string `json:"digest"`
	// Created is the image's creation time from its config (RFC 3339), if set.
	Created   string     `json:"created,omitempty"`
	Platforms []Platform `json:"platforms"`
	Builder   Builder    `json:"builder"`
	// Source is the code the image was built from, when it says.
	Source *SourceRef `json:"source,omitempty"`
	// Description is the image's org.opencontainers.image.description.
	Description string `json:"description,omitempty"`
	// Base is the image this one is built on; absent for roots and for
	// images whose base couldn't be determined.
	Base *BaseLink `json:"base,omitempty"`
	// Root says why the image has no parent, when it is a root.
	Root string `json:"root,omitempty"`
	// Unresolved gives the reasons no base was found, when it wasn't.
	Unresolved []string `json:"unresolved,omitempty"`
	Evidence   Evidence `json:"evidence"`
	// Vulnerabilities is absent when the image has no vulnerability data;
	// that means unknown, not clean.
	Vulnerabilities *Vulnerabilities `json:"vulnerabilities,omitempty"`
	Reproducibility Reproducibility  `json:"reproducibility"`
	// Factory is present for images built or rebased by clearcutt-factory.
	Factory *Factory `json:"factory,omitempty"`
	// Packages is how many package versions the image ships, when known.
	Packages *int     `json:"packages,omitempty"`
	Verdict  Verdict  `json:"verdict"`
	Warnings []string `json:"warnings"`
}

// Platform is one platform image of a multi-platform image.
type Platform struct {
	// Platform is os/arch[/variant], e.g. linux/arm64.
	Platform string `json:"platform"`
	Digest   string `json:"digest"`
	// Size is the total compressed size of the layers, in bytes.
	Size   int64 `json:"size"`
	Layers int   `json:"layers"`
}

// Builder is how the image was built, as far as its metadata tells.
type Builder struct {
	// Kind names the builder: clearcutt-factory, buildkit, docker,
	// buildpacks, nix, apko, debuerreotype, or unknown. Open: new builders
	// may appear, so show unknown values as they are.
	Kind string `json:"kind"`
	// Basis says what the classification rests on.
	Basis string `json:"basis"`
}

// SourceRef is the code an image was built from.
type SourceRef struct {
	// URL is a repository URL.
	URL string `json:"url"`
	// Revision is a commit or tag, when known.
	Revision string `json:"revision,omitempty"`
	// Basis is where this came from: provenance (verified), label, or annotation.
	Basis string `json:"basis" enum:"provenance,label,annotation"`
}

// BaseLink is an image's base and how current it is.
type BaseLink struct {
	// ImageID is the base's ID when the base is itself in the report.
	ImageID    string `json:"imageId,omitempty"`
	Repository string `json:"repository"`
	// Ref is the base as the image is built on it (repository:tag or
	// repository@digest).
	Ref    string `json:"ref"`
	Digest string `json:"digest,omitempty"`
	// Method is how the relationship was established: layer-prefix (the
	// image starts with the base's exact layers), oci-base-digest,
	// buildpacks-metadata, oci-base-name, or history.
	Method string `json:"method" enum:"layer-prefix,oci-base-digest,buildpacks-metadata,oci-base-name,history"`
	// Strength is proof (layer-prefix), declared (an exact claim by the
	// image's author), assisted (a partial claim), or weak.
	Strength string `json:"strength" enum:"proof,declared,assisted,weak"`
	// Drift is current, stale, or unknown.
	Drift          string `json:"drift" enum:"current,stale,unknown"`
	VersionsBehind int    `json:"versionsBehind"`
	DaysBehind     int    `json:"daysBehind"`
	// CurrentRef and CurrentDigest are the newest observed version of the base.
	CurrentRef    string `json:"currentRef,omitempty"`
	CurrentDigest string `json:"currentDigest,omitempty"`
}

// Evidence is what is known about each kind of supply-chain evidence.
type Evidence struct {
	// Signature is a signature over the image itself.
	Signature EvidenceItem `json:"signature"`
	// SBOM is a software bill of materials (CycloneDX or SPDX).
	SBOM EvidenceItem `json:"sbom"`
	// VulnerabilityScan is a vulnerability report about the image.
	VulnerabilityScan EvidenceItem `json:"vulnerabilityScan"`
	// Provenance is SLSA build provenance.
	Provenance EvidenceItem `json:"provenance"`
	// Recipe is a clearcutt-factory recipe: what anyone needs to rebuild
	// the image bit for bit.
	Recipe EvidenceItem `json:"recipe"`
	// Rebase is a clearcutt-factory rebase record, for images whose layers
	// were moved onto a newer base without a rebuild.
	Rebase EvidenceItem `json:"rebase"`
	// Tests is evidence that the image was tested (a smoke test or test
	// attestation).
	Tests EvidenceItem `json:"tests"`
}

// EvidenceItem is one kind of evidence for one image.
type EvidenceItem struct {
	// Status is verified (found and checked against a trusted signer),
	// present (found but not checked: no trusted signer applies, or it
	// can't be checked), failed (found, and the check failed), missing
	// (looked for, none), unknown (couldn't be looked for), or
	// not-applicable (e.g. a rebase record for an image never rebased).
	Status string `json:"status" enum:"verified,present,failed,missing,unknown,not-applicable"`
	// Source is where it was found: cosign-signature, cosign-attestation,
	// github-attestation, or oci-referrer (an unsigned document). Open: new
	// sources may appear.
	Source string `json:"source,omitempty"`
	// PredicateType is the in-toto predicate type, for attestations.
	PredicateType string `json:"predicateType,omitempty"`
	// Signer is who signed it, as read from the signing certificate or key.
	Signer *Signer `json:"signer,omitempty"`
	// Ref is where it is stored (e.g. an attestation's repository@digest).
	Ref string `json:"ref,omitempty"`
	// Timestamp is when it was signed or produced (RFC 3339), if known.
	Timestamp string `json:"timestamp,omitempty"`
	// Platforms gives the status per platform image, for evidence attached
	// per platform (SBOMs and vulnerability reports); Status is the worst.
	Platforms map[string]string `json:"platforms,omitempty"`
	// Detail explains the status in a sentence.
	Detail string `json:"detail,omitempty"`
}

// Vulnerabilities is an image's vulnerability findings.
type Vulnerabilities struct {
	// Source is attestation (the publisher's signed report) or scan (this
	// run scanned the image or its SBOM).
	Source string `json:"source" enum:"attestation,scan"`
	// Scanner is the scanner and version, e.g. grype 0.118.0.
	Scanner string `json:"scanner,omitempty"`
	// ScannedAt is when the scan ran (RFC 3339); findings describe that day.
	ScannedAt string         `json:"scannedAt,omitempty"`
	Counts    SeverityCounts `json:"counts"`
	Fixable   SeverityCounts `json:"fixable"`
	// Findings are deduplicated across platforms.
	Findings []Finding `json:"findings"`
}

// Finding is one vulnerability in one package version.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity" enum:"critical,high,medium,low,negligible,unknown"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	// FixedIn lists versions with a fix; empty when none is known.
	FixedIn []string `json:"fixedIn,omitempty"`
	// Platforms are the platform images it was found in.
	Platforms []string `json:"platforms"`
	// Suppressed says a VEX statement covers it (it is not counted).
	Suppressed bool `json:"suppressed,omitempty"`
}

// Reproducibility is whether rebuilding the image gives the same digest.
type Reproducibility struct {
	// Status is reproduced, not-reproduced (the rebuild gave a different
	// digest), not-checked (a recipe exists but this run didn't rebuild, or
	// the rebuild couldn't finish; see detail), or no-recipe (nothing to
	// rebuild from).
	Status string `json:"status" enum:"reproduced,not-reproduced,not-checked,no-recipe"`
	// Method is recipe-rebuild (rebuilt from the signed recipe) or
	// rebase-repeat (repeated the recorded rebase).
	Method string `json:"method,omitempty" enum:"recipe-rebuild,rebase-repeat"`
	// CheckedAt is when it was checked (RFC 3339).
	CheckedAt string `json:"checkedAt,omitempty"`
	// Digest is what the rebuild produced.
	Digest string `json:"digest,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Factory describes an image built or rebased by clearcutt-factory, from its
// verified recipe or rebase record.
type Factory struct {
	// Kind is Image or App. A rebased image's comes from the recipe of the
	// image it was rebased from; it is absent when that couldn't be read.
	Kind string `json:"kind,omitempty" enum:"Image,App"`
	// Name is the manifest's metadata.name (absent like kind).
	Name string `json:"name,omitempty"`
	// Stack is the stack an app was built on.
	Stack string `json:"stack,omitempty"`
	// Version is the clearcutt-factory version that built or rebased it.
	Version string `json:"version,omitempty"`
	// SourceDateEpoch is the build timestamp all files were clamped to.
	SourceDateEpoch int64 `json:"sourceDateEpoch,omitempty"`
	// RebasedFrom is the image whose layers were rebased (repository@digest).
	RebasedFrom string `json:"rebasedFrom,omitempty"`
	// Inputs counts what the lock pins.
	Inputs *FactoryInputs `json:"inputs,omitempty"`
}

// FactoryInputs counts a factory lock's pins.
type FactoryInputs struct {
	Packages int `json:"packages"`
	Tools    int `json:"tools"`
	Images   int `json:"images"`
}

// Verdict is whether the image meets the policy.
type Verdict struct {
	// Status is verified (meets every requirement), failed (violates one),
	// or unverified (some requirement couldn't be decided).
	Status string `json:"status" enum:"verified,failed,unverified"`
	// Reasons explain a failed or unverified verdict, one requirement each.
	Reasons []string `json:"reasons"`
}

// Base is a base-image repository and its newest observed version.
type Base struct {
	Repository     string `json:"repository"`
	CurrentRef     string `json:"currentRef"`
	CurrentDigest  string `json:"currentDigest,omitempty"`
	CurrentCreated string `json:"currentCreated,omitempty"`
	// Versions is how many versions of it images are built on.
	Versions int `json:"versions"`
	// Consumers is how many images are built on it; StaleConsumers how many
	// of those aren't on the newest version.
	Consumers      int `json:"consumers"`
	StaleConsumers int `json:"staleConsumers"`
}

// PackageUse is one package version and the images that ship it.
type PackageUse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Type is the ecosystem: apk, deb, rpm, golang, npm, pypi, maven, nix, …
	Type string `json:"type"`
	PURL string `json:"purl,omitempty"`
	// Images are image IDs.
	Images []string `json:"images"`
}

// History is the series of reports for an estate, newest first.
type History struct {
	// APIVersion is clearcutt.dev/v1.
	APIVersion string `json:"apiVersion"`
	// Kind is EstateHistory.
	Kind    string         `json:"kind"`
	Name    string         `json:"name"`
	Entries []HistoryEntry `json:"entries"`
}

// HistoryEntry is one past report's headline numbers.
type HistoryEntry struct {
	GeneratedAt string `json:"generatedAt"`
	// Ref is where that report is stored (a registry reference or a path).
	Ref     string  `json:"ref,omitempty"`
	Summary Summary `json:"summary"`
}

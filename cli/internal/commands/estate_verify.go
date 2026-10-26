package commands

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/estateverify"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/northcutted/clearcutt-verify/internal/registryauth"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

// cosignRunner, when set, runs cosign instead of the binary (tests).
var cosignRunner func(ctx context.Context, bin string, args ...string) ([]byte, error)

// grypeRunner, when set, runs grype instead of the binary (tests).
var grypeRunner func(ctx context.Context, dir, bin string, args ...string) (stdout, stderr []byte, err error)

var estateVerifyOpts struct {
	observations string
	refs         string
	policy       string
	name         string
	out          string
	history      string
	reproduce    bool
	rescan       bool
	factoryPath  string
	cosignPath   string
	grypePath    string
	trustedRoot  string
	generatedAt  string
	concurrency  int
	platforms    []string
	failOn       string
	// Policy without a file.
	require        []string
	identityRegexp string
	sourceOwner    string
	sourceMatches  bool
	trustPolicy    string
	issuer         string
	severity       string
	onlyFixed      bool
	maxScanAge     int
	scanSource     string
	vex            []string
	observe        []string
}

// newEstateVerifyCmd verifies every image in an estate and writes the estate
// report bundle (see contract/README.md).
func newEstateVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify every image in an estate and write the estate report",
		Long: `Verifies every image in an estate and writes the estate report bundle
(estate-report.json, estate-history.json) that clearcutt-portal reads; the
format is the contract in contract/README.md.

For each image it finds the evidence attached in the registry (signatures,
SBOMs, vulnerability reports, SLSA provenance, clearcutt-factory recipes and
rebase records; cosign v2 tags and v3 bundles), verifies it with cosign
against the policy's trusted signers, reads vulnerabilities and packages from
the attestations that verified (nothing from ones that didn't), places the
image on its base (proven by layer digests where possible), and decides a
verdict. With no trusted signer, no image is verified. A verified
clearcutt-factory reproduction attestation, made from the image's verified
recipe or rebase record, shows an image reproduced without rebuilding it. With
--reproduce it rebuilds the other clearcutt-factory images from their signed
recipes (clearcutt-factory on PATH). With --rescan it scans each image's
verified SBOMs itself with grype (on PATH), so the report shows the
publisher's scan and today's side by side; the policy's scanSource says which
failOn gates on (default with --rescan: the worse of the two), and its vex:
documents are applied to the rescans with every suppressed finding listed.

Images come from an observations file (clearcutt-verify import observe) or a list of
references (--refs), which are imported and observed first.

It prints a summary table; --verbose adds why each image that isn't verified
isn't, --quiet prints nothing but errors and the --fail-on result, and
--format json or yaml prints the report itself instead of the table.`,
		Example: `  clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out dist/estate
  clearcutt-verify estate verify --observations dist/scan/observations.json \
    --require signature,sbom,vulnerabilityScan \
    --trusted-identity-regexp '^https://github\.com/acme/' \
    --trusted-issuer https://token.actions.githubusercontent.com --out dist/estate`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEstateVerify(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	o := &estateVerifyOpts
	f.StringVar(&o.observations, "observations", "", "observations.json from clearcutt-verify import observe")
	f.StringVar(&o.refs, "refs", "", "File of image references, one per line (imported and observed first)")
	f.StringVar(&o.policy, "policy", "", "VerificationPolicy file (see clearcutt-verify estate verify --help)")
	f.StringVar(&o.name, "name", "estate", "Estate name in the report")
	f.StringVar(&o.out, "out", "", "Bundle directory to write (estate-report.json, estate-history.json)")
	f.StringVar(&o.history, "history", "", "Previous estate-history.json to extend (default: the one in --out, if any)")
	f.BoolVar(&o.reproduce, "reproduce", false, "Rebuild clearcutt-factory images from their signed recipes and compare digests (images with a verified reproduction attestation aren't rebuilt)")
	f.StringVar(&o.factoryPath, "factory-path", "clearcutt-factory", "clearcutt-factory binary, for --reproduce")
	f.StringVar(&o.cosignPath, "cosign-path", "cosign", "cosign v3 binary (checked before the run; missing or another major version exits 1)")
	f.StringVar(&o.trustedRoot, "trusted-root", "", "Sigstore trusted_root.json for cosign to verify keyless evidence against (cosign --trusted-root); default: fetched once with cosign initialize before the run")
	f.BoolVar(&o.rescan, "rescan", false, "Scan each image's verified SBOMs with grype and report the fresh findings beside the attested scan (grype's database settings, GRYPE_DB_*, apply)")
	f.StringVar(&o.grypePath, "grype-path", "grype", "grype binary, for --rescan (checked before the run; missing exits 1)")
	f.StringVar(&o.generatedAt, "generated-at", "", "Deterministic report timestamp (RFC 3339)")
	f.IntVar(&o.concurrency, "concurrency", 4, "Images to verify at once")
	f.StringSliceVar(&o.platforms, "platforms", nil, "Read only these platform images (e.g. linux/amd64,linux/arm64); default all. Cuts requests for bases published for many architectures")
	f.StringVar(&o.failOn, "fail-on", "never", "Exit 2 when any image is failed, or failed or unverified: failed, unverified, never")
	f.StringSliceVar(&o.require, "require", nil, "Required evidence when there is no --policy (e.g. signature,sbom,vulnerabilityScan,provenance)")
	f.StringVar(&o.identityRegexp, "trusted-identity-regexp", "", "Trusted signer certificate identity (regular expression) when there is no --policy")
	f.StringVar(&o.issuer, "trusted-issuer", "", "Trusted signer OIDC issuer when there is no --policy")
	f.StringVar(&o.sourceOwner, "trusted-source-owner", "", "Accept the trusted signer only from runs in this owner's repositories (e.g. https://github.com/acme); for reusable workflows")
	f.BoolVar(&o.sourceMatches, "trusted-source-matches-image", false, "Accept the trusted signer only from runs in the repository each image names as its source")
	f.StringVar(&o.trustPolicy, "trust-policy", "", "TrustPolicy file whose image signers are trusted too (shared with clearcutt-factory)")
	f.StringVar(&o.severity, "vulnerabilities-fail-on", "", "Fail images with vulnerabilities at or above this severity when there is no --policy")
	f.BoolVar(&o.onlyFixed, "only-fixed", false, "Count only fixable vulnerabilities toward --vulnerabilities-fail-on")
	f.IntVar(&o.maxScanAge, "max-scan-age-days", 0, "Leave images unverified whose vulnerability scan is older than this, when there is no --policy")
	f.StringVar(&o.scanSource, "scan-source", "", "Which findings --vulnerabilities-fail-on gates on with --rescan: attestation, rescan, or worst (default worst), when there is no --policy")
	f.StringSliceVar(&o.vex, "vex", nil, "OpenVEX documents to apply to --rescan, when there is no --policy")
	f.StringSliceVar(&o.observe, "observe", nil, "Path globs of repositories (or repository:tag) to observe without gating on, when there is no --policy")
	return cmd
}

func runEstateVerify(ctx context.Context, stdout, stderr io.Writer) error {
	o := estateVerifyOpts
	if ctx == nil {
		ctx = context.Background()
	}
	if o.out == "" {
		return errors.New("--out is required")
	}
	if (o.observations == "") == (o.refs == "") {
		return errors.New("pass exactly one of --observations and --refs")
	}
	switch o.failOn {
	case "failed", "unverified", "never":
	default:
		return fmt.Errorf("--fail-on %q must be failed, unverified, or never", o.failOn)
	}

	policy, vex, err := estatePolicy()
	if err != nil {
		return err
	}
	policy.Reproduce = o.reproduce
	policy.Rescan = o.rescan
	if !o.rescan && policy.ScanSource != "" && policy.ScanSource != "attestation" {
		return fmt.Errorf("scanSource %s gates on this run's own scan, which needs --rescan", policy.ScanSource)
	}
	if !o.rescan && len(policy.VEX) > 0 {
		fprintf(stderr, "[verify-estate] note: the policy's VEX documents apply to --rescan, which this run doesn't do; the publisher's scans are read as attested\n")
	}

	// The tools come first: without them every piece of evidence would come
	// out failed or unknown for a reason that has nothing to do with the
	// estate. A missing or unusable tool is an operational error (exit 1),
	// never a policy result.
	verifier := &estateverify.Verifier{Signers: append(append([]report.Signer{}, policy.TrustedSigners...), policy.StackSigners...), Cosign: o.cosignPath, Run: cosignRunner, TrustedRoot: o.trustedRoot}
	var rootWarning string
	if len(policy.TrustedSigners)+len(policy.StackSigners) > 0 {
		if _, err := verifier.CheckCosign(ctx); err != nil {
			return err
		}
		// Sigstore's trusted root, once, before the concurrent verifications
		// that read it; a fetch that fails is an operational error here, not
		// unknown evidence everywhere.
		var root string
		root, rootWarning, err = verifier.PrepareTrustedRoot(ctx)
		if err != nil {
			return err
		}
		switch {
		case GlobalOpts.Quiet:
		case rootWarning != "":
			warnLoudly(stderr, "[verify-estate]", "estate verify: no single trusted root", rootWarning)
		case root == "":
		case o.trustedRoot != "":
			fprintf(stderr, "[verify-estate] Sigstore evidence is verified against %s (--trusted-root)\n", root)
		default:
			fprintf(stderr, "[verify-estate] Sigstore evidence is verified against %s (cosign initialize fetched it once for this run)\n", root)
		}
	}
	verifier.Signers = policy.TrustedSigners
	if o.reproduce {
		if _, err := exec.LookPath(o.factoryPath); err != nil {
			return fmt.Errorf("--reproduce rebuilds images with clearcutt-factory, which is not available (%s): install it, or name it with --factory-path: %w", o.factoryPath, err)
		}
	}
	var scanner *estateverify.GrypeScanner
	if o.rescan {
		scanner = &estateverify.GrypeScanner{Binary: o.grypePath, Run: grypeRunner}
		version, err := scanner.CheckGrype(ctx)
		if err != nil {
			return err
		}
		if !GlobalOpts.Quiet {
			fprintf(stderr, "[verify-estate] rescanning verified SBOMs with grype %s\n", version)
		}
	}

	// One cache for the run: the observer, the verifier, and base checks read
	// many of the same manifests, and registries count each read.
	ropts := []remote.Option{
		remote.WithAuthFromKeychain(registryauth.Keychain),
		// Ride out registry throttling and blips; a refusal that persists
		// is reported as unknown.
		remote.WithRetryStatusCodes(http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout),
		remote.WithRetryBackoff(remote.Backoff{Duration: time.Second, Factor: 2, Jitter: 0.2, Steps: 4}),
		remote.WithTransport(estateverify.NewManifestCache(remote.DefaultTransport)),
	}
	var observations estategraph.Observations
	if o.observations != "" {
		if observations, err = estategraph.ReadObservations(o.observations); err != nil {
			return err
		}
	} else {
		refs, err := readRefList(o.refs)
		if err != nil {
			return err
		}
		inventory, _, err := estategraph.ImportRefList(refs, estategraph.ImportOptions{GeneratedAt: o.generatedAt})
		if err != nil {
			return err
		}
		observer := estategraph.RegistryObserver{Options: ropts}
		observations, _, err = estategraph.ObserveImages(ctx, inventory, observer, estategraph.ObserveOptions{GeneratedAt: o.generatedAt, Concurrency: o.concurrency})
		if err != nil {
			return err
		}
	}

	opts := estateverify.Options{
		Name: o.name, Version: Version, Policy: policy, Sources: sourcesOf(observations),
		GeneratedAt: o.generatedAt, Concurrency: o.concurrency, Platforms: o.platforms, RemoteOptions: ropts,
		Discoverer: &estateverify.Discoverer{Options: ropts},
		Verifier:   verifier,
		Log:        stderr,
	}
	if o.reproduce {
		opts.Reproducer = estateverify.FactoryReproducer{Binary: o.factoryPath}
	}
	if scanner != nil {
		opts.Scanner, opts.VEX = scanner, vex
	}
	r, err := estateverify.Build(ctx, observations, opts)
	if err != nil {
		return err
	}
	if rootWarning != "" {
		// The report says so too: it is what readers see.
		r.Warnings = append(r.Warnings, rootWarning)
	}

	history, err := extendHistory(r, estateverify.SourceRefs(observations), o.history, o.out)
	if err != nil {
		return err
	}
	// Nothing is written that breaks the contract readers rely on: a report
	// a portal would refuse, or a history it would choke on, is a bug here,
	// not a result.
	if err := report.Validate(r); err != nil {
		return fmt.Errorf("the estate report this run made isn't valid, so nothing was written (a bug in clearcutt-verify; please report it): %w", err)
	}
	if err := report.Validate(history); err != nil {
		return fmt.Errorf("the estate history isn't valid, so nothing was written (the history this run extends, %s, or this run's entry): %w", firstNonEmptyString(o.history, filepath.Join(o.out, report.HistoryFile)), err)
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	if err := writeReportJSON(filepath.Join(o.out, report.ReportFile), r); err != nil {
		return err
	}
	if err := writeReportJSON(filepath.Join(o.out, report.HistoryFile), history); err != nil {
		return err
	}

	wrote := fmt.Sprintf("wrote %s and %s", filepath.Join(o.out, report.ReportFile), filepath.Join(o.out, report.HistoryFile))
	switch {
	case structuredFormat():
		// The report itself, for a pipeline; what was written goes to stderr.
		if err := printReport(stdout, r); err != nil {
			return err
		}
		if !GlobalOpts.Quiet {
			fprintf(stderr, "[verify-estate] %s\n", wrote)
		}
	case GlobalOpts.Quiet:
	default:
		printEstateSummary(stdout, r)
		if GlobalOpts.Verbose {
			printVerdictReasons(stdout, r)
		}
		fprintf(stdout, "\n%s\n", wrote)
	}
	// A report that shows nothing could be checked is honest, but it isn't a
	// result: the run exits as an operational failure, not as a pass.
	if estateverify.NothingChecked(r) {
		return errors.New("nothing about the estate could be checked: every piece of evidence is unknown (cosign, the registries, or the images couldn't be reached); the report says so and was written, but this isn't a result")
	}
	if scanner != nil && scanner.Failed() > 0 && scanner.Scanned() == 0 {
		return fmt.Errorf("grype couldn't scan any image (%d scans failed; see each image's rescan.detail), so every rescan is unknown; the report was written, but this isn't a result", scanner.Failed())
	}
	s := r.Summary.Verdicts
	if (o.failOn == "failed" && s.Failed > 0) || (o.failOn == "unverified" && s.Failed+s.Unverified > 0) {
		fprintf(stderr, "[verify-estate] %d failed, %d unverified (--fail-on %s)\n", s.Failed, s.Unverified, o.failOn)
		return fmt.Errorf("estate verification: %w", ErrCheckFailed)
	}
	return nil
}

// estatePolicy reads --policy, or builds a policy from flags, and reads the
// VEX documents it names (relative to the policy file, or to the working
// directory for --vex).
func estatePolicy() (report.Policy, []estateverify.VEXDocument, error) {
	o := estateVerifyOpts
	var p report.Policy
	vexDir := "."
	if o.policy != "" {
		if len(o.require) > 0 || o.identityRegexp != "" || o.issuer != "" || o.sourceOwner != "" || o.sourceMatches || o.severity != "" || o.maxScanAge != 0 ||
			o.scanSource != "" || len(o.vex) > 0 || len(o.observe) > 0 {
			return report.Policy{}, nil, errors.New("--policy and the policy flags (--require, --trusted-*, --vulnerabilities-fail-on, --scan-source, --vex, --observe) are exclusive")
		}
		var err error
		if p, err = estateverify.ReadPolicy(o.policy); err != nil {
			return report.Policy{}, nil, err
		}
		vexDir = filepath.Dir(o.policy)
	} else {
		p = report.Policy{Required: o.require, FailOn: o.severity, OnlyFixed: o.onlyFixed, MaxScanAgeDays: o.maxScanAge, ScanSource: o.scanSource, Observe: o.observe}
		if o.identityRegexp != "" || o.issuer != "" || o.sourceOwner != "" || o.sourceMatches {
			p.TrustedSigners = []report.Signer{{IdentityRegexp: o.identityRegexp, Issuer: o.issuer, SourceRepositoryOwner: o.sourceOwner, SourceMatchesImage: o.sourceMatches}}
		}
		for _, f := range o.vex {
			p.VEX = append(p.VEX, report.VEXDocument{File: f})
		}
	}
	if o.trustPolicy != "" {
		t, err := estateverify.ReadTrustPolicy(o.trustPolicy)
		if err != nil {
			return report.Policy{}, nil, err
		}
		p.TrustedSigners = append(p.TrustedSigners, t.For("image")...)
		p.StackSigners = append(p.StackSigners, t.For("stack")...)
	}
	var files []string
	for _, d := range p.VEX {
		files = append(files, d.File)
	}
	vex, err := estateverify.ReadVEX(vexDir, files)
	if err != nil {
		return report.Policy{}, nil, err
	}
	p.VEX = nil
	for _, d := range vex {
		p.VEX = append(p.VEX, report.VEXDocument{File: d.File, ID: d.ID, Author: d.Author, Statements: len(d.Statements)})
	}
	return p, vex, estateverify.ValidatePolicy(p)
}

func readRefList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var refs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			refs = append(refs, line)
		}
	}
	return refs, sc.Err()
}

// sourcesOf groups the observed repositories by registry.
func sourcesOf(observations estategraph.Observations) []report.Source {
	repos := map[string][]string{}
	for _, obs := range observations.Images {
		ref := firstNonEmptyString(obs.DigestRef, obs.SourceRef)
		r, err := name.ParseReference(ref, name.WeakValidation)
		if err != nil {
			continue
		}
		reg := r.Context().RegistryStr()
		if reg == name.DefaultRegistry {
			reg = "docker.io"
		}
		repos[reg] = appendUniqueString(repos[reg], r.Context().RepositoryStr())
	}
	var out []report.Source
	for reg, list := range repos {
		sort.Strings(list)
		out = append(out, report.Source{Registry: reg, Repositories: list})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Registry < out[j].Registry })
	return out
}

// extendHistory prepends this run to the previous history (from path, or
// the bundle directory). refs maps each image ID to the reference it was
// observed by.
func extendHistory(r *report.Report, refs map[string]string, path, out string) (*report.History, error) {
	h := &report.History{APIVersion: report.APIVersion, Kind: report.KindHistory, Name: r.Metadata.Name, Entries: []report.HistoryEntry{}}
	if path == "" {
		path = filepath.Join(out, report.HistoryFile)
		if _, err := os.Stat(path); err != nil {
			path = ""
		}
	}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var prev report.History
		if err := json.Unmarshal(raw, &prev); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if prev.Kind != report.KindHistory {
			return nil, fmt.Errorf("%s is not an EstateHistory", path)
		}
		for _, e := range prev.Entries {
			if e.GeneratedAt != r.Metadata.GeneratedAt {
				h.Entries = append(h.Entries, e)
			}
		}
		renameLegacyIDs(h.Entries, r, refs)
	}
	h.Entries = append([]report.HistoryEntry{{GeneratedAt: r.Metadata.GeneratedAt, Ref: report.ReportFile, Summary: r.Summary, Images: historyImages(r)}}, h.Entries...)
	return h, nil
}

// renameLegacyIDs gives rows of earlier runs the IDs images have now.
// Before v0.17.0 an image's ID came from the reference as it was written:
// its repository's last path segment and its tag (billing-1-2), the
// segment alone for the tag latest, written or not (ghcr.io/acme/app was
// app), or the segment and the digest's first 12 hex digits for a digest
// reference (with or without a tag). Now it is the whole reference
// (ghcr-io-acme-billing-1-2). refs maps each current image ID to the
// reference it was observed by. A row whose ID is no current image's, and is
// the old ID of exactly one current image, is that image's, so its history
// carries on. Anything less certain, an image whose reference isn't known
// included, is left as it was.
func renameLegacyIDs(entries []report.HistoryEntry, r *report.Report, refs map[string]string) {
	current := map[string]bool{}
	legacy := map[string][]string{} // old ID → current IDs
	for _, img := range r.Images {
		current[img.ID] = true
		if old := legacyImageID(refs[img.ID]); old != "" {
			legacy[old] = append(legacy[old], img.ID)
		}
	}
	for i := range entries {
		for j := range entries[i].Images {
			row := &entries[i].Images[j]
			if ids := legacy[row.ID]; !current[row.ID] && len(ids) == 1 {
				row.ID = ids[0]
			}
		}
	}
}

// legacyImageID is the ID clearcutt-verify gave the image referenced by ref
// before v0.17.0, or "" when ref isn't a reference.
func legacyImageID(ref string) string {
	parsed, err := name.ParseReference(strings.TrimSpace(ref), name.WeakValidation)
	if err != nil {
		return ""
	}
	base := sanitizeLegacy(path.Base(parsed.Context().RepositoryStr()))
	switch id := parsed.Identifier(); {
	case strings.HasPrefix(id, "sha256:") && len(id) >= 19:
		return strings.Trim(base+"-"+sanitizeLegacy(id[:19]), "-")
	case id != "latest":
		return strings.Trim(base+"-"+sanitizeLegacy(id), "-")
	}
	return base
}

func sanitizeLegacy(v string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(v) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteRune('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// historyImages is one row per image of the run, for per-image history.
func historyImages(r *report.Report) []report.HistoryImage {
	packages := map[string][]string{} // image ID → "type name version" lines
	for _, p := range r.Packages {
		for _, id := range p.Images {
			packages[id] = append(packages[id], p.Type+" "+p.Name+" "+p.Version+"\n")
		}
	}
	rows := make([]report.HistoryImage, 0, len(r.Images))
	for _, img := range r.Images {
		row := report.HistoryImage{ID: img.ID, Digest: img.Digest, Verdict: img.Verdict.Status}
		if b := img.Base; b != nil {
			row.Base = &report.HistoryBase{Digest: b.Digest, Platform: b.Platform, Drift: b.Drift, Strength: b.Strength}
		}
		if img.Factory != nil && img.Factory.RebasedFrom != "" {
			row.RebasedFrom, row.RebaseStatus = img.Factory.RebasedFrom, img.Evidence.Rebase.Status
		}
		if v := img.Vulnerabilities; v != nil {
			counts := v.Counts
			row.Vulnerabilities = &counts
			row.FixableFindings = fixableFindings(v)
		}
		if rs := img.Rescan; rs != nil && rs.Status == "scanned" && rs.Vulnerabilities != nil {
			counts := rs.Vulnerabilities.Counts
			row.RescanVulnerabilities = &counts
		}
		row.ObserveOnly = img.ObserveOnly
		if img.Packages != nil {
			row.PackagesDigest = packagesDigest(packages[img.ID])
		}
		rows = append(rows, row)
	}
	return rows
}

// fixableFindings lists the IDs of the counted (not suppressed) high and
// critical findings that have a fix, once each, sorted.
func fixableFindings(v *report.Vulnerabilities) []string {
	var ids []string
	for _, f := range v.Findings {
		if !f.Suppressed && len(f.FixedIn) > 0 && (f.Severity == "high" || f.Severity == "critical") {
			ids = appendUniqueString(ids, f.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// packagesDigest identifies a package set: sha256 of its "type name
// version\n" lines, sorted.
func packagesDigest(lines []string) string {
	sorted := append([]string{}, lines...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func printEstateSummary(w io.Writer, r *report.Report) {
	s := r.Summary
	fprintf(w, "%d images: %d verified, %d failed, %d unverified", s.Images, s.Verdicts.Verified, s.Verdicts.Failed, s.Verdicts.Unverified)
	if s.Verdicts.ObserveOnly > 0 {
		fprintf(w, ", %d observe-only (not gating)", s.Verdicts.ObserveOnly)
	}
	fprintf(w, "\n")
	if rs := s.Rescan; rs != nil {
		fprintf(w, "rescan (%s): %d images scanned, %d unknown; %d critical, %d high, %d medium (%d suppressed by VEX)\n",
			firstNonEmptyString(rs.Scanner, "grype"), rs.Scanned, rs.Unknown, rs.Counts.Critical, rs.Counts.High, rs.Counts.Medium, rs.Suppressed)
	}
	fprintf(w, "bases: %d proven, %d claimed, %d roots, %d unresolved; %d current, %d stale\n",
		s.Bases.Proven, s.Bases.Claimed, s.Bases.Roots, s.Bases.Unresolved, s.Bases.Current, s.Bases.Stale)
	for _, st := range r.Stacks {
		signed := 0
		for _, v := range st.Versions {
			if v.Signature.Status == "verified" {
				signed++
			}
		}
		fprintf(w, "stack %s: %d apps, %d on an older version; %d of %d versions in use verified\n",
			st.Repository, st.Consumers, st.StaleConsumers, signed, len(st.Versions))
	}
	fprintf(w, "\n%-28s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %s\n", "IMAGE", "SIGNATURE", "SBOM", "VULNS", "PROVENANCE", "RECIPE", "REBASE", "REPRO", "VERDICT")
	for _, img := range r.Images {
		e := img.Evidence
		verdict := img.Verdict.Status
		if img.ObserveOnly {
			verdict += " (observe-only)"
		}
		fprintf(w, "%-28s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %s\n", truncate(img.ID, 28),
			e.Signature.Status, e.SBOM.Status, e.VulnerabilityScan.Status, e.Provenance.Status, e.Recipe.Status, e.Rebase.Status,
			img.Reproducibility.Status, verdict)
	}
}

// printReport writes the report in the structured --format.
func printReport(w io.Writer, r *report.Report) error {
	if strings.EqualFold(GlobalOpts.Format, "json") {
		return output.PrintJSON(w, r)
	}
	return output.PrintYAML(w, r)
}

// printVerdictReasons lists why each image that isn't verified isn't
// (--verbose).
func printVerdictReasons(w io.Writer, r *report.Report) {
	for _, img := range r.Images {
		if img.Verdict.Status == "verified" {
			continue
		}
		fprintf(w, "\n%s: %s\n", img.ID, img.Verdict.Status)
		for _, reason := range img.Verdict.Reasons {
			fprintf(w, "  - %s\n", reason)
		}
		for _, warning := range img.Warnings {
			fprintf(w, "  ! %s\n", warning)
		}
	}
}

func writeReportJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func appendUniqueString(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

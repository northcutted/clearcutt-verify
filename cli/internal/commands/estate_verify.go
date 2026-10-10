package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/estateverify"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

var estateVerifyOpts struct {
	observations string
	refs         string
	policy       string
	name         string
	out          string
	history      string
	reproduce    bool
	factoryPath  string
	cosignPath   string
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
the attestations, places the image on its base (proven by layer digests where
possible), and decides a verdict. With --reproduce it rebuilds
clearcutt-factory images from their signed recipes (clearcutt-factory on PATH).

Images come from an observations file (clearcutt-verify import observe) or a list of
references (--refs), which are imported and observed first.`,
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
	f.BoolVar(&o.reproduce, "reproduce", false, "Rebuild clearcutt-factory images from their signed recipes and compare digests")
	f.StringVar(&o.factoryPath, "factory-path", "clearcutt-factory", "clearcutt-factory binary, for --reproduce")
	f.StringVar(&o.cosignPath, "cosign-path", "cosign", "cosign binary")
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

	policy, err := estatePolicy()
	if err != nil {
		return err
	}
	policy.Reproduce = o.reproduce

	// One cache for the run: the observer, the verifier, and base checks read
	// many of the same manifests, and registries count each read.
	ropts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
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
		Verifier:   &estateverify.Verifier{Signers: policy.TrustedSigners, Cosign: o.cosignPath},
		Log:        stderr,
	}
	if o.reproduce {
		opts.Reproducer = estateverify.FactoryReproducer{Binary: o.factoryPath}
	}
	r, err := estateverify.Build(ctx, observations, opts)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	if err := writeReportJSON(filepath.Join(o.out, report.ReportFile), r); err != nil {
		return err
	}
	history, err := extendHistory(r, o.history, o.out)
	if err != nil {
		return err
	}
	if err := writeReportJSON(filepath.Join(o.out, report.HistoryFile), history); err != nil {
		return err
	}

	printEstateSummary(stdout, r)
	fmt.Fprintf(stdout, "\nwrote %s and %s\n", filepath.Join(o.out, report.ReportFile), filepath.Join(o.out, report.HistoryFile))
	s := r.Summary.Verdicts
	if (o.failOn == "failed" && s.Failed > 0) || (o.failOn == "unverified" && s.Failed+s.Unverified > 0) {
		fmt.Fprintf(stderr, "[verify-estate] %d failed, %d unverified (--fail-on %s)\n", s.Failed, s.Unverified, o.failOn)
		return fmt.Errorf("estate verification: %w", ErrCheckFailed)
	}
	return nil
}

// estatePolicy reads --policy, or builds a policy from flags.
func estatePolicy() (report.Policy, error) {
	o := estateVerifyOpts
	var p report.Policy
	if o.policy != "" {
		if len(o.require) > 0 || o.identityRegexp != "" || o.issuer != "" || o.sourceOwner != "" || o.sourceMatches || o.severity != "" || o.maxScanAge != 0 {
			return report.Policy{}, errors.New("--policy and the policy flags (--require, --trusted-*, --vulnerabilities-fail-on) are exclusive")
		}
		var err error
		if p, err = estateverify.ReadPolicy(o.policy); err != nil {
			return report.Policy{}, err
		}
	} else {
		p = report.Policy{Required: o.require, FailOn: o.severity, OnlyFixed: o.onlyFixed, MaxScanAgeDays: o.maxScanAge}
		if o.identityRegexp != "" || o.issuer != "" || o.sourceOwner != "" || o.sourceMatches {
			p.TrustedSigners = []report.Signer{{IdentityRegexp: o.identityRegexp, Issuer: o.issuer, SourceRepositoryOwner: o.sourceOwner, SourceMatchesImage: o.sourceMatches}}
		}
	}
	if o.trustPolicy != "" {
		t, err := estateverify.ReadTrustPolicy(o.trustPolicy)
		if err != nil {
			return report.Policy{}, err
		}
		p.TrustedSigners = append(p.TrustedSigners, t.For("image")...)
	}
	return p, estateverify.ValidatePolicy(p)
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
// the bundle directory).
func extendHistory(r *report.Report, path, out string) (*report.History, error) {
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
	}
	h.Entries = append([]report.HistoryEntry{{GeneratedAt: r.Metadata.GeneratedAt, Ref: report.ReportFile, Summary: r.Summary}}, h.Entries...)
	return h, nil
}

func printEstateSummary(w io.Writer, r *report.Report) {
	s := r.Summary
	fmt.Fprintf(w, "%d images: %d verified, %d failed, %d unverified\n", s.Images, s.Verdicts.Verified, s.Verdicts.Failed, s.Verdicts.Unverified)
	fmt.Fprintf(w, "bases: %d proven, %d claimed, %d roots, %d unresolved; %d current, %d stale\n",
		s.Bases.Proven, s.Bases.Claimed, s.Bases.Roots, s.Bases.Unresolved, s.Bases.Current, s.Bases.Stale)
	fmt.Fprintf(w, "\n%-28s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %s\n", "IMAGE", "SIGNATURE", "SBOM", "VULNS", "PROVENANCE", "RECIPE", "REBASE", "REPRO", "VERDICT")
	for _, img := range r.Images {
		e := img.Evidence
		fmt.Fprintf(w, "%-28s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %s\n", truncate(img.ID, 28),
			e.Signature.Status, e.SBOM.Status, e.VulnerabilityScan.Status, e.Provenance.Status, e.Recipe.Status, e.Rebase.Status,
			img.Reproducibility.Status, img.Verdict.Status)
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

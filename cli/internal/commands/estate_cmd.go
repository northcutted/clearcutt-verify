package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/northcutted/clearcutt-verify/internal/estate"
	"github.com/northcutted/clearcutt-verify/internal/estateverify"
	"github.com/northcutted/clearcutt-verify/internal/registryauth"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

type estateFlags struct {
	dir          string
	files        []string
	generatedAt  string
	insecure     bool
	output       string
	history      string
	allowMissing bool
	// Who must have signed what estate pull and estate history read: a
	// policy's estate signers, or cosign's flags.
	policy, trustPolicy                                 string
	identity, identityRegexp, issuer, workflowRepo, key string
	ignoreTlog, allowUnverified                         bool
	cosignPath, trustedRoot                             string
}

var estateOpts estateFlags

// estateDefaultFiles are the artifacts a governance snapshot is made of. They
// are the outputs of `import observe`, `graph build` and `graph layers`.
var estateDefaultFiles = []string{"observations.json", "graph.json", "layers.json"}

// NewEstateCmd builds the `clearcutt-verify estate` command group: verify an
// estate and write its report, persist a snapshot or report to a registry,
// and read one back.
func NewEstateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "estate",
		Short: "Verify an estate, and keep its reports and snapshots in a registry",
		Long: `Verify every image in an estate and write the estate report (estate verify),
and store reports or governance snapshots (observations, base graph, layer
graph) in a registry as OCI artifacts (estate push, pull, history).

The registry is a deliberate backing store, not a convenient one. The evidence
lives under the same auth boundary, replication and retention as the images it
describes; digests make each snapshot immutable; tags give history, so estate
drift is a diff between two tags; and a mirror carries its own evidence into an
air gap. Nothing new has to be operated.

Snapshots are deterministic: identical inputs produce an identical digest, so a
nightly push of an unchanged estate does not create a new version.`,
	}
	cmd.AddCommand(newEstateVerifyCmd(), newEstateDependentsCmd(), newEstatePushCmd(), newEstatePullCmd(), newEstateHistoryCmd())
	return cmd
}

func newEstatePushCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push <reference>",
		Short: "Push an estate snapshot to a registry as an OCI artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runEstatePush(args[0])
		},
	}
	cmd.Flags().StringVar(&estateOpts.dir, "dir", ".", "Directory holding the snapshot files")
	cmd.Flags().StringSliceVar(&estateOpts.files, "file", nil, "Snapshot file(s) to store (default: observations.json, graph.json, layers.json)")
	cmd.Flags().StringVar(&estateOpts.generatedAt, "generated-at", "", "Snapshot timestamp recorded as a manifest annotation")
	cmd.Flags().BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	cmd.Flags().StringVar(&estateOpts.history, "history", "", "Also append this snapshot to a history index at this reference (e.g. ghcr.io/acme/estate:history)")
	return cmd
}

func newEstatePullCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull <reference>",
		Short: "Pull an estate snapshot or report bundle out of a registry, verifying its signature",
		Long: `Pulls an estate snapshot or report bundle that estate push stored, and writes
its files, once cosign has verified its signature against the signers with
role estate in a trust policy (--trust-policy, or the one a verification
policy names: --policy), or against the signer named with
--certificate-identity (or --certificate-identity-regexp) and
--certificate-oidc-issuer, or --key, as cosign verify takes them. A bundle
that isn't signed by one of them, or whose signature can't be checked, is
refused, and nothing is written: anyone who can push to the repository could
have written it. --allow-unverified writes it anyway, with a warning.

It needs cosign v3 (on PATH, or --cosign-path), which reads the registry
with the Docker keychain: log cosign in to private registries.`,
		Example: `  clearcutt-verify estate pull ghcr.io/acme/estate:latest --output dist/estate --allow-missing \
    --trust-policy trust.yaml
  clearcutt-verify estate pull ghcr.io/acme/estate:latest --output dist/estate --allow-missing \
    --certificate-identity https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEstatePull(cmd.Context(), args[0])
		},
	}
	f := cmd.Flags()
	f.StringVar(&estateOpts.output, "output", ".", "Directory to write the snapshot files into")
	f.BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	f.BoolVar(&estateOpts.allowMissing, "allow-missing", false, "Succeed, writing nothing, when the registry has nothing at the reference yet (a first run); any other failure still fails")
	signerFlags(f, "the bundle")
	return cmd
}

// signerFlags adds the flags naming who must have signed what a command
// reads: a policy's estate signers, or cosign's flags.
func signerFlags(f *pflag.FlagSet, what string) {
	f.StringVar(&estateOpts.trustPolicy, "trust-policy", "", "TrustPolicy file whose signers with role estate may have signed "+what)
	f.StringVar(&estateOpts.policy, "policy", "", "VerificationPolicy file whose trustPolicy's signers with role estate may have signed "+what)
	f.StringVar(&estateOpts.identity, "certificate-identity", "", "The signer's certificate identity, exactly (as cosign verify takes it)")
	f.StringVar(&estateOpts.identityRegexp, "certificate-identity-regexp", "", "The signer's certificate identity, as an anchored regular expression")
	f.StringVar(&estateOpts.issuer, "certificate-oidc-issuer", "", "The signer's OIDC issuer, e.g. https://token.actions.githubusercontent.com")
	f.StringVar(&estateOpts.workflowRepo, "certificate-github-workflow-repository", "", "OWNER/REPO the signing GitHub Actions run must be in (for a reusable workflow, the calling repository)")
	f.StringVar(&estateOpts.key, "key", "", "Public key (file or KMS URI) "+what+" is signed with, instead of a certificate identity")
	f.BoolVar(&estateOpts.ignoreTlog, "insecure-ignore-tlog", false, "With --key: accept a signature with no transparency log entry (cosign --insecure-ignore-tlog)")
	f.BoolVar(&estateOpts.allowUnverified, "allow-unverified", false, "Go on even when the signature of "+what+" isn't verified (prints a warning); without a signer, it isn't checked at all")
	f.StringVar(&estateOpts.cosignPath, "cosign-path", "cosign", "cosign v3 binary")
	f.StringVar(&estateOpts.trustedRoot, "trusted-root", "", "Sigstore trusted_root.json for cosign to verify a keyless signer, or a key signer that checks the transparency log, against (default: fetched once with cosign initialize)")
}

// pullSigners is who must have signed what estate pull or estate history
// reads: a policy's signers with role estate (--trust-policy, or --policy's
// trustPolicy), or the one cosign's flags name; nil when none is named.
func pullSigners() ([]report.Signer, error) {
	o := estateOpts
	keyless := o.identity != "" || o.identityRegexp != "" || o.issuer != "" || o.workflowRepo != ""
	if o.policy != "" || o.trustPolicy != "" {
		if keyless || o.key != "" || o.ignoreTlog {
			return nil, errors.New("--policy and --trust-policy name the estate signers; the cosign flags (--certificate-*, --key, --insecure-ignore-tlog) are exclusive with them")
		}
		if o.policy != "" && o.trustPolicy != "" {
			return nil, errors.New("--policy and --trust-policy are exclusive")
		}
		return estateverify.ReadEstateSigners(o.policy, o.trustPolicy)
	}
	switch {
	case !keyless && o.key == "":
		if o.ignoreTlog {
			return nil, errors.New("--insecure-ignore-tlog applies to --key")
		}
		return nil, nil
	case keyless && o.key != "":
		return nil, errors.New("name the signer with --key, or with --certificate-identity(-regexp) and --certificate-oidc-issuer, not both")
	case o.identity != "" && o.identityRegexp != "":
		return nil, errors.New("--certificate-identity and --certificate-identity-regexp are exclusive")
	case keyless && (o.identity == "" && o.identityRegexp == "" || o.issuer == ""):
		return nil, errors.New("a keyless signer needs --certificate-identity (or --certificate-identity-regexp) and --certificate-oidc-issuer")
	case keyless && o.ignoreTlog:
		return nil, errors.New("--insecure-ignore-tlog applies to --key: a keyless certificate is valid only when the transparency log shows it was used in time")
	}
	s := report.Signer{Identity: o.identity, IdentityRegexp: o.identityRegexp, Issuer: o.issuer, Key: o.key}
	if o.workflowRepo != "" {
		s.SourceRepository = "https://github.com/" + strings.TrimPrefix(strings.TrimSuffix(o.workflowRepo, "/"), "https://github.com/")
	}
	if o.ignoreTlog {
		off := false
		s.Tlog = &off
	}
	if err := estateverify.ValidatePolicy(report.Policy{TrustedSigners: []report.Signer{s}}); err != nil {
		return nil, err
	}
	return []report.Signer{s}, nil
}

// noSignerError says how to name who signed what a command reads.
func noSignerError(command, what string) error {
	return fmt.Errorf("%s verifies the signature of %s: name its signers with --trust-policy (or --policy), whose signers with role estate count, or the one signer with --certificate-identity (or --certificate-identity-regexp) and --certificate-oidc-issuer, or --key, as cosign verify takes them (or pass --allow-unverified to go on unverified)", command, what)
}

// verifyArtifact checks the signature over an estate artifact (repo@digest)
// against signers, with cosign, and returns the item; verified is whether a
// signer vouched for it.
func verifyArtifact(ctx context.Context, signers []report.Signer, ref, repo, digest string) (report.EvidenceItem, error) {
	verifier := &estateverify.Verifier{Signers: signers, Cosign: estateOpts.cosignPath, Run: cosignRunner, TrustedRoot: estateOpts.trustedRoot, Timeout: GlobalOpts.CosignTimeout}
	if _, err := verifier.CheckCosign(ctx); err != nil {
		return report.EvidenceItem{}, err
	}
	if _, warning, err := verifier.PrepareTrustedRoot(ctx); err != nil {
		return report.EvidenceItem{}, err
	} else if warning != "" {
		warnLoudly(errOut, "[estate]", "estate: no single trusted root", warning)
	}
	ropts := registryOptions()
	if !estateOpts.insecure {
		ropts = append(ropts, remote.WithAuthFromKeychain(registryauth.ForRefs(ref)))
	}
	return estateverify.VerifySignature(ctx, verifier, &estateverify.Discoverer{Options: ropts}, repo, digest), nil
}

// warnLoudly prints a warning where it can't be missed: on w (standard
// error) and, in GitHub Actions, as a ::warning annotation there too (the
// runner reads standard error, and standard output may be a report).
func warnLoudly(w io.Writer, prefix, title, msg string) {
	fprintf(w, "%s WARNING: %s\n", prefix, msg)
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fprintf(w, "::warning title=%s::%s\n", title, msg)
	}
}

// warnUnverified says, where it can't be missed, that what was pulled is
// trusted on nobody's word.
func warnUnverified(ref, why string) {
	msg := fmt.Sprintf("--allow-unverified: the signature of %s was NOT verified (%s). Anyone who can push to the repository could have written these files; nothing shows they come from your estate job.", ref, why)
	fprintf(errOut, "[estate] WARNING: %s\n", msg)
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		fprintf(out, "::warning title=estate pull: unverified bundle::%s\n", msg)
	}
}

// estateClient reaches the registries refs name. Each credential goes only
// to its registry: REGISTRY_USER/REGISTRY_TOKEN (or CLEARCUTT_REGISTRY_*) to
// the registries refs name, GITHUB_TOKEN to ghcr.io, and the Docker
// keychain's each to its own. A CI runner with only environment credentials
// and a laptop with only a docker login both work without a flag.
func estateClient(refs ...string) *estate.Client {
	if estateOpts.insecure {
		return estate.NewInsecureClient(registryOptions()...)
	}
	return estate.NewKeychainClient(registryauth.ForRefs(refs...), registryOptions()...)
}

func runEstatePush(ref string) error {
	wanted := nonEmptyStrings(estateOpts.files)
	if len(wanted) == 0 {
		wanted = estateDefaultFiles
	}
	snapshot := estate.Snapshot{
		GeneratedAt: strings.TrimSpace(estateOpts.generatedAt),
		Files:       map[string][]byte{},
	}
	var missing []string
	for _, fileName := range wanted {
		path := fileName
		if !filepath.IsAbs(path) {
			path = filepath.Join(estateOpts.dir, fileName)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && len(estateOpts.files) == 0 {
				// Defaults are a convenience, not a contract: a fleet that has
				// not run `graph layers` yet should still be able to push what
				// it does have. An explicitly requested file is different — the
				// operator asked for it by name, so its absence is an error.
				missing = append(missing, fileName)
				continue
			}
			return fmt.Errorf("reading estate file %s: %w", path, err)
		}
		snapshot.Files[filepath.Base(fileName)] = body
	}
	if len(snapshot.Files) == 0 {
		return fmt.Errorf("no estate files found in %s (looked for %s); run `clearcutt-verify import observe` and `clearcutt-verify graph build` first",
			estateOpts.dir, strings.Join(wanted, ", "))
	}
	for _, fileName := range missing {
		fprintf(out, "[estate] %s not present; pushing without it\n", fileName)
	}

	digest, historyDigest, err := estateClient(ref, estateOpts.history).PushSnapshot(ref, estateOpts.history, snapshot)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(snapshot.Files))
	for fileName := range snapshot.Files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	fprintf(out, "[estate] pushed %d file(s) to %s\n", len(names), ref)
	for _, fileName := range names {
		fprintf(out, "[estate]   %s (%d bytes)\n", fileName, len(snapshot.Files[fileName]))
	}
	fprintf(out, "[estate] digest %s\n", digest)
	fprintf(out, "[estate] this digest is stable for identical content, so an unchanged estate re-pushes to the same version\n")
	if historyDigest != "" {
		metrics := estate.ExtractMetrics(snapshot)
		fprintf(out, "[estate] appended to history %s (%s)\n", estateOpts.history, historyDigest)
		fprintf(out, "[estate]   %s\n", metrics)
	}
	return nil
}

func newEstateHistoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history <reference>",
		Short: "Show how an estate changed over time",
		Long: `Read a history index and print the trend, once cosign has verified the
index's signature against the signers with role estate in a trust policy
(--trust-policy, or the one a verification policy names: --policy), or the
signer named with cosign's flags, as estate pull does: a job that appends to
the history (estate push --history) signs the index digest it prints. An
index nobody trusted signed is refused; --allow-unverified reads it anyway,
with a warning.

Reading a trend costs one manifest fetch regardless of how long the series is:
each run's metrics are carried in the index annotations, so no snapshot blobs
are pulled. Pull an individual snapshot by digest to drill into a date.`,
		Example: `  clearcutt-verify estate history ghcr.io/acme/estate:history --trust-policy trust.yaml`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEstateHistory(cmd.Context(), args[0])
		},
	}
	cmd.Flags().BoolVar(&estateOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	signerFlags(cmd.Flags(), "the history index")
	return cmd
}

func runEstateHistory(ctx context.Context, ref string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	signers, err := pullSigners()
	if err != nil {
		return err
	}
	if signers == nil && !estateOpts.allowUnverified {
		return noSignerError("estate history", "the history index it reads")
	}
	history, err := estateClient(ref).ReadHistory(ref)
	if err != nil {
		return err
	}
	pinned, err := pinnedRef(ref, history.Digest)
	if err != nil {
		return err
	}
	if signers == nil {
		warnUnverified(pinned, "no signer was named")
	} else {
		repo, _, _ := strings.Cut(pinned, "@")
		item, err := verifyArtifact(ctx, signers, ref, repo, history.Digest)
		if err != nil {
			return err
		}
		if item.Status != "verified" {
			why := fmt.Sprintf("its signature is %s: %s", item.Status, item.Detail)
			if !estateOpts.allowUnverified {
				return fmt.Errorf("refusing the history index %s: %s", pinned, why)
			}
			warnUnverified(pinned, why)
		} else {
			fprintf(out, "[estate] history index signature verified: %s\n", signerDescription(item.Signer))
		}
	}
	if len(history.Entries) == 0 {
		fprintf(out, "[estate] %s holds no snapshots yet\n", ref)
		return nil
	}
	if strings.EqualFold(GlobalOpts.Format, "json") {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(history)
	}

	fprintf(out, "%-22s  %6s  %8s  %6s  %6s  %8s\n", "GENERATED", "IMAGES", "RESOLVED", "PROVEN", "STALE", "COVERAGE")
	for _, entry := range history.Entries {
		generated := entry.GeneratedAt
		if generated == "" {
			generated = "(untimed)"
		}
		if len(generated) > 22 {
			generated = generated[:22]
		}
		fprintf(out, "%-22s  %6d  %8d  %6d  %6d  %7.0f%%\n",
			generated, entry.Metrics.Images, entry.Metrics.Resolved, entry.Metrics.Proven,
			entry.Metrics.Stale, entry.Metrics.Coverage()*100)
	}

	first, last, ok := history.Delta()
	if !ok {
		fprintf(out, "\n[estate] one snapshot so far; a trend needs at least two\n")
		return nil
	}
	fprintf(out, "\n[estate] over %d snapshots:\n", len(history.Entries))
	trend := func(label string, from, to int, higherIsBetter bool) {
		delta := to - from
		direction := "unchanged"
		switch {
		case delta > 0 && higherIsBetter, delta < 0 && !higherIsBetter:
			direction = "improved"
		case delta != 0:
			direction = "regressed"
		}
		fprintf(out, "[estate]   %-24s %4d -> %-4d  %+d (%s)\n", label, from, to, delta, direction)
	}
	trend("images observed", first.Metrics.Images, last.Metrics.Images, true)
	trend("provenance resolved", first.Metrics.Resolved, last.Metrics.Resolved, true)
	trend("proven by layer digests", first.Metrics.Proven, last.Metrics.Proven, true)
	trend("stale consumers", first.Metrics.Stale, last.Metrics.Stale, false)
	fprintf(out, "[estate]   %-24s %3.0f%% -> %.0f%%\n", "proof share of resolved",
		first.Metrics.ProvenShare()*100, last.Metrics.ProvenShare()*100)
	return nil
}

func runEstatePull(ctx context.Context, ref string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	signers, err := pullSigners()
	if err != nil {
		return err
	}
	verify := signers != nil
	if !verify && !estateOpts.allowUnverified {
		return noSignerError("estate pull", "what it pulls")
	}
	if verify {
		// The tools first: a missing cosign is an operational error, not an
		// unverified bundle.
		v := &estateverify.Verifier{Signers: signers, Cosign: estateOpts.cosignPath, Run: cosignRunner, TrustedRoot: estateOpts.trustedRoot, Timeout: GlobalOpts.CosignTimeout}
		if _, err := v.CheckCosign(ctx); err != nil {
			return err
		}
	}
	snapshot, digest, err := estateClient(ref).Pull(ref)
	if err != nil {
		// Nothing stored yet is the one failure a first run expects. Anything
		// else (credentials, network, a foreign artifact) must stop a job that
		// would otherwise start a new history and push it over the old one.
		if estateOpts.allowMissing && errors.Is(err, estate.ErrNotFound) {
			_, _ = fmt.Fprintf(out, "[estate] nothing at %s yet; nothing pulled\n", ref)
			return nil
		}
		return err
	}
	pinned, err := pinnedRef(ref, digest)
	if err != nil {
		return err
	}
	switch {
	case !verify:
		warnUnverified(pinned, "no signer was named")
	default:
		repo, _, _ := strings.Cut(pinned, "@")
		item, err := verifyArtifact(ctx, signers, ref, repo, digest)
		if err != nil {
			return err
		}
		if item.Status != "verified" {
			why := fmt.Sprintf("its signature is %s: %s", item.Status, item.Detail)
			if !estateOpts.allowUnverified {
				return fmt.Errorf("refusing %s, so nothing was written: %s", pinned, why)
			}
			warnUnverified(pinned, why)
			break
		}
		fprintf(out, "[estate] signature verified: %s\n", signerDescription(item.Signer))
	}
	if err := os.MkdirAll(estateOpts.output, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(snapshot.Files))
	for fileName := range snapshot.Files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	for _, fileName := range names {
		// The file name comes off a registry annotation, which is attacker
		// controllable. Take only the base name so a crafted artifact cannot
		// write outside the output directory.
		safe := filepath.Base(filepath.Clean(fileName))
		if safe == "." || safe == string(filepath.Separator) || safe == ".." {
			return fmt.Errorf("estate artifact contains an unusable file name %q", fileName)
		}
		path := filepath.Join(estateOpts.output, safe)
		if err := os.WriteFile(path, snapshot.Files[fileName], 0o644); err != nil {
			return err
		}
		fprintf(out, "[estate] wrote %s (%d bytes)\n", path, len(snapshot.Files[fileName]))
	}
	if snapshot.GeneratedAt != "" {
		fprintf(out, "[estate] snapshot generated at %s\n", snapshot.GeneratedAt)
	}
	fprintf(out, "[estate] pulled %s\n", digest)
	return nil
}

// pinnedRef is ref's repository at digest: what was pulled.
func pinnedRef(ref, digest string) (string, error) {
	opts := []name.Option{name.WeakValidation}
	if estateOpts.insecure {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return "", err
	}
	return r.Context().Name() + "@" + digest, nil
}

// signerDescription names a verified signer.
func signerDescription(s *report.Signer) string {
	switch {
	case s == nil:
		return "a trusted signer"
	case s.Key != "":
		return "key " + s.Key
	case s.SourceRepository != "":
		return s.Identity + " (" + s.Issuer + "), in " + s.SourceRepository
	}
	return s.Identity + " (" + s.Issuer + ")"
}

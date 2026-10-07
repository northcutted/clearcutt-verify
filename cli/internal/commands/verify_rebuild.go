package commands

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/certify"
	"github.com/spf13/cobra"
)

type verifyRebuildFlags struct {
	target                    string
	system                    string
	coreDir                   string
	expectedRef               string
	expectedDigest            string
	requireDigestMatch        bool
	provenanceFile            string
	sourceRepo                string
	sourceCommit              string
	checkoutDir               string
	rebuild                   bool
	nixAttr                   string
	outLink                   string
	rebuiltArchive            string
	registryArchive           string
	pullRegistryArchive       bool
	requireLayerMatch         bool
	diffoscopeOutput          string
	runtimeClosureFile        string
	graftedClosureFile        string
	requireClosureEquivalence bool
	outputPredicate           bool
}

type verifyRebuildDigestResult struct {
	ExpectedRef    string `json:"expectedRef,omitempty"`
	ExpectedDigest string `json:"expectedDigest,omitempty"`
	ResolvedDigest string `json:"resolvedDigest,omitempty"`
	Match          bool   `json:"match"`
}

type verifyRebuildClosureResult struct {
	RuntimeFile    string `json:"runtimeFile,omitempty"`
	GraftedFile    string `json:"graftedFile,omitempty"`
	RuntimeHash    string `json:"runtimeHash,omitempty"`
	GraftedHash    string `json:"graftedHash,omitempty"`
	RuntimePaths   int    `json:"runtimePaths"`
	GraftedPaths   int    `json:"graftedPaths"`
	Equivalent     bool   `json:"equivalent"`
	FirstDeltaPath string `json:"firstDeltaPath,omitempty"`
}

type verifyRebuildProvenanceResult struct {
	File          string `json:"file,omitempty"`
	Type          string `json:"type,omitempty"`
	PredicateType string `json:"predicateType,omitempty"`
	SubjectName   string `json:"subjectName,omitempty"`
	SubjectDigest string `json:"subjectDigest,omitempty"`
	SourceRepo    string `json:"sourceRepo,omitempty"`
	SourceCommit  string `json:"sourceCommit,omitempty"`
}

type verifyRebuildBuildResult struct {
	SourceRepo     string `json:"sourceRepo,omitempty"`
	SourceCommit   string `json:"sourceCommit,omitempty"`
	CheckoutDir    string `json:"checkoutDir,omitempty"`
	BuildDir       string `json:"buildDir,omitempty"`
	NixAttr        string `json:"nixAttr,omitempty"`
	OutLink        string `json:"outLink,omitempty"`
	RebuiltArchive string `json:"rebuiltArchive,omitempty"`
	Ran            bool   `json:"ran"`
}

type verifyRebuildLayerResult struct {
	RebuiltArchive       string   `json:"rebuiltArchive,omitempty"`
	RegistryArchive      string   `json:"registryArchive,omitempty"`
	RebuiltLayerDigests  []string `json:"rebuiltLayerDigests,omitempty"`
	RegistryLayerDigests []string `json:"registryLayerDigests,omitempty"`
	Match                bool     `json:"match"`
	FirstDelta           string   `json:"firstDelta,omitempty"`
	DiffoscopeOutput     string   `json:"diffoscopeOutput,omitempty"`
}

type verifyRebuildSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type verifyRebuildPredicate struct {
	Type          string                         `json:"_type,omitempty"`
	PredicateType string                         `json:"predicateType"`
	Subject       []verifyRebuildSubject         `json:"subject,omitempty"`
	GeneratedAt   string                         `json:"generatedAt"`
	Status        string                         `json:"status"`
	Target        string                         `json:"target"`
	System        string                         `json:"system"`
	Checks        []VerifyCheckResult            `json:"checks"`
	Digest        *verifyRebuildDigestResult     `json:"digest,omitempty"`
	Provenance    *verifyRebuildProvenanceResult `json:"provenance,omitempty"`
	Build         *verifyRebuildBuildResult      `json:"build,omitempty"`
	Layers        *verifyRebuildLayerResult      `json:"layers,omitempty"`
	Closure       *verifyRebuildClosureResult    `json:"closure,omitempty"`
}

var verifyRebuildOpts verifyRebuildFlags

func NewVerifyRebuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rebuild [image-ref]",
		Short: "Verify reproducible rebuild evidence for a published image",
		Long: `Checks a bounded rebuild predicate before it is promoted into release
evidence. The command can resolve a published reference with crane, parse local
SLSA/in-toto provenance or download it from the image ref with Cosign, recover
the pinned source commit, optionally check out and rebuild that commit with Nix,
and compare rebuilt image layer digests against a registry archive. It does not
publish, sign, or mutate registry state.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && verifyRebuildOpts.expectedRef == "" {
				verifyRebuildOpts.expectedRef = args[0]
			}
			return runVerifyRebuild()
		},
	}

	f := cmd.Flags()
	f.StringVar(&verifyRebuildOpts.target, "target", "", "ClearCutt target id, for example java21-distroless (required)")
	f.StringVar(&verifyRebuildOpts.system, "system", "x86_64-linux", "Nix system the rebuild predicate applies to")
	f.StringVar(&verifyRebuildOpts.coreDir, "core-dir", "core", "Path to the ClearCutt core flake directory")
	f.StringVar(&verifyRebuildOpts.expectedRef, "expected-ref", "", "Published image reference to resolve with crane digest")
	f.StringVar(&verifyRebuildOpts.expectedDigest, "expected-digest", "", "Expected digest in sha256:... form")
	f.BoolVar(&verifyRebuildOpts.requireDigestMatch, "require-digest-match", false, "Fail unless --expected-ref resolves to --expected-digest")
	f.StringVar(&verifyRebuildOpts.provenanceFile, "provenance-file", "", "Local SLSA/in-toto provenance statement to parse instead of downloading from the image ref")
	f.StringVar(&verifyRebuildOpts.sourceRepo, "source-repo", "", "Git repository URL to rebuild; overrides provenance source repo")
	f.StringVar(&verifyRebuildOpts.sourceCommit, "source-commit", "", "Git commit SHA to rebuild; overrides provenance source commit")
	f.StringVar(&verifyRebuildOpts.checkoutDir, "checkout-dir", "", "Directory for the pinned source checkout; created when absent")
	f.BoolVar(&verifyRebuildOpts.rebuild, "rebuild", false, "Check out the pinned source commit and run nix build")
	f.StringVar(&verifyRebuildOpts.nixAttr, "nix-attr", "", "Nix flake attribute to build (default .#<target>)")
	f.StringVar(&verifyRebuildOpts.outLink, "out-link", "", "Nix build --out-link path for the rebuilt image archive")
	f.StringVar(&verifyRebuildOpts.rebuiltArchive, "rebuilt-archive", "", "Rebuilt image archive to compare, docker-save or OCI-layout")
	f.StringVar(&verifyRebuildOpts.registryArchive, "registry-archive", "", "Registry image archive to compare, docker-save or OCI-layout")
	f.BoolVar(&verifyRebuildOpts.pullRegistryArchive, "pull-registry-archive", false, "Use crane pull --format=oci to create --registry-archive from the published ref")
	f.BoolVar(&verifyRebuildOpts.requireLayerMatch, "require-layer-match", false, "Fail unless rebuilt and registry archive layer digests match exactly")
	f.StringVar(&verifyRebuildOpts.diffoscopeOutput, "diffoscope-out", "", "Write diffoscope output here when layer digests differ")
	f.StringVar(&verifyRebuildOpts.runtimeClosureFile, "runtime-closure-file", "", "File containing one runtime Nix store path per line")
	f.StringVar(&verifyRebuildOpts.graftedClosureFile, "grafted-closure-file", "", "File containing one grafted image Nix store path per line")
	f.BoolVar(&verifyRebuildOpts.requireClosureEquivalence, "require-closure-equivalence", false, "Fail unless runtime and grafted closure files normalize to the same paths")
	f.BoolVar(&verifyRebuildOpts.outputPredicate, "output-predicate", false, "Emit the verification predicate as JSON")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func runVerifyRebuild() error {
	o := verifyRebuildOpts
	if o.expectedRef == "" && o.expectedDigest == "" && o.provenanceFile == "" && !o.rebuild && o.rebuiltArchive == "" && o.registryArchive == "" && o.runtimeClosureFile == "" && o.graftedClosureFile == "" {
		return fmt.Errorf("provide an image ref, --expected-digest, --provenance-file, --rebuild, archives, or closure files to verify")
	}
	if o.requireLayerMatch && o.rebuiltArchive == "" && !o.rebuild {
		return fmt.Errorf("--require-layer-match requires --rebuilt-archive or --rebuild")
	}
	if o.requireLayerMatch && o.registryArchive == "" && !o.pullRegistryArchive {
		return fmt.Errorf("--require-layer-match requires --registry-archive or --pull-registry-archive")
	}
	if o.requireClosureEquivalence && (o.runtimeClosureFile == "" || o.graftedClosureFile == "") {
		return fmt.Errorf("--require-closure-equivalence requires --runtime-closure-file and --grafted-closure-file")
	}
	compareLayers := o.rebuiltArchive != "" || o.registryArchive != "" || o.pullRegistryArchive || o.requireLayerMatch

	predicate := verifyRebuildPredicate{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://clearcutt.dev/predicate/rebuild/v1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        "pass",
		Target:        o.target,
		System:        o.system,
		Checks:        []VerifyCheckResult{},
	}
	hasFailure := false
	addCheck := func(id, status, message string) {
		predicate.Checks = append(predicate.Checks, VerifyCheckResult{ID: id, Status: status, Message: message})
		if status == "fail" {
			hasFailure = true
			predicate.Status = "fail"
		}
		// Structured output modes (--output-predicate, --format json|yaml) own
		// stdout; only the human table mode streams per-check progress lines.
		if !o.outputPredicate && !structuredFormat() {
			fmt.Fprintf(out, "[rebuild] %s: %s\n", status, message)
		}
	}

	var cleanup []string
	defer func() {
		for _, path := range cleanup {
			_ = os.RemoveAll(path)
		}
	}()

	var prov *verifyRebuildProvenanceResult
	if o.provenanceFile != "" {
		loaded, err := readRebuildProvenance(o.provenanceFile)
		if err != nil {
			return err
		}
		prov = loaded
	} else if shouldDownloadRebuildProvenance(o) {
		loaded, err := downloadRebuildProvenance(o.expectedRef, o.coreDir)
		if err != nil {
			return err
		}
		prov = loaded
		addCheck("provenance.download", "pass", fmt.Sprintf("downloaded SLSA provenance for %s", o.expectedRef))
	}
	if prov != nil {
		applyRebuildProvenance(&o, &predicate, prov)
		if prov.SourceRepo == "" || prov.SourceCommit == "" {
			addCheck("provenance.pinned_source", "fail", fmt.Sprintf("provenance %s does not identify both source repo and commit", prov.File))
		} else {
			addCheck("provenance.pinned_source", "pass", fmt.Sprintf("provenance pins %s at %s", prov.SourceRepo, prov.SourceCommit))
		}
	}
	if o.requireDigestMatch && (o.expectedRef == "" || o.expectedDigest == "") {
		return fmt.Errorf("--require-digest-match requires --expected-ref and --expected-digest, or a provenance subject with both")
	}
	if o.pullRegistryArchive && o.expectedRef == "" {
		return fmt.Errorf("--pull-registry-archive requires an image ref, --expected-ref, or a provenance subject name")
	}

	if o.expectedRef != "" {
		resolved, err := captureExternalOutput(externalCommand{
			Name: "crane",
			Args: []string{"digest", o.expectedRef},
			Dir:  o.coreDir,
		})
		if err != nil {
			return err
		}
		resolvedDigest := strings.TrimSpace(resolved)
		digest := &verifyRebuildDigestResult{
			ExpectedRef:    o.expectedRef,
			ExpectedDigest: o.expectedDigest,
			ResolvedDigest: resolvedDigest,
			Match:          o.expectedDigest == "" || resolvedDigest == o.expectedDigest,
		}
		predicate.Digest = digest
		if o.expectedDigest != "" && resolvedDigest != o.expectedDigest {
			addCheck("digest.match", "fail", fmt.Sprintf("digest mismatch for %s: got %s, expected %s", o.expectedRef, resolvedDigest, o.expectedDigest))
		} else if o.expectedDigest != "" {
			addCheck("digest.match", "pass", fmt.Sprintf("%s resolves to expected digest %s", o.expectedRef, resolvedDigest))
		} else {
			addCheck("digest.resolved", "pass", fmt.Sprintf("%s resolves to %s", o.expectedRef, resolvedDigest))
		}
	} else if o.expectedDigest != "" {
		predicate.Digest = &verifyRebuildDigestResult{ExpectedDigest: o.expectedDigest}
		addCheck("digest.expected", "pass", fmt.Sprintf("expected digest recorded: %s", o.expectedDigest))
	}

	if o.rebuild {
		build, tempPaths, err := runPinnedNixRebuild(o)
		cleanup = append(cleanup, tempPaths...)
		if err != nil {
			return err
		}
		o.rebuiltArchive = build.RebuiltArchive
		predicate.Build = build
		addCheck("rebuild.nix_build", "pass", fmt.Sprintf("rebuilt %s from %s", build.NixAttr, build.BuildDir))
	}

	if o.pullRegistryArchive {
		tempDir, err := os.MkdirTemp("", "clearcutt-registry-archive-*")
		if err != nil {
			return err
		}
		cleanup = append(cleanup, tempDir)
		o.registryArchive = filepath.Join(tempDir, "registry-image.tar")
		if _, err := captureExternalOutput(externalCommand{
			Name: "crane",
			Args: []string{"pull", "--format=oci", o.expectedRef, o.registryArchive},
			Dir:  o.coreDir,
		}); err != nil {
			return err
		}
		addCheck("registry.archive", "pass", fmt.Sprintf("pulled %s to %s", o.expectedRef, o.registryArchive))
	}

	if compareLayers {
		if o.rebuiltArchive == "" || o.registryArchive == "" {
			return fmt.Errorf("layer digest comparison requires both rebuilt and registry archives")
		}
		layers, err := compareRebuildLayers(o.rebuiltArchive, o.registryArchive)
		if err != nil {
			return err
		}
		predicate.Layers = layers
		if layers.Match {
			addCheck("layers.match", "pass", fmt.Sprintf("rebuilt and registry archives have matching ordered layers (%d layers)", len(layers.RebuiltLayerDigests)))
		} else {
			addCheck("layers.match", "fail", fmt.Sprintf("layer digest mismatch first-delta=%s", layers.FirstDelta))
			if o.diffoscopeOutput != "" {
				layers.DiffoscopeOutput = o.diffoscopeOutput
				if err := runDiffoscope(o.rebuiltArchive, o.registryArchive, o.diffoscopeOutput); err != nil {
					addCheck("diffoscope.output", "fail", fmt.Sprintf("diffoscope failed: %v", err))
				} else {
					addCheck("diffoscope.output", "pass", fmt.Sprintf("wrote diffoscope output to %s", o.diffoscopeOutput))
				}
			}
		}
	}

	if o.runtimeClosureFile != "" || o.graftedClosureFile != "" {
		if o.runtimeClosureFile == "" || o.graftedClosureFile == "" {
			return fmt.Errorf("closure equivalence requires both --runtime-closure-file and --grafted-closure-file")
		}
		runtimePaths, err := readNormalizedClosureFile(o.runtimeClosureFile)
		if err != nil {
			return err
		}
		graftedPaths, err := readNormalizedClosureFile(o.graftedClosureFile)
		if err != nil {
			return err
		}
		nonempty := len(runtimePaths) > 0 && len(graftedPaths) > 0
		runtimeHash := hashClosure(runtimePaths)
		graftedHash := hashClosure(graftedPaths)
		equivalent := nonempty && reflect.DeepEqual(runtimePaths, graftedPaths)
		closure := &verifyRebuildClosureResult{
			RuntimeFile:  o.runtimeClosureFile,
			GraftedFile:  o.graftedClosureFile,
			RuntimeHash:  runtimeHash,
			GraftedHash:  graftedHash,
			RuntimePaths: len(runtimePaths),
			GraftedPaths: len(graftedPaths),
			Equivalent:   equivalent,
		}
		if !nonempty {
			addCheck("closure.nonempty", "fail", fmt.Sprintf("closure files must not be empty: runtime=%d grafted=%d", len(runtimePaths), len(graftedPaths)))
		} else if !equivalent {
			closure.FirstDeltaPath = firstClosureDelta(runtimePaths, graftedPaths)
			addCheck("closure.equivalent", "fail", fmt.Sprintf("closure mismatch: runtime=%s grafted=%s first-delta=%s", runtimeHash, graftedHash, closure.FirstDeltaPath))
		} else {
			addCheck("closure.equivalent", "pass", fmt.Sprintf("runtime and grafted closures match (%d paths, %s)", len(runtimePaths), runtimeHash))
		}
		predicate.Closure = closure
	}

	switch {
	case o.outputPredicate:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(predicate); err != nil {
			return err
		}
	case structuredFormat():
		// The rebuild predicate already carries the standard status + checks
		// shape, so --format json|yaml emits it directly.
		if err := printStructured(predicate); err != nil {
			return err
		}
	case !hasFailure:
		fmt.Fprintf(out, "[rebuild] complete: %s (%s)\n", o.target, o.system)
	}

	if hasFailure {
		return ErrCheckFailed
	}
	return nil
}

func runPinnedNixRebuild(o verifyRebuildFlags) (*verifyRebuildBuildResult, []string, error) {
	var cleanup []string
	nixAttr := o.nixAttr
	if strings.TrimSpace(nixAttr) == "" {
		nixAttr = ".#" + o.target
	}
	outLink := o.outLink
	if strings.TrimSpace(outLink) == "" {
		tempDir, err := os.MkdirTemp("", "clearcutt-rebuild-out-*")
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = append(cleanup, tempDir)
		outLink = filepath.Join(tempDir, "rebuilt-image.tar")
	}

	buildDir := o.coreDir
	checkoutDir := o.checkoutDir
	if o.sourceRepo != "" || o.sourceCommit != "" {
		if o.sourceRepo == "" || o.sourceCommit == "" {
			return nil, cleanup, fmt.Errorf("--rebuild with pinned source requires both source repo and source commit")
		}
		if checkoutDir == "" {
			tempDir, err := os.MkdirTemp("", "clearcutt-rebuild-src-*")
			if err != nil {
				return nil, cleanup, err
			}
			cleanup = append(cleanup, tempDir)
			checkoutDir = filepath.Join(tempDir, "src")
		}
		if _, err := os.Stat(checkoutDir); os.IsNotExist(err) {
			if _, err := captureExternalOutput(externalCommand{Name: "git", Args: []string{"clone", o.sourceRepo, checkoutDir}}); err != nil {
				return nil, cleanup, err
			}
		}
		if _, err := captureExternalOutput(externalCommand{Name: "git", Args: []string{"fetch", "--depth", "1", "origin", o.sourceCommit}, Dir: checkoutDir}); err != nil {
			return nil, cleanup, err
		}
		if _, err := captureExternalOutput(externalCommand{Name: "git", Args: []string{"checkout", "--detach", o.sourceCommit}, Dir: checkoutDir}); err != nil {
			return nil, cleanup, err
		}
		buildDir = filepath.Join(checkoutDir, "core")
	}

	if _, err := captureExternalOutput(externalCommand{
		Name: "nix",
		Args: []string{"--extra-experimental-features", "nix-command flakes", "build", nixAttr, "--out-link", outLink},
		Dir:  buildDir,
	}); err != nil {
		return nil, cleanup, err
	}

	return &verifyRebuildBuildResult{
		SourceRepo:     o.sourceRepo,
		SourceCommit:   o.sourceCommit,
		CheckoutDir:    checkoutDir,
		BuildDir:       buildDir,
		NixAttr:        nixAttr,
		OutLink:        outLink,
		RebuiltArchive: outLink,
		Ran:            true,
	}, cleanup, nil
}

func compareRebuildLayers(rebuiltArchive, registryArchive string) (*verifyRebuildLayerResult, error) {
	rebuilt, err := imageLayerBlobDigests(rebuiltArchive)
	if err != nil {
		return nil, fmt.Errorf("read rebuilt archive layers: %w", err)
	}
	registry, err := imageLayerBlobDigests(registryArchive)
	if err != nil {
		return nil, fmt.Errorf("read registry archive layers: %w", err)
	}
	match := reflect.DeepEqual(rebuilt, registry) && len(rebuilt) > 0
	return &verifyRebuildLayerResult{
		RebuiltArchive:       rebuiltArchive,
		RegistryArchive:      registryArchive,
		RebuiltLayerDigests:  rebuilt,
		RegistryLayerDigests: registry,
		Match:                match,
		FirstDelta:           firstClosureDelta(rebuilt, registry),
	}, nil
}

func imageLayerBlobDigests(archive string) ([]string, error) {
	tempDir, err := os.MkdirTemp("", "clearcutt-layer-digest-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	img, err := certify.LoadImageArchive(archive, tempDir)
	if err != nil {
		return nil, err
	}
	if img.Format == "" {
		return nil, fmt.Errorf("unsupported image archive format")
	}
	if len(img.LayerPaths) == 0 {
		return nil, fmt.Errorf("image archive contains no resolved layers")
	}
	digests := make([]string, 0, len(img.LayerPaths))
	for _, layer := range img.LayerPaths {
		digest, err := fileSHA256(layer)
		if err != nil {
			return nil, err
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func runDiffoscope(left, right, outputPath string) error {
	args := []string{}
	if strings.HasSuffix(outputPath, ".html") || strings.HasSuffix(outputPath, ".htm") {
		args = append(args, "--html", outputPath)
	} else {
		args = append(args, "--text", outputPath)
	}
	args = append(args, left, right)
	_, err := captureExternalOutput(externalCommand{Name: "diffoscope", Args: args})
	if err != nil {
		if info, statErr := os.Stat(outputPath); statErr == nil && info.Size() > 0 {
			return nil
		}
	}
	return err
}

func shouldDownloadRebuildProvenance(o verifyRebuildFlags) bool {
	if o.expectedRef == "" {
		return false
	}
	if o.rebuild && (o.sourceRepo == "" || o.sourceCommit == "") {
		return true
	}
	if o.requireDigestMatch && o.expectedDigest == "" {
		return true
	}
	return false
}

func downloadRebuildProvenance(ref, dir string) (*verifyRebuildProvenanceResult, error) {
	raw, err := captureExternalOutput(externalCommand{
		Name: "cosign",
		Args: []string{"download", "attestation", "--predicate-type", "https://slsa.dev/provenance/v1", ref},
		Dir:  dir,
	})
	if err != nil {
		return nil, err
	}
	return parseRebuildProvenance([]byte(raw), "cosign:"+ref)
}

func applyRebuildProvenance(o *verifyRebuildFlags, predicate *verifyRebuildPredicate, prov *verifyRebuildProvenanceResult) {
	predicate.Provenance = prov
	if prov.SubjectName != "" && prov.SubjectDigest != "" {
		if subject, ok := rebuildSubject(prov.SubjectName, prov.SubjectDigest); ok {
			predicate.Subject = []verifyRebuildSubject{subject}
		}
	}
	if o.expectedDigest == "" && prov.SubjectDigest != "" {
		o.expectedDigest = prov.SubjectDigest
	}
	if o.expectedRef == "" && prov.SubjectName != "" {
		o.expectedRef = prov.SubjectName
	}
	if o.sourceRepo == "" {
		o.sourceRepo = prov.SourceRepo
	}
	if o.sourceCommit == "" {
		o.sourceCommit = prov.SourceCommit
	}
}

func readRebuildProvenance(path string) (*verifyRebuildProvenanceResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provenance file %s: %w", path, err)
	}
	return parseRebuildProvenance(raw, path)
}

func parseRebuildProvenance(raw []byte, source string) (*verifyRebuildProvenanceResult, error) {
	candidates := rebuildJSONCandidates(raw)
	var lastErr error
	for _, candidate := range candidates {
		root, err := decodeRebuildProvenanceRoot(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		result := rebuildProvenanceFromRoot(root, source)
		if result.SourceCommit != "" || result.SubjectDigest != "" {
			return result, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("parse provenance %s: %w", source, lastErr)
	}
	return nil, fmt.Errorf("parse provenance %s: no SLSA/in-toto statement found", source)
}

func rebuildJSONCandidates(raw []byte) [][]byte {
	trimmed := bytes.TrimSpace(raw)
	candidates := [][]byte{}
	if len(trimmed) > 0 {
		candidates = append(candidates, trimmed)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) > 0 {
			copied := append([]byte(nil), line...)
			candidates = append(candidates, copied)
		}
	}
	return candidates
}

func decodeRebuildProvenanceRoot(raw []byte) (map[string]any, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if payload := rebuildString(root["payload"]); payload != "" {
		return decodeRebuildPayload(payload)
	}
	if envelope := rebuildMap(root["dsseEnvelope"]); len(envelope) > 0 {
		if payload := rebuildString(envelope["payload"]); payload != "" {
			return decodeRebuildPayload(payload)
		}
	}
	return root, nil
}

func decodeRebuildPayload(payload string) (map[string]any, error) {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(payload)
	}
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(decoded, &root); err != nil {
		return nil, err
	}
	return root, nil
}

func rebuildProvenanceFromRoot(root map[string]any, source string) *verifyRebuildProvenanceResult {
	result := &verifyRebuildProvenanceResult{
		File:          source,
		Type:          rebuildString(root["_type"]),
		PredicateType: rebuildString(root["predicateType"]),
	}
	if subjects, ok := root["subject"].([]any); ok && len(subjects) > 0 {
		if subject, ok := subjects[0].(map[string]any); ok {
			result.SubjectName = rebuildString(subject["name"])
			result.SubjectDigest = rebuildDigest(subject["digest"])
		}
	}
	result.SourceRepo, result.SourceCommit = rebuildSourceFromProvenance(root)
	return result
}

func rebuildSubject(name, digest string) (verifyRebuildSubject, bool) {
	algo, hexValue, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hexValue == "" {
		return verifyRebuildSubject{}, false
	}
	return verifyRebuildSubject{Name: name, Digest: map[string]string{algo: hexValue}}, true
}

func rebuildSourceFromProvenance(root map[string]any) (repo, commit string) {
	type candidate struct {
		repo   string
		commit string
	}
	candidates := []candidate{}
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			uri := rebuildString(v["uri"])
			if uri == "" {
				uri = rebuildString(v["repository"])
			}
			if uri == "" {
				uri = rebuildString(v["repo"])
			}
			if digest := rebuildMap(v["digest"]); len(digest) > 0 {
				commit := firstRebuildDigestValue(digest, "gitCommit", "sha1", "sha256")
				if commit != "" {
					candidates = append(candidates, candidate{repo: normalizeGitURI(uri), commit: commit})
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(root)
	for _, candidate := range candidates {
		if candidate.repo != "" && candidate.commit != "" {
			return candidate.repo, candidate.commit
		}
	}
	for _, candidate := range candidates {
		if candidate.commit != "" {
			return "", candidate.commit
		}
	}
	return "", ""
}

func normalizeGitURI(uri string) string {
	uri = strings.TrimSpace(uri)
	uri = strings.TrimPrefix(uri, "git+")
	if uri == "" {
		return ""
	}
	if at := strings.Index(uri, "@"); at > len("https://") {
		uri = uri[:at]
	}
	if strings.HasPrefix(uri, "git@github.com:") {
		path := strings.TrimPrefix(uri, "git@github.com:")
		return "https://github.com/" + strings.TrimSuffix(path, ".git")
	}
	return strings.TrimSuffix(uri, ".git")
}

func rebuildDigest(value any) string {
	digest := rebuildMap(value)
	if len(digest) == 0 {
		return ""
	}
	for _, preferred := range []string{"sha256", "sha1", "gitCommit"} {
		if got := rebuildString(digest[preferred]); got != "" {
			if strings.Contains(got, ":") {
				return got
			}
			return preferred + ":" + got
		}
	}
	keys := make([]string, 0, len(digest))
	for key := range digest {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if got := rebuildString(digest[key]); got != "" {
			if strings.Contains(got, ":") {
				return got
			}
			return key + ":" + got
		}
	}
	return ""
}

func firstRebuildDigestValue(digest map[string]any, keys ...string) string {
	for _, key := range keys {
		if got := rebuildString(digest[key]); got != "" {
			return strings.TrimPrefix(got, key+":")
		}
	}
	return ""
}

func rebuildMap(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return nil
}

func rebuildString(value any) string {
	if s, ok := value.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func readNormalizedClosureFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read closure file %s: %w", path, err)
	}
	defer f.Close()

	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		seen[line] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read closure file %s: %w", path, err)
	}

	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func hashClosure(paths []string) string {
	sum := sha256.Sum256([]byte(strings.Join(paths, "\n") + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func firstClosureDelta(left, right []string) string {
	max := len(left)
	if len(right) > max {
		max = len(right)
	}
	for i := 0; i < max; i++ {
		if i >= len(left) {
			return right[i]
		}
		if i >= len(right) {
			return left[i]
		}
		if left[i] != right[i] {
			if left[i] < right[i] {
				return left[i]
			}
			return right[i]
		}
	}
	return ""
}

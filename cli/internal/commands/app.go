package commands

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/oci"
	"github.com/spf13/cobra"
)

// newOCIClient is the registry-client seam. Production builds talk to real
// registries with ambient auth; tests swap this for an insecure in-memory client.
var newOCIClient = func() *oci.Client { return oci.NewClient() }

// NewAppCmd builds the `app` command group: the downstream application lifecycle
// (build an app onto a ClearCutt base, compare against a candidate base, and rebase
// onto a new base while preserving the application layers byte-for-byte).
//
// Unlike the rest of the CLI — which is offline catalog governance — these commands
// talk to a registry directly (still daemon-free). Signing is delegated to cosign.
func NewAppCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Build, compare, and rebase downstream application images",
		Long: `Manage the lifecycle of downstream application images built on ClearCutt bases.

These subcommands operate directly against an OCI registry (no Docker daemon or Nix
required) and are the only network-touching commands in the CLI:

  build      Lay a prebuilt artifact onto a ClearCutt base and push the app image.
  diff-base  Compare an app image or catalog base against a candidate base.
  rebase     Swap the base under an app image, preserving the app layers byte-for-byte,
             then sign and attest the result.`,
	}
	cmd.AddCommand(newAppBuildCmd())
	cmd.AddCommand(newAppDiffBaseCmd())
	cmd.AddCommand(newAppRebaseCmd())
	return cmd
}

// resolveBaseReference turns a --base argument into a pullable registry reference.
// A bare catalog id (e.g. java21-distroless) is resolved through the catalog to a
// digest-pinned reference; anything containing a registry path/tag/digest is used
// verbatim. It also returns the catalog id and version to stamp into labels.
func resolveBaseReference(baseArg, explicitVersion string) (ref, baseID, baseVersion string, err error) {
	if baseArg == "" {
		return "", "", "", fmt.Errorf("a base image is required")
	}
	if strings.ContainsAny(baseArg, "/@:") {
		// An explicit registry reference; we cannot infer a catalog id from it.
		return baseArg, "", explicitVersion, nil
	}

	rec, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, baseArg)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve base %q: %w", baseArg, err)
	}
	rel, err := latestOrTaggedRelease(rec.Releases, explicitVersion)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve base %q: %w", baseArg, err)
	}
	version := rel.Tag
	if rel.ManifestDigest != nil && *rel.ManifestDigest != "" {
		ref = rec.FullName + "@" + *rel.ManifestDigest
	} else {
		ref = rec.FullName + ":" + rec.Tier.ID + "-" + rel.Tag
	}
	return ref, baseArg, version, nil
}

var runtimeLineRe = regexp.MustCompile(`^([a-zA-Z]+)([0-9][0-9.]*)$`)

// parseRuntimeLine extracts the runtime family and major/minor version from a base
// id like "java21-distroless" -> ("java", 21, 0) or "python3.14-slim" -> ("python", 3, 14).
func parseRuntimeLine(id string) (runtime string, major, minor int, ok bool) {
	core := id
	if i := strings.LastIndex(id, "-"); i > 0 {
		core = id[:i]
	}
	if strings.EqualFold(core, "coreLTS") {
		return "core", 0, 0, true
	}
	m := runtimeLineRe.FindStringSubmatch(core)
	if m == nil {
		return "", 0, 0, false
	}
	runtime = strings.ToLower(m[1])
	parts := strings.SplitN(m[2], ".", 3)
	major, _ = strconv.Atoi(parts[0])
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return runtime, major, minor, true
}

// runtimeCompat implements the strict major/minor ABI gate: same runtime family and
// same major.minor line is allowed (a patch- or ClearCutt-version-only upgrade, the
// whole point of rebasing); a family change or any major/minor bump is blocked to
// avoid interpreter ABI drift / wheel incompatibilities.
func runtimeCompat(oldID, newID string) (ok bool, reason string) {
	or, oMaj, oMin, ok1 := parseRuntimeLine(oldID)
	nr, nMaj, nMin, ok2 := parseRuntimeLine(newID)
	if !ok1 || !ok2 {
		return false, fmt.Sprintf("cannot determine runtime line from base ids %q / %q", oldID, newID)
	}
	if or != nr {
		return false, fmt.Sprintf("runtime family changed: %s -> %s", or, nr)
	}
	if oMaj != nMaj || oMin != nMin {
		return false, fmt.Sprintf("runtime version line changed: %s -> %s (major/minor ABI drift risk)",
			versionLabel(or, oMaj, oMin), versionLabel(nr, nMaj, nMin))
	}
	return true, fmt.Sprintf("runtime %s preserved (patch/base-only upgrade)", versionLabel(or, oMaj, oMin))
}

func versionLabel(runtime string, major, minor int) string {
	if runtime == "core" && major == 0 && minor == 0 {
		return "coreLTS"
	}
	if minor == 0 {
		return fmt.Sprintf("%s%d", runtime, major)
	}
	return fmt.Sprintf("%s%d.%d", runtime, major, minor)
}

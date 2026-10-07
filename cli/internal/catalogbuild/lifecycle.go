package catalogbuild

import (
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/versionpolicy"
)

// Lifecycle mirrors the lifecycle object the Node producer emits.
type Lifecycle struct {
	Status            string  `json:"status"`
	Support           string  `json:"support"`
	ProductionAllowed bool    `json:"productionAllowed"`
	DeprecatedAt      *string `json:"deprecatedAt"`
	EOLAt             *string `json:"eolAt"`
	Reason            *string `json:"reason"`
}

// RuntimeContract mirrors the runtimeContract object the Node producer emits.
type RuntimeContract struct {
	User                  string  `json:"user"`
	WorkingDir            string  `json:"workingDir"`
	ShellPresent          bool    `json:"shellPresent"`
	PackageManagerPresent bool    `json:"packageManagerPresent"`
	CACertificatesPresent bool    `json:"caCertificatesPresent"`
	TimezoneDataPresent   bool    `json:"timezoneDataPresent"`
	DefaultEntrypoint     *string `json:"defaultEntrypoint"`
	ProductionTier        bool    `json:"productionTier"`
}

func Str(s string) *string { return &s }

// gatherLangKey strips the trailing tier segment from a target id, matching the
// `target.lastIndexOf('-')` split in gather-catalog.mjs.
func gatherLangKey(target string) string {
	if idx := strings.LastIndex(target, "-"); idx != -1 {
		return target[:idx]
	}
	return target
}

// determineLifecycle classifies a target's lifecycle from the shared version
// policy (core/lib/version-policy.json, mirrored into the versionpolicy
// package) rather than a hand-maintained switch, so the Go catalog builder and
// the Nix build stay aligned on one classification.
func determineLifecycle(target, tier string) Lifecycle {
	lc := versionpolicy.LifecycleFor(gatherLangKey(target), tier)
	return Lifecycle{
		Status:            lc.Status,
		Support:           lc.Support,
		ProductionAllowed: lc.ProductionAllowed,
	}
}

func determineRuntimeContract(target, tier string) RuntimeContract {
	langKey := gatherLangKey(target)

	var entrypoint *string
	switch {
	case strings.HasPrefix(langKey, "java"):
		entrypoint = Str("/usr/local/bin/java")
	case strings.HasPrefix(langKey, "node"):
		entrypoint = Str("/usr/bin/node")
	case strings.HasPrefix(langKey, "python"):
		entrypoint = Str("/usr/bin/python")
	case strings.HasPrefix(langKey, "go"):
		entrypoint = Str("/usr/bin/go")
	case strings.HasPrefix(langKey, "dotnet"):
		entrypoint = Str("/usr/bin/dotnet")
	case langKey == "coreLTS":
		entrypoint = Str("/bin/sh")
	}

	shellPresent, packageManagerPresent, productionTier := true, true, false
	switch tier {
	case "slim":
		shellPresent, packageManagerPresent, productionTier = true, false, true
	case "distroless":
		shellPresent, packageManagerPresent, productionTier = false, false, true
	default:
		shellPresent, packageManagerPresent, productionTier = true, true, false
	}

	return RuntimeContract{
		User:                  "10001",
		WorkingDir:            "/app",
		ShellPresent:          shellPresent,
		PackageManagerPresent: packageManagerPresent,
		CACertificatesPresent: true,
		TimezoneDataPresent:   true,
		DefaultEntrypoint:     entrypoint,
		ProductionTier:        productionTier,
	}
}

func defaultGatherExceptions() catalog.ExceptionSummary {
	return catalog.ExceptionSummary{}
}

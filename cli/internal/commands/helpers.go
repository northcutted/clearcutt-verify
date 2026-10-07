package commands

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/config"
)

// Small shared helpers that outlived the remediation subsystem they were written
// for. They are used by catalog build/enrich, scan, verify, and evidence
// manifesting, none of which have anything to do with CVE patching.

// firstNonEmpty returns the first non-empty value.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// fallbackString returns value, or fallback when value is empty.
func fallbackString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// envIntValue reads an integer from the environment, falling back on absent or
// unparseable values rather than failing: these tune batch sizes, and a typo in a
// workflow variable should not break a catalog build.
func envIntValue(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

// fixedVersionString takes the first version from a scanner's comma-separated
// "fixed in" field, which lists every fixing version across affected branches.
func fixedVersionString(value *string) string {
	if value == nil {
		return ""
	}
	parts := strings.SplitN(*value, ",", 2)
	return strings.TrimSpace(parts[0])
}

// findingHasFix reports whether a scanner finding names any fixing version.
func findingHasFix(fixedIn *string) bool {
	return fixedVersionString(fixedIn) != ""
}

// productionTier reports whether a tier is production-facing under the policy.
func productionTier(policy config.RemediationPolicy, tier string) bool {
	policy = config.EffectiveRemediationPolicy(policy)
	for _, item := range policy.ProductionTiers {
		if item == tier {
			return item == tier
		}
	}
	return false
}

// remediationPolicyFromJSON parses a policy blob, falling back to the default on
// anything malformed. Callers use it to interpret scanner thresholds, so a bad blob
// should degrade to the documented defaults rather than fail the gate open.
func remediationPolicyFromJSON(raw string) config.RemediationPolicy {
	if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "null" {
		return config.DefaultRemediationPolicy()
	}
	var policy config.RemediationPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		return config.DefaultRemediationPolicy()
	}
	return config.EffectiveRemediationPolicy(policy)
}

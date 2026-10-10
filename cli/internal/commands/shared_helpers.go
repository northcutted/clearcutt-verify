package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// registryDestCredentialPair reads registry credentials from the environment
// (REGISTRY_*, CLEARCUTT_REGISTRY_*, or GitHub Actions' own).
func registryDestCredentialPair() (string, string) {
	user := firstNonEmptyString(os.Getenv("REGISTRY_USER"), os.Getenv("CLEARCUTT_REGISTRY_USER"), os.Getenv("GITHUB_ACTOR"))
	token := firstNonEmptyString(os.Getenv("REGISTRY_TOKEN"), os.Getenv("CLEARCUTT_REGISTRY_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	return user, token
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// nonEmptyStrings drops blank entries and surrounding space.
func nonEmptyStrings(values []string) []string {
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// writeJSONFile writes value as indented JSON, creating the directory.
func writeJSONFile(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

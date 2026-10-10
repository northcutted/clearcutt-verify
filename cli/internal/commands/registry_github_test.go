package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryScanGitHubOrg(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/acme/packages":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "apps/checkout"}, {"name": "stacks/go"}})
		case strings.HasPrefix(r.URL.Path, "/orgs/acme/packages/container/"):
			_ = json.NewEncoder(w).Encode([]map[string]any{{"metadata": map[string]any{"container": map[string]any{"tags": []string{"1.0.0", "latest"}}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_TOKEN", "ghs_test")

	dir := t.TempDir()
	out, refs := filepath.Join(dir, "images.yaml"), filepath.Join(dir, "refs.txt")
	if stdout, err := runCLI(t, "registry", "scan", "--github-org", "acme", "--package-prefix", "apps/", "--output", out, "--refs-output", refs); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	raw, _ := os.ReadFile(refs)
	if got := strings.TrimSpace(string(raw)); !strings.Contains(got, "ghcr.io/acme/apps/checkout:1.0.0") || strings.Contains(got, "stacks/go") {
		t.Errorf("refs:\n%s", got)
	}
	for _, bad := range [][]string{
		{"registry", "scan", "--output", filepath.Join(dir, "x.yaml")},
		{"registry", "scan", "--github-org", "acme", "--registry", "docker.io", "--output", filepath.Join(dir, "y.yaml")},
		{"registry", "scan", "--registry", "ghcr.io", "--package-prefix", "apps/", "--output", filepath.Join(dir, "z.yaml")},
	} {
		if _, err := runCLI(t, bad...); err == nil {
			t.Errorf("%v: want an error", bad[2:])
		}
	}
}

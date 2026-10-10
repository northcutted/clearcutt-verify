package registryscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitHub serves the Packages API for one user (not an organization),
// with the apps/checkout package's versions split over two pages.
func fakeGitHub(t *testing.T) *httptest.Server {
	t.Helper()
	versions := []map[string]any{}
	for i := 0; i < 101; i++ {
		tags := []string{}
		if i == 0 {
			tags = []string{"latest", "1.2.0"}
		} else if i == 1 {
			tags = []string{"sha256-abc.sig"}
		}
		versions = append(versions, map[string]any{"metadata": map[string]any{"container": map[string]any{"tags": tags}}})
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		page := r.URL.Query().Get("page")
		switch r.URL.Path {
		case "/orgs/Acme/packages":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)
		case "/users/Acme/packages":
			if r.URL.Query().Get("package_type") != "container" {
				t.Errorf("package_type %q", r.URL.Query().Get("package_type"))
			}
			_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "apps/checkout"}, {"name": "stacks/go"}, {"name": "platform/run-go"}})
		case "/users/Acme/packages/container/apps%2Fcheckout/versions", "/users/Acme/packages/container/apps/checkout/versions":
			if page == "1" {
				_ = json.NewEncoder(w).Encode(versions[:100])
			} else {
				_ = json.NewEncoder(w).Encode(versions[100:])
			}
		default:
			t.Errorf("unexpected request %s", r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestGitHubPackages(t *testing.T) {
	srv := fakeGitHub(t)
	defer srv.Close()
	g := &GitHubPackages{Owner: "Acme", Prefixes: []string{"apps/", "platform/"}, Token: "ghs_test", API: srv.URL}
	repos, err := g.Repositories(context.Background(), "ghcr.io")
	if err != nil || strings.Join(repos, ",") != "acme/apps/checkout,acme/platform/run-go" {
		t.Fatalf("repositories %v, %v", repos, err)
	}
	tags, err := g.Tags(context.Background(), "ghcr.io/acme/apps/checkout")
	if err != nil || strings.Join(tags, ",") != "latest,1.2.0,sha256-abc.sig" {
		t.Fatalf("tags %v, %v", tags, err)
	}

	// Scan keeps images, not cosign sidecar tags.
	res, err := Scan(context.Background(), g, Options{Registry: "ghcr.io", Namespace: "acme", Repositories: []string{"acme/apps/checkout"}, MaxTagsPerRepo: 10})
	if err != nil || len(res.Refs) != 2 || strings.Contains(strings.Join(res.Refs, ","), ".sig") {
		t.Errorf("scan refs %v, %v", res.Refs, err)
	}

	if _, err := (&GitHubPackages{Owner: "Acme", API: srv.URL, Token: "wrong"}).Repositories(context.Background(), "ghcr.io"); err == nil || !strings.Contains(err.Error(), "packages: read") {
		t.Errorf("unauthorized: %v", err)
	}
	if _, err := g.Repositories(context.Background(), "docker.io"); err == nil {
		t.Error("listed GitHub packages for docker.io")
	}
	if _, err := g.Tags(context.Background(), "ghcr.io/other/x"); err == nil {
		t.Error("listed another owner's package")
	}
}

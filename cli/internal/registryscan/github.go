package registryscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// GitHubPackages lists the container packages an organization or user
// publishes to ghcr.io through the GitHub Packages API: ghcr.io has no
// _catalog endpoint, so this is how a namespace is enumerated without
// naming every repository.
type GitHubPackages struct {
	// Owner is the organization or user, e.g. acme.
	Owner string
	// Prefixes keeps only packages whose name starts with one of them,
	// e.g. apps/ (default: all).
	Prefixes []string
	// Token authenticates (packages: read); default GITHUB_TOKEN.
	Token string
	// API is the REST API base (default GITHUB_API_URL, else
	// https://api.github.com).
	API    string
	Client *http.Client

	ownerKind string // orgs or users, once known
}

const ghcrHost = "ghcr.io"

// Repositories returns ghcr.io/<owner>/<package> paths (without the host),
// as the registry names them.
func (g *GitHubPackages) Repositories(ctx context.Context, registry string) ([]string, error) {
	if registry != ghcrHost {
		return nil, fmt.Errorf("GitHub packages are served from %s, not %s", ghcrHost, registry)
	}
	var out []string
	for _, kind := range []string{"orgs", "users"} {
		var pkgs []struct {
			Name string `json:"name"`
		}
		err := g.pages(ctx, fmt.Sprintf("/%s/%s/packages?package_type=container", kind, url.PathEscape(g.Owner)), func(raw []byte) (int, error) {
			var page []struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			pkgs = append(pkgs, page...)
			return len(page), nil
		})
		if isStatus(err, http.StatusNotFound) && kind == "orgs" {
			continue // a user, not an organization
		}
		if err != nil {
			return nil, err
		}
		g.ownerKind = kind
		for _, p := range pkgs {
			if g.keep(p.Name) {
				out = append(out, strings.ToLower(g.Owner)+"/"+p.Name)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("no organization or user %q on GitHub", g.Owner)
}

// Tags returns the tags of one ghcr.io repository from its package versions.
func (g *GitHubPackages) Tags(ctx context.Context, repository string) ([]string, error) {
	path := strings.TrimPrefix(repository, ghcrHost+"/")
	owner, name, ok := strings.Cut(path, "/")
	if !ok || !strings.EqualFold(owner, g.Owner) {
		return nil, fmt.Errorf("%s is not a package of %s", repository, g.Owner)
	}
	kind := g.ownerKind
	if kind == "" {
		kind = "orgs"
	}
	var tags []string
	err := g.pages(ctx, fmt.Sprintf("/%s/%s/packages/container/%s/versions?", kind, url.PathEscape(g.Owner), url.PathEscape(name)), func(raw []byte) (int, error) {
		var page []struct {
			Metadata struct {
				Container struct {
					Tags []string `json:"tags"`
				} `json:"container"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return 0, err
		}
		for _, v := range page {
			tags = append(tags, v.Metadata.Container.Tags...)
		}
		return len(page), nil
	})
	return tags, err
}

func (g *GitHubPackages) keep(name string) bool {
	if len(g.Prefixes) == 0 {
		return true
	}
	for _, p := range g.Prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// pages fetches path page by page (100 at a time) until a short page.
func (g *GitHubPackages) pages(ctx context.Context, path string, each func([]byte) (int, error)) error {
	api := strings.TrimSuffix(firstNonEmpty(g.API, os.Getenv("GITHUB_API_URL"), "https://api.github.com"), "/")
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}
	token := firstNonEmpty(g.Token, os.Getenv("GITHUB_TOKEN"))
	sep := "&"
	if strings.HasSuffix(path, "?") {
		sep = ""
	}
	for page := 1; ; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s%sper_page=100&page=%d", api, path, sep, page), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return &statusError{code: resp.StatusCode, body: strings.TrimSpace(string(raw))}
		}
		n, err := each(raw)
		if err != nil {
			return err
		}
		if n < 100 {
			return nil
		}
	}
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	hint := ""
	if e.code == http.StatusUnauthorized || e.code == http.StatusForbidden {
		hint = " (the GitHub Packages API needs a token with packages: read, in GITHUB_TOKEN)"
	}
	return fmt.Sprintf("GitHub API: %d %s%s", e.code, e.body, hint)
}

func isStatus(err error, code int) bool {
	se, ok := err.(*statusError)
	return ok && se.code == code
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

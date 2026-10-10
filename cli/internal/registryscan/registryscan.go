// Package registryscan enumerates an OCI registry namespace into a deterministic
// list of image references.
//
// It exists because every other governance path in ClearCutt starts from a list of
// refs that a human had to write by hand. Pointing the CLI at a registry and letting
// it discover what is actually published is the difference between "govern the images
// you remembered to list" and "govern the images you actually have".
//
// Enumeration is behind a Lister seam so the scan logic is testable without a
// registry. The real implementation talks the distribution protocol directly via
// go-containerregistry, so it needs no Docker daemon.
package registryscan

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/registryauth"
)

const (
	// APIVersion matches the rest of the imported-fleet data model.
	APIVersion = "clearcutt.dev/v1"
	// Kind names the artifact this package emits.
	Kind = "RegistryScan"

	defaultMaxTagsPerRepo = 25
)

// sidecarTagSuffixes are the tag shapes Sigstore/GitHub attach alongside a real
// image (cosign signatures, attestations, SBOM references). They are addressed as
// `sha256-<digest>.sig` style tags and are evidence *about* an image, never an image
// a workload runs. Enumerating them as fleet members would swamp every report, so
// they are excluded unless the caller explicitly asks for them.
var sidecarTagSuffixes = []string{".sig", ".att", ".sbom", ".atts"}

// Lister enumerates repositories and tags. The seam keeps Scan hermetic in tests.
type Lister interface {
	// Repositories returns every repository path the registry will disclose.
	Repositories(ctx context.Context, registry string) ([]string, error)
	// Tags returns the tags for one fully-qualified repository.
	Tags(ctx context.Context, repository string) ([]string, error)
}

// Options configures a scan.
type Options struct {
	// Registry is the registry host, e.g. "ghcr.io".
	Registry string
	// Namespace filters discovered repositories to this path prefix, e.g.
	// "northcutted/clearcutt". Required when the registry catalog is broad.
	Namespace string
	// Repositories, when set, skips catalog enumeration entirely and scans exactly
	// these repository paths. Registries that do not implement the `_catalog`
	// endpoint (GHCR among them) need this.
	Repositories []string
	// TagPatterns are shell globs a tag must match to be selected. Empty means all.
	TagPatterns []string
	// ExcludeTagPatterns are shell globs that reject a tag even if it matched.
	ExcludeTagPatterns []string
	// MaxTagsPerRepo caps how many tags are selected per repository, newest-sorting
	// last so the cap keeps the highest-sorting tags. Zero applies the default.
	MaxTagsPerRepo int
	// IncludeSidecarTags keeps cosign/attestation sidecar tags in the result.
	IncludeSidecarTags bool
	// GeneratedAt pins the timestamp for reproducible output.
	GeneratedAt string
}

// Result is the deterministic record of one scan.
type Result struct {
	APIVersion   string       `json:"apiVersion"`
	Kind         string       `json:"kind"`
	GeneratedAt  string       `json:"generatedAt"`
	Registry     string       `json:"registry"`
	Namespace    string       `json:"namespace,omitempty"`
	Repositories []Repository `json:"repositories"`
	Refs         []string     `json:"refs"`
	Summary      Summary      `json:"summary"`
	Warnings     []string     `json:"warnings"`
}

// Repository is one discovered repository and the tags selected from it.
type Repository struct {
	Name         string   `json:"name"`
	TagsTotal    int      `json:"tagsTotal"`
	TagsSelected []string `json:"tagsSelected"`
	Truncated    bool     `json:"truncated,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// Summary is the headline count set for a scan.
type Summary struct {
	RepositoriesDiscovered int `json:"repositoriesDiscovered"`
	RepositoriesScanned    int `json:"repositoriesScanned"`
	RepositoriesFailed     int `json:"repositoriesFailed"`
	TagsDiscovered         int `json:"tagsDiscovered"`
	TagsSelected           int `json:"tagsSelected"`
	SidecarTagsSkipped     int `json:"sidecarTagsSkipped"`
}

// Scan enumerates the registry and returns the refs worth governing.
//
// A repository that fails to list is recorded as a warning rather than aborting the
// scan: a partial inventory of a large estate is useful, and a hard failure on one
// unreadable repository would make the command unusable against real registries
// where permissions are uneven.
func Scan(ctx context.Context, lister Lister, opts Options) (Result, error) {
	registry := strings.TrimSpace(opts.Registry)
	if registry == "" {
		return Result{}, fmt.Errorf("registry scan requires a registry host")
	}
	if lister == nil {
		return Result{}, fmt.Errorf("registry scan requires a lister")
	}
	generatedAt := opts.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	namespace := strings.Trim(strings.TrimSpace(opts.Namespace), "/")
	maxTags := opts.MaxTagsPerRepo
	if maxTags <= 0 {
		maxTags = defaultMaxTagsPerRepo
	}

	result := Result{
		APIVersion:   APIVersion,
		Kind:         Kind,
		GeneratedAt:  generatedAt,
		Registry:     registry,
		Namespace:    namespace,
		Repositories: []Repository{},
		Refs:         []string{},
		Warnings:     []string{},
	}

	repos, err := discoverRepositories(ctx, lister, registry, namespace, opts.Repositories)
	if err != nil {
		return Result{}, err
	}
	result.Summary.RepositoriesDiscovered = len(repos)
	if len(repos) == 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("no repositories found under %s/%s", registry, namespace))
		return result, nil
	}

	seenRefs := map[string]struct{}{}
	for _, repo := range repos {
		entry := Repository{Name: repo, TagsSelected: []string{}}
		tags, err := lister.Tags(ctx, qualify(registry, repo))
		if err != nil {
			entry.Warnings = append(entry.Warnings, fmt.Sprintf("tag listing failed: %v", err))
			result.Summary.RepositoriesFailed++
			result.Repositories = append(result.Repositories, entry)
			continue
		}
		result.Summary.RepositoriesScanned++
		entry.TagsTotal = len(tags)
		result.Summary.TagsDiscovered += len(tags)

		selected := make([]string, 0, len(tags))
		for _, tag := range tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			if !opts.IncludeSidecarTags && isSidecarTag(tag) {
				result.Summary.SidecarTagsSkipped++
				continue
			}
			if !matchesAny(tag, opts.TagPatterns, true) {
				continue
			}
			if matchesAny(tag, opts.ExcludeTagPatterns, false) {
				continue
			}
			selected = append(selected, tag)
		}
		sort.Strings(selected)
		if len(selected) > maxTags {
			// Keep the highest-sorting tags: version-like tags sort so that the
			// newest land last, and a truncated inventory of the newest is more
			// useful than a truncated inventory of the oldest.
			entry.Truncated = true
			entry.Warnings = append(entry.Warnings, fmt.Sprintf("%d tags matched; kept the %d highest-sorting", len(selected), maxTags))
			selected = selected[len(selected)-maxTags:]
		}
		entry.TagsSelected = selected
		result.Summary.TagsSelected += len(selected)
		for _, tag := range selected {
			ref := qualify(registry, repo) + ":" + tag
			if _, dup := seenRefs[ref]; dup {
				continue
			}
			seenRefs[ref] = struct{}{}
			result.Refs = append(result.Refs, ref)
		}
		result.Repositories = append(result.Repositories, entry)
	}

	sort.SliceStable(result.Repositories, func(i, j int) bool { return result.Repositories[i].Name < result.Repositories[j].Name })
	sort.Strings(result.Refs)
	if len(result.Refs) == 0 {
		result.Warnings = append(result.Warnings, "no tags matched the scan filters")
	}
	return result, nil
}

// discoverRepositories resolves the repository set, preferring an explicit list.
func discoverRepositories(ctx context.Context, lister Lister, registry, namespace string, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		seen := map[string]struct{}{}
		for _, repo := range explicit {
			repo = strings.Trim(strings.TrimSpace(repo), "/")
			if repo == "" {
				continue
			}
			// Accept both "namespace/name" and a bare name under --namespace.
			if namespace != "" && !strings.HasPrefix(repo, namespace+"/") && repo != namespace {
				repo = namespace + "/" + repo
			}
			if _, dup := seen[repo]; dup {
				continue
			}
			seen[repo] = struct{}{}
			out = append(out, repo)
		}
		sort.Strings(out)
		return out, nil
	}

	all, err := lister.Repositories(ctx, registry)
	if err != nil {
		// The `_catalog` endpoint is optional in the distribution spec and several
		// major registries (GHCR included) do not implement it for a user namespace.
		// Say so, and name the flag that works, instead of surfacing a raw 404.
		return nil, fmt.Errorf("catalog enumeration failed for %s: %w\n\nSome registries (GHCR, Docker Hub) do not expose the _catalog endpoint.\nPass --repository one or more times to scan known repositories directly", registry, err)
	}
	out := make([]string, 0, len(all))
	for _, repo := range all {
		repo = strings.Trim(strings.TrimSpace(repo), "/")
		if repo == "" {
			continue
		}
		if namespace != "" && repo != namespace && !strings.HasPrefix(repo, namespace+"/") {
			continue
		}
		out = append(out, repo)
	}
	sort.Strings(out)
	return out, nil
}

// isSidecarTag reports whether a tag names Sigstore/attestation evidence rather than
// a runnable image.
func isSidecarTag(tag string) bool {
	if !strings.HasPrefix(tag, "sha256-") {
		return false
	}
	for _, suffix := range sidecarTagSuffixes {
		if strings.HasSuffix(tag, suffix) {
			return true
		}
	}
	return false
}

// matchesAny reports whether tag matches any glob. An empty pattern set returns
// emptyResult, letting callers express "no filter means keep" and "no filter means
// do not exclude" with the same helper.
func matchesAny(tag string, patterns []string, emptyResult bool) bool {
	if len(patterns) == 0 {
		return emptyResult
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if ok, err := path.Match(pattern, tag); err == nil && ok {
			return true
		}
	}
	return false
}

func qualify(registry, repo string) string {
	return registry + "/" + repo
}

// RemoteLister is the production Lister: it speaks the OCI distribution protocol
// directly, authenticating from the ambient keychain (docker config, cloud helpers).
type RemoteLister struct {
	remoteOpts []remote.Option
	nameOpts   []name.Option
}

// NewRemoteLister returns a Lister authenticated from the ambient keychain.
func NewRemoteLister() *RemoteLister {
	return &RemoteLister{remoteOpts: []remote.Option{remote.WithAuthFromKeychain(registryauth.Keychain)}}
}

// NewRemoteListerWithBasicAuth returns a Lister using explicit credentials.
func NewRemoteListerWithBasicAuth(username, password string) *RemoteLister {
	return &RemoteLister{remoteOpts: []remote.Option{remote.WithAuth(&authn.Basic{Username: username, Password: password})}}
}

// Repositories enumerates the registry catalog.
func (l *RemoteLister) Repositories(ctx context.Context, registry string) ([]string, error) {
	reg, err := name.NewRegistry(registry, l.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("invalid registry %q: %w", registry, err)
	}
	return remote.Catalog(ctx, reg, l.remoteOpts...)
}

// Tags enumerates one repository's tags.
func (l *RemoteLister) Tags(ctx context.Context, repository string) ([]string, error) {
	repo, err := name.NewRepository(repository, l.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("invalid repository %q: %w", repository, err)
	}
	return remote.ListWithContext(ctx, repo, l.remoteOpts...)
}

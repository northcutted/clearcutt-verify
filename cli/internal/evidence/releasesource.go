package evidence

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/catalogbuild"
)

// ReleaseSource reads releases and their evidence from an OCI registry rather
// than from GitHub releases.
//
// It implements catalogbuild.ReleaseSource, so the catalog builder is unchanged:
// the same two methods, backed by tags and referrers instead of one vendor's
// releases API. That is what makes the control plane swappable — the catalog
// never knew where evidence came from, only that something could list releases
// and fetch assets.
//
// A "release" here is a tag on the image repository. Its "assets" are the files
// in the evidence bundles attached to the manifest that tag points at.
type ReleaseSource struct {
	client *Client
	repo   string
	// TagFilter keeps only tags a release should be built from. Nil accepts
	// every tag, which is rarely what you want on a repository that also
	// carries cosign sidecars and history indexes.
	TagFilter func(tag string) bool
}

// NewReleaseSource reads releases from the given repository, e.g.
// "ghcr.io/acme/clearcutt-java25".
func NewReleaseSource(client *Client, repo string) *ReleaseSource {
	return &ReleaseSource{client: client, repo: repo, TagFilter: DefaultTagFilter}
}

// DefaultTagFilter rejects tags that are not releases: cosign sidecars
// (sha256-*.sig / .att / .sbom), the referrers tag fallback (sha256-*), and
// ClearCutt's own estate history index. Without this a catalog would list its
// own bookkeeping as product releases.
func DefaultTagFilter(tag string) bool {
	if strings.HasPrefix(tag, "sha256-") {
		return false
	}
	switch tag {
	case "history", "latest-estate":
		return false
	}
	return true
}

// ListReleases enumerates repository tags newest-first and attaches the
// evidence found on each.
//
// Tag listing is one paginated call; each release then costs a HEAD to resolve
// its digest plus a referrers read. No blobs are pulled — asset CONTENT is
// fetched only when DownloadAsset asks for it.
func (s *ReleaseSource) ListReleases(limit int) ([]catalogbuild.Release, error) {
	if limit <= 0 {
		limit = 10
	}
	repo, err := name.NewRepository(s.repo, s.client.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing repository %q: %w", s.repo, err)
	}
	tags, err := remote.List(repo, s.client.remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("listing tags in %s: %w", s.repo, err)
	}
	filtered := make([]string, 0, len(tags))
	for _, tag := range tags {
		if s.TagFilter != nil && !s.TagFilter(tag) {
			continue
		}
		filtered = append(filtered, tag)
	}
	// Newest-first by tag order is the best available proxy: a registry does
	// not date its tags. Releases carry a created annotation from the evidence
	// itself, which the catalog can sort on more meaningfully.
	sort.Sort(sort.Reverse(sort.StringSlice(filtered)))
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	releases := make([]catalogbuild.Release, 0, len(filtered))
	for _, tag := range filtered {
		ref := s.repo + ":" + tag
		attachments, err := s.client.List(ref)
		if err != nil {
			// A tag with no readable evidence is still a release; the catalog
			// records what evidence is missing, which is the point.
			releases = append(releases, catalogbuild.Release{Tag: tag, Name: tag})
			continue
		}
		release := catalogbuild.Release{Tag: tag, Name: tag}
		for _, attachment := range attachments {
			if attachment.Created != "" && release.PublishedAt == "" {
				release.PublishedAt = attachment.Created
			}
			for _, fileName := range attachment.Files {
				release.Assets = append(release.Assets, catalogbuild.Asset{
					Name: fileName,
					URL:  AssetRef(s.repo, attachment.Digest, fileName),
				})
			}
		}
		sort.SliceStable(release.Assets, func(i, j int) bool { return release.Assets[i].Name < release.Assets[j].Name })
		releases = append(releases, release)
	}
	return releases, nil
}

// AssetRef encodes where an evidence file lives, in the URL field the catalog
// model already carries. It is deliberately a registry reference rather than an
// http URL: it is resolvable with registry credentials alone, on any registry,
// and it survives the repository moving hosts.
func AssetRef(repo, attachmentDigest, fileName string) string {
	return repo + "@" + attachmentDigest + "#" + fileName
}

// ParseAssetRef splits an asset reference back into its parts.
func ParseAssetRef(ref string) (repo, attachmentDigest, fileName string, err error) {
	hash := strings.LastIndex(ref, "#")
	if hash < 0 {
		return "", "", "", fmt.Errorf("evidence asset reference %q has no #filename", ref)
	}
	fileName = ref[hash+1:]
	at := strings.LastIndex(ref[:hash], "@")
	if at < 0 {
		return "", "", "", fmt.Errorf("evidence asset reference %q has no @digest", ref)
	}
	return ref[:at], ref[at+1 : hash], fileName, nil
}

// DownloadAsset fetches one evidence file.
func (s *ReleaseSource) DownloadAsset(asset catalogbuild.Asset) ([]byte, error) {
	repo, attachmentDigest, fileName, err := ParseAssetRef(asset.URL)
	if err != nil {
		return nil, err
	}
	bundle, err := s.client.Fetch(repo, attachmentDigest)
	if err != nil {
		return nil, err
	}
	body, ok := bundle.Files[fileName]
	if !ok {
		return nil, fmt.Errorf("evidence bundle %s has no file %q", attachmentDigest, fileName)
	}
	return body, nil
}

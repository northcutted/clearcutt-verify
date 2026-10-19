package estate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// HistoryArtifactType marks the index that holds an estate's history.
const HistoryArtifactType = "application/vnd.clearcutt.estate.history.v1+json"

// HistoryEntry is one snapshot in the series.
type HistoryEntry struct {
	Digest      string  `json:"digest"`
	GeneratedAt string  `json:"generatedAt"`
	Metrics     Metrics `json:"metrics"`
}

// History is the series, oldest first.
type History struct {
	Ref     string         `json:"ref"`
	Digest  string         `json:"digest"`
	Entries []HistoryEntry `json:"entries"`
}

// PushSnapshot writes one snapshot and, when historyRef is set, appends it to
// that history index.
//
// The history is an OCI IMAGE INDEX whose entries are snapshot manifests, with
// each run's metrics carried in the entry's annotations. That shape is chosen
// for three properties the registry gives away and a bespoke store would not:
//
//   - Reading a trend costs ONE manifest fetch. The numbers are in the
//     annotations, so charting a year of daily snapshots pulls no blobs at all.
//   - Every snapshot stays immutable and independently pullable by digest, so
//     drilling into one date does not depend on the index still being right.
//   - Storage is incremental for free. Blobs are content-addressed, so a file
//     that did not change between two runs is stored once and referenced twice.
//     Snapshots are logically complete but physically deltas — which is the
//     property a hand-rolled "full snapshot every day" store has to work for.
//
// Appending rewrites the index, which is O(entries). A daily snapshot for three
// years is about a thousand descriptors — a few hundred KB — so this stays
// cheap for far longer than anyone will keep the data.
func (c *Client) PushSnapshot(snapshotRef, historyRef string, snapshot Snapshot) (snapshotDigest, historyDigest string, err error) {
	img, err := Build(snapshot)
	if err != nil {
		return "", "", err
	}
	target, err := name.ParseReference(snapshotRef, c.nameOpts...)
	if err != nil {
		return "", "", fmt.Errorf("parsing snapshot reference %q: %w", snapshotRef, err)
	}
	if err := remote.Write(target, img, c.remoteOpts...); err != nil {
		return "", "", fmt.Errorf("pushing estate snapshot to %s: %w", snapshotRef, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return "", "", err
	}
	snapshotDigest = digest.String()

	if strings.TrimSpace(historyRef) == "" {
		return snapshotDigest, "", nil
	}
	historyDigest, err = c.appendToHistory(historyRef, img, snapshot)
	if err != nil {
		// The snapshot is already stored and addressable, so report the digest
		// alongside the failure rather than losing it. A failed history append
		// is recoverable; a snapshot the caller cannot name is not.
		return snapshotDigest, "", fmt.Errorf("snapshot stored at %s but appending to history %s failed: %w", snapshotDigest, historyRef, err)
	}
	return snapshotDigest, historyDigest, nil
}

func (c *Client) appendToHistory(historyRef string, img v1.Image, snapshot Snapshot) (string, error) {
	target, err := name.ParseReference(historyRef, c.nameOpts...)
	if err != nil {
		return "", fmt.Errorf("parsing history reference %q: %w", historyRef, err)
	}

	base, err := c.existingHistory(target)
	if err != nil {
		return "", err
	}
	// A re-push of identical content must not add a duplicate entry: the digest
	// is the same, so the series would gain a row that says nothing happened.
	digest, err := img.Digest()
	if err != nil {
		return "", err
	}
	if manifest, err := base.IndexManifest(); err == nil {
		for _, entry := range manifest.Manifests {
			if entry.Digest.String() == digest.String() {
				existingDigest, digestErr := base.Digest()
				if digestErr != nil {
					return "", digestErr
				}
				return existingDigest.String(), nil
			}
		}
	}

	metrics := ExtractMetrics(snapshot)
	annotations := metrics.Annotations()
	if generatedAt := strings.TrimSpace(snapshot.GeneratedAt); generatedAt != "" {
		annotations[GeneratedAtAnnotation] = generatedAt
	}
	mediaType, err := img.MediaType()
	if err != nil {
		return "", err
	}
	size, err := img.Size()
	if err != nil {
		return "", err
	}
	updated := mutate.AppendManifests(base, mutate.IndexAddendum{
		Add: img,
		Descriptor: v1.Descriptor{
			MediaType:   mediaType,
			Size:        size,
			Digest:      digest,
			Annotations: annotations,
		},
	})
	updated = mutate.IndexMediaType(updated, types.OCIImageIndex)
	if err := remote.WriteIndex(target, updated, c.remoteOpts...); err != nil {
		// A history index is rewritten on every append, so its tag must be
		// mutable. Registries enforcing tag immutability reject the write with
		// a generic error that gives an operator nothing to act on, so say what
		// the constraint is and how to satisfy it.
		return "", fmt.Errorf("writing history index %s: %w\n\n"+
			"If the registry enforces tag immutability, this is expected: the history index is a single "+
			"moving pointer to a growing series, so its tag must be mutable. Every snapshot it names is "+
			"immutable and digest-addressed; only the pointer moves.\n"+
			"Either exempt this tag from the immutability rule, or keep the history in a separate "+
			"repository from the images, e.g. --history %s",
			historyRef, err, suggestSeparateHistoryRepo(historyRef))
	}
	indexDigest, err := updated.Digest()
	if err != nil {
		return "", err
	}
	return indexDigest.String(), nil
}

// existingHistory reads the history index at target to append to. Only a
// registry saying nothing is stored there (404, MANIFEST_UNKNOWN,
// NAME_UNKNOWN) starts a new series: any other failure (credentials, rate
// limits, an outage) stops the push, because writing a fresh index over a
// series that couldn't be read would erase it. What is there must be a
// history index: an index whose every entry is an estate snapshot this
// command appended, carrying its metrics. An image, or another kind of index,
// is never overwritten.
func (c *Client) existingHistory(target name.Reference) (v1.ImageIndex, error) {
	desc, err := remote.Get(target, c.remoteOpts...)
	switch {
	case err != nil && manifestNotFound(err):
		return mutate.IndexMediaType(empty.Index, types.OCIImageIndex), nil
	case err != nil:
		return nil, fmt.Errorf("reading history index %s: %w (not starting a new history over one that couldn't be read)", target, err)
	case !desc.MediaType.IsIndex():
		return nil, fmt.Errorf("%s holds a %s, not an estate history index; refusing to overwrite it", target, desc.MediaType)
	}
	index, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("reading history index %s: %w", target, err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading history index %s: %w", target, err)
	}
	for _, entry := range manifest.Manifests {
		if _, ok := entry.Annotations[annImages]; !ok || entry.MediaType != types.OCIManifestSchema1 {
			return nil, fmt.Errorf("%s is an index, but not an estate history (its entry %s is not an estate snapshot); refusing to overwrite it", target, entry.Digest)
		}
	}
	return index, nil
}

// ReadHistory fetches a series. It reads the index only — no snapshot blobs —
// so charting a long history is one request regardless of its length.
func (c *Client) ReadHistory(historyRef string) (History, error) {
	target, err := name.ParseReference(historyRef, c.nameOpts...)
	if err != nil {
		return History{}, fmt.Errorf("parsing history reference %q: %w", historyRef, err)
	}
	index, err := remote.Index(target, c.remoteOpts...)
	if err != nil {
		return History{}, fmt.Errorf("fetching estate history %s: %w", historyRef, err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return History{}, err
	}
	indexDigest, err := index.Digest()
	if err != nil {
		return History{}, err
	}
	history := History{Ref: historyRef, Digest: indexDigest.String()}
	for _, entry := range manifest.Manifests {
		history.Entries = append(history.Entries, HistoryEntry{
			Digest:      entry.Digest.String(),
			GeneratedAt: entry.Annotations[GeneratedAtAnnotation],
			Metrics:     MetricsFromAnnotations(entry.Annotations),
		})
	}
	// Order by the timestamp the snapshot records, not by push order: a
	// backfilled run must land in the right place on the trend line.
	sort.SliceStable(history.Entries, func(i, j int) bool {
		if history.Entries[i].GeneratedAt != history.Entries[j].GeneratedAt {
			return history.Entries[i].GeneratedAt < history.Entries[j].GeneratedAt
		}
		return history.Entries[i].Digest < history.Entries[j].Digest
	})
	return history, nil
}

// Delta reports the change between the first and last entry, which is the
// question the history exists to answer: did this get better?
func (h History) Delta() (first, last HistoryEntry, ok bool) {
	if len(h.Entries) < 2 {
		return HistoryEntry{}, HistoryEntry{}, false
	}
	return h.Entries[0], h.Entries[len(h.Entries)-1], true
}

// suggestSeparateHistoryRepo proposes a history reference in a sibling
// repository, for registries whose immutability policy cannot be scoped to
// exclude one tag.
func suggestSeparateHistoryRepo(historyRef string) string {
	ref := historyRef
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	repo := ref
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		repo = ref[:colon]
	}
	return repo + "-history:history"
}

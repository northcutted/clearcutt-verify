package commands

import (
	"fmt"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

// latestOrTaggedRelease returns the release matching tag, or the latest release
// when tag is empty. "Latest" is the entry flagged IsLatest, falling back to the
// first release on record. Callers that need the latest-N alias syntax should use
// resolveRelease instead.
func latestOrTaggedRelease(releases []catalog.ReleaseEntry, tag string) (*catalog.ReleaseEntry, error) {
	if len(releases) == 0 {
		return nil, fmt.Errorf("no releases found")
	}
	if tag != "" {
		for i := range releases {
			if releases[i].Tag == tag {
				return &releases[i], nil
			}
		}
		return nil, fmt.Errorf("release tag %q not found", tag)
	}
	for i := range releases {
		if releases[i].IsLatest {
			return &releases[i], nil
		}
	}
	return &releases[0], nil
}

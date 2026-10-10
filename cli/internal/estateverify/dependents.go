package estateverify

import (
	"sort"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Dependent is an image built on a base, as an estate report records it:
// what automation needs to wake the repository that owns it.
type Dependent struct {
	ImageID    string   `json:"imageId"`
	Repository string   `json:"repository"`
	Digest     string   `json:"digest"`
	Tags       []string `json:"tags"`
	// Base is the version of the base the image is built on.
	Base report.BaseLink `json:"base"`
	// Source is the repository the image was built from (verified
	// provenance where there was any, else its label).
	Source *report.SourceRef `json:"source,omitempty"`
	// Depth is 1 for images built directly on the base, 2 for images built
	// on those, and so on.
	Depth int `json:"depth"`
}

// strengthRank orders base-link strengths, strongest first.
var strengthRank = map[string]int{"proof": 4, "declared": 3, "assisted": 2, "weak": 1}

// Dependents lists the images built on base (a repository, with or without
// a tag or digest) whose link is at least minStrength, nearest first. With
// transitive, images built on those are included too.
func Dependents(r *report.Report, base, minStrength string, transitive bool) []Dependent {
	min := strengthRank[minStrength]
	byBase := map[string][]report.Image{}
	for _, img := range r.Images {
		if img.Base != nil && strengthRank[img.Base.Strength] >= min {
			k := normalizeRepo(img.Base.Repository)
			byBase[k] = append(byBase[k], img)
		}
	}
	var out []Dependent
	seen := map[string]bool{}
	frontier := []string{repoOf(qualify(base))}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []string
		for _, repo := range frontier {
			for _, img := range byBase[normalizeRepo(repo)] {
				if seen[img.ID] {
					continue
				}
				seen[img.ID] = true
				out = append(out, Dependent{ImageID: img.ID, Repository: img.Repository, Digest: img.Digest, Tags: img.Tags, Base: *img.Base, Source: img.Source, Depth: depth})
				next = append(next, img.Repository)
			}
		}
		if !transitive {
			break
		}
		frontier = next
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].ImageID < out[j].ImageID
	})
	if out == nil {
		out = []Dependent{}
	}
	return out
}

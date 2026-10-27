package estateverify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"sigs.k8s.io/yaml"

	"github.com/northcutted/clearcutt-verify/internal/estategraph"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

// PolicyInitOptions selects discovery scope; no signature verification runs.
type PolicyInitOptions struct {
	Concurrency   int
	Platforms     []string
	RemoteOptions []remote.Option
	// Progress is called serially after each reference has been inspected.
	Progress func(completed, total int, ref string)
}

// UnverifiedSigner is certificate metadata found in an attachment, not trust.
type UnverifiedSigner struct {
	Format string        `json:"format"`
	Signer report.Signer `json:"signer"`
}

// PolicySuggestion describes availability, not verified evidence or compliance.
type PolicySuggestion struct {
	Images             int                `json:"images"`
	Platforms          []string           `json:"platforms,omitempty"`
	Required           []string           `json:"required"`
	Available          map[string]int     `json:"available"`
	UnverifiedSigners  []UnverifiedSigner `json:"unverifiedSigners"`
	PresentOnlyFormats []string           `json:"presentOnlyFormats,omitempty"`
}

type policyImage struct {
	available map[string]bool
	found     []Found
}

// SuggestPolicy freshly discovers evidence on every observed subject. An
// unreadable reference, platform or evidence listing aborts rather than
// recommending fewer requirements on the strength of incomplete discovery.
func SuggestPolicy(ctx context.Context, observations estategraph.Observations, opts PolicyInitOptions) (PolicySuggestion, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	images := uniqueImages(observations.Images)
	if len(images) == 0 {
		return PolicySuggestion{}, fmt.Errorf("no images to inspect")
	}
	sort.Slice(images, func(i, j int) bool {
		return images[i].DigestRef+"\x00"+images[i].SourceRef < images[j].DigestRef+"\x00"+images[j].SourceRef
	})
	opts.Platforms = platformSelection(opts.Platforms)
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 4
	}
	if conc > len(images) {
		conc = len(images)
	}
	results := make([]policyImage, len(images))
	errs := make([]error, len(images))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	completed := 0
	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i], errs[i] = inspectPolicyImage(ctx, images[i], opts)
				if opts.Progress != nil {
					progressMu.Lock()
					completed++
					opts.Progress(completed, len(images), firstNonEmpty(images[i].SourceRef, images[i].DigestRef))
					progressMu.Unlock()
				}
			}
		}()
	}
send:
	for i := range images {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return PolicySuggestion{}, err
	}
	for i, err := range errs {
		if err != nil {
			return PolicySuggestion{}, fmt.Errorf("inspect %q: %w", firstNonEmpty(images[i].SourceRef, images[i].DigestRef), err)
		}
	}
	return summarizePolicy(results, opts.Platforms), nil
}

func inspectPolicyImage(ctx context.Context, obs estategraph.Observation, opts PolicyInitOptions) (policyImage, error) {
	ref, err := name.NewDigest(obs.DigestRef)
	if err != nil {
		return policyImage{}, fmt.Errorf("image could not be resolved to an immutable digest: %w", err)
	}
	repo, digest := ref.Context().Name(), ref.DigestStr()
	platforms, err := platformImages(ctx, repo, digest, obs, opts.RemoteOptions, opts.Platforms)
	if err != nil {
		return policyImage{}, fmt.Errorf("platforms could not be read: %w", err)
	}
	// platformImages is also used for best-effort reports. Here every selected
	// image manifest/config must be readable before suggesting requirements.
	var selected []report.Platform
	ropts := append([]remote.Option{remote.WithContext(ctx)}, opts.RemoteOptions...)
	for _, p := range platforms {
		child, err := name.NewDigest(repo + "@" + p.Digest)
		if err != nil {
			return policyImage{}, err
		}
		img, err := remote.Image(child, ropts...)
		if err != nil {
			return policyImage{}, err
		}
		if _, err := img.Manifest(); err != nil {
			return policyImage{}, fmt.Errorf("platform %s manifest: %w", p.Platform, err)
		}
		config, err := img.ConfigFile()
		if err != nil {
			return policyImage{}, fmt.Errorf("platform %s config: %w", p.Platform, err)
		}
		if config.OS == "" || config.Architecture == "" {
			return policyImage{}, fmt.Errorf("platform %s has no readable OS/architecture", p.Platform)
		}
		actual := config.OS + "/" + config.Architecture
		if p.Digest == digest || p.Platform == "unknown" {
			p.Platform = actual
			if config.Variant != "" {
				p.Platform += "/" + config.Variant
			}
		} else if p.Platform != actual && !strings.HasPrefix(p.Platform, actual+"/") {
			return policyImage{}, fmt.Errorf("platform %s disagrees with image config %s", p.Platform, actual)
		}
		if len(opts.Platforms) == 0 || contains(opts.Platforms, p.Platform) {
			selected = append(selected, p)
		}
	}
	if len(selected) == 0 {
		return policyImage{}, fmt.Errorf("no readable image platforms match the selected scope")
	}
	found, unknown := discoverImage(ctx, repo, digest, selected, &Discoverer{Options: opts.RemoteOptions})
	if len(unknown) > 0 {
		var subjects []string
		for subject := range unknown {
			subjects = append(subjects, subject)
		}
		sort.Strings(subjects)
		return policyImage{}, fmt.Errorf("evidence listing for %s: %w", subjects[0], unknown[subjects[0]])
	}
	out := policyImage{available: map[string]bool{}}
	for _, copies := range found {
		out.found = append(out.found, copies...)
	}
	for _, kind := range Kinds {
		if kind == KindRebase {
			continue // not a supported required evidence kind
		}
		subjects := []string{digest}
		if perPlatform[kind] {
			subjects = nil
			for _, p := range selected {
				subjects = append(subjects, p.Digest)
			}
		}
		out.available[kind] = true
		for _, subject := range subjects {
			if len(copiesOf(found[subject], kind, subject)) == 0 {
				out.available[kind] = false
			}
		}
	}
	return out, nil
}

func summarizePolicy(images []policyImage, platforms []string) PolicySuggestion {
	out := PolicySuggestion{Images: len(images), Platforms: platformSelection(platforms), Required: []string{},
		Available: map[string]int{}, UnverifiedSigners: []UnverifiedSigner{}}
	candidates := map[string]UnverifiedSigner{}
	formats := map[string]bool{}
	for _, kind := range Kinds {
		if kind == KindRebase {
			continue
		}
		out.Available[kind] = 0
		for _, image := range images {
			if image.available[kind] {
				out.Available[kind]++
			}
		}
		if out.Available[kind] == len(images) {
			out.Required = append(out.Required, kind)
		}
	}
	for _, image := range images {
		for _, f := range image.found {
			if Unsigned(f.Format) {
				formats[f.Format] = true
			}
			if f.Signer == nil || f.Signer.Identity == "" {
				continue
			}
			// Certificate claims never grant owner-wide or regexp trust. Keep
			// only the exact identity/issuer/caller fields discovery observed.
			s := f.Signer
			c := UnverifiedSigner{Format: f.Format, Signer: report.Signer{Identity: s.Identity, Issuer: s.Issuer,
				SourceRepository: s.SourceRepository, SourceRef: s.SourceRef}}
			key, _ := json.Marshal(c)
			candidates[string(key)] = c
		}
	}
	var keys []string
	for k := range candidates {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.UnverifiedSigners = append(out.UnverifiedSigners, candidates[k])
	}
	for f := range formats {
		out.PresentOnlyFormats = append(out.PresentOnlyFormats, f)
	}
	sort.Strings(out.PresentOnlyFormats)
	return out
}

// RenderPolicySuggestion writes no active trust. Every physical line of
// untrusted certificate metadata is commented, including embedded newlines.
func RenderPolicySuggestion(s PolicySuggestion) (policy, trust []byte, err error) {
	if s.Images <= 0 {
		return nil, nil, fmt.Errorf("no images inspected")
	}
	if err := ValidatePolicy(report.Policy{Required: s.Required}); err != nil {
		return nil, nil, err
	}
	s.Required = append([]string{}, s.Required...)
	var p, t bytes.Buffer
	comment := func(b *bytes.Buffer, text string) {
		for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			fmt.Fprintf(b, "# %s\n", line)
		}
	}
	comment(&p, fmt.Sprintf("Starter from discovery of %d image reference(s), not a verification result.", s.Images))
	comment(&p, "Review required evidence and trust-policy.yaml before using this as a gate.")
	comment(&p, "Availability requires SBOM/scan evidence for every selected image platform; it does not establish usable or trusted content.")
	if len(s.Platforms) > 0 {
		comment(&p, "Inspected platform scope: "+strings.Join(s.Platforms, ", ")+". Use the same --platforms when verifying.")
	} else {
		comment(&p, "Inspected platform scope: all image platforms.")
	}
	for _, kind := range Kinds {
		if kind != KindRebase {
			comment(&p, fmt.Sprintf("%s available: %d/%d image reference(s).", kind, s.Available[kind], s.Images))
		}
	}
	comment(&p, "Choose failOn, onlyFixed, maxDaysBehind and maxScanAgeDays for your estate; none are inferred.")
	body, err := yaml.Marshal(struct {
		APIVersion  string   `json:"apiVersion"`
		Kind        string   `json:"kind"`
		Required    []string `json:"required"`
		TrustPolicy string   `json:"trustPolicy"`
	}{report.APIVersion, "VerificationPolicy", s.Required, "trust-policy.yaml"})
	if err != nil {
		return nil, nil, err
	}
	p.Write(body)
	comment(&t, "No signer is trusted yet. Discovery does not verify certificates or signatures.")
	comment(&t, "Confirm identities, issuers and caller repositories/refs out of band before adding active signer rows.")
	comment(&t, "Key-signed evidence requires a public key you trust out of band; no key is inferred.")
	tp := report.TrustPolicy{APIVersion: report.APIVersion, Kind: report.KindTrustPolicy, Signers: []report.TrustedSigner{}}
	if err := report.Validate(tp); err != nil {
		return nil, nil, err
	}
	body, err = yaml.Marshal(tp)
	if err != nil {
		return nil, nil, err
	}
	t.Write(body)
	for _, format := range s.PresentOnlyFormats {
		comment(&t, "Present-only format (not verified): "+format)
	}
	for i, c := range s.UnverifiedSigners {
		comment(&t, fmt.Sprintf("Candidate %d: UNVERIFIED certificate claims in %q; not active trust.", i+1, c.Format))
		var candidate any
		if c.Format == FormatNotation {
			comment(&t, "Notation needs separate Notation trust configuration; this is not a Cosign signer entry.")
			candidate = c.Signer
		} else {
			signer := c.Signer
			candidate = []report.TrustedSigner{{Name: fmt.Sprintf("review-candidate-%d", i+1), Roles: []string{"image"},
				Identity: signer.Identity, Issuer: signer.Issuer, SourceRepository: signer.SourceRepository, SourceRef: signer.SourceRef}}
		}
		body, err := yaml.Marshal(candidate)
		if err != nil {
			return nil, nil, err
		}
		comment(&t, string(body))
	}
	return p.Bytes(), t.Bytes(), nil
}

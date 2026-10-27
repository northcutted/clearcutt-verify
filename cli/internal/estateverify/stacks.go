package estateverify

import (
	"context"
	"sort"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// stacksOf lists the registry stacks the estate's clearcutt-factory apps
// are built on, from their verified recipes (a rebased app's is the recipe
// of the image it was rebased from, reached through its verified rebase
// record): the versions in use, each version's signature checked against
// the policy's stack signers, and the apps pinned to a version other than
// the one the stack's tag names now. A stack is a repository and tag: apps
// on ghcr.io/acme/stacks/go:1 and :2 are on two stacks, each current or
// stale against its own tag.
func stacksOf(ctx context.Context, images []report.Image, opts Options) []report.Stack {
	type pin struct{ digest, image string }
	byRef := map[string][]pin{}
	for _, img := range images {
		f := img.Factory
		if f == nil || f.StackRef == "" || f.StackDigest == "" {
			continue
		}
		// The factory block is read only from verified evidence; this keeps
		// it that way.
		if img.Evidence.Recipe.Status != "verified" && img.Evidence.Rebase.Status != "verified" {
			continue
		}
		ref := qualify(f.StackRef)
		byRef[ref] = append(byRef[ref], pin{f.StackDigest, img.ID})
	}
	if len(byRef) == 0 {
		return nil
	}
	verifier := &Verifier{Signers: opts.Policy.StackSigners}
	if opts.Verifier != nil {
		verifier.Cosign, verifier.Run, verifier.TrustedRoot = opts.Verifier.Cosign, opts.Verifier.Run, opts.Verifier.TrustedRoot
		verifier.Timeout = opts.Verifier.Timeout
		verifier.Cache = opts.Verifier.Cache
	}
	o := append([]remote.Option{remote.WithContext(ctx)}, opts.RemoteOptions...)

	var out []report.Stack
	for ref, pins := range byRef {
		repo := repoOf(ref)
		st := report.Stack{Repository: repo, Ref: ref, Versions: []report.StackVersion{}}
		if r, err := name.ParseReference(st.Ref); err == nil {
			if desc, err := remote.Head(r, o...); err == nil {
				st.CurrentDigest = desc.Digest.String()
			}
		}
		versions := map[string]*report.StackVersion{}
		var order []string
		for _, p := range pins {
			v, ok := versions[p.digest]
			if !ok {
				v = &report.StackVersion{Digest: p.digest, Current: p.digest == st.CurrentDigest, Images: []string{}}
				v.Signature = stackSignature(ctx, repo, p.digest, verifier, opts)
				versions[p.digest] = v
				order = append(order, p.digest)
			}
			v.Images = appendUnique(v.Images, p.image)
			st.Consumers++
			if st.CurrentDigest != "" && p.digest != st.CurrentDigest {
				st.StaleConsumers++
			}
		}
		sort.Strings(order)
		for _, d := range order {
			sort.Strings(versions[d].Images)
			st.Versions = append(st.Versions, *versions[d])
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Repository != out[j].Repository {
			return out[i].Repository < out[j].Repository
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

// stackSignature verifies a stack artifact's signature.
func stackSignature(ctx context.Context, repo, digest string, verifier *Verifier, opts Options) report.EvidenceItem {
	found, err := opts.Discoverer.Discover(ctx, repo, digest)
	if err != nil {
		return report.EvidenceItem{Status: "unknown", Detail: "The registry couldn't be read: " + err.Error()}
	}
	item, _ := verifyEvidence(ctx, verifier, repo, digest, KindSignature, "", found)
	if item.Status == "missing" {
		item.Detail = "The stack carries no signature."
	}
	if item.Status != "missing" && len(verifier.Signers) == 0 {
		item.Detail = "No stack signer is configured (a trust policy's stack signers), so it can't be verified."
	}
	return item
}

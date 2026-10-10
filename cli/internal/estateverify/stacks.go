package estateverify

import (
	"context"
	"sort"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/northcutted/clearcutt-verify/internal/report"
)

// stacksOf lists the registry stacks the estate's clearcutt-factory apps
// are built on, from their verified recipes: the versions in use, each
// version's signature checked against the policy's stack signers, and the
// apps pinned to a version other than the one the stack's tag names now.
func stacksOf(ctx context.Context, images []report.Image, opts Options) []report.Stack {
	type pin struct{ ref, digest, image string }
	byRepo := map[string][]pin{}
	for _, img := range images {
		f := img.Factory
		if f == nil || f.StackRef == "" || f.StackDigest == "" || img.Evidence.Recipe.Status != "verified" {
			continue
		}
		ref := qualify(f.StackRef)
		byRepo[repoOf(ref)] = append(byRepo[repoOf(ref)], pin{ref, f.StackDigest, img.ID})
	}
	if len(byRepo) == 0 {
		return nil
	}
	verifier := &Verifier{Signers: opts.Policy.StackSigners}
	if opts.Verifier != nil {
		verifier.Cosign, verifier.Run = opts.Verifier.Cosign, opts.Verifier.Run
	}
	o := append([]remote.Option{remote.WithContext(ctx)}, opts.RemoteOptions...)

	var out []report.Stack
	for repo, pins := range byRepo {
		st := report.Stack{Repository: repo, Ref: pins[0].ref, Versions: []report.StackVersion{}}
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
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return out
}

// stackSignature verifies a stack artifact's signature.
func stackSignature(ctx context.Context, repo, digest string, verifier *Verifier, opts Options) report.EvidenceItem {
	found, err := opts.Discoverer.Discover(ctx, repo, digest)
	if err != nil {
		return report.EvidenceItem{Status: "unknown", Detail: "The registry couldn't be read: " + err.Error()}
	}
	f, ok := newest(found, KindSignature, digest)
	if !ok {
		return report.EvidenceItem{Status: "missing", Detail: "The stack carries no signature."}
	}
	item := report.EvidenceItem{Source: sourceName(f), Ref: f.Ref, Timestamp: f.Timestamp, Signer: f.Signer}
	item.Status, item.Detail = check(ctx, verifier, repo+"@"+digest, f, "")
	if len(verifier.Signers) == 0 {
		item.Detail = "No stack signer is configured (a trust policy's stack signers), so it can't be verified."
	}
	return item
}

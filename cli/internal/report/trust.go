package report

// KindTrustPolicy names a trust policy document.
const KindTrustPolicy = "TrustPolicy"

// TrustPolicy says whose signatures an organization accepts, and for what.
// The ClearCutt tools share it: clearcutt-verify checks an estate's evidence
// against its image signers, and clearcutt-factory (signing.trustPolicy)
// checks images and stacks against it when building, publishing, and
// rebasing.
type TrustPolicy struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	// Signers are the trusted signers; evidence verifies if any applicable
	// one vouches for it.
	Signers []TrustedSigner `json:"signers"`
}

// TrustedSigner is one signer and what it may sign. Its identity fields
// mean what they mean in Signer.
type TrustedSigner struct {
	// Name labels the signer in reports and messages.
	Name string `json:"name,omitempty"`
	// Roles is what the signer may sign: image (an image's signature and
	// attestations; the default), stack (a clearcutt-factory stack), and/or
	// estate (an estate report bundle or history index in a registry, as
	// clearcutt-verify estate pull and estate history read them).
	Roles []string `json:"roles,omitempty" enum:"image,stack,estate"`
	// Identity is the keyless certificate identity, exactly (a GitHub
	// Actions workflow: https://github.com/OWNER/REPO/.github/workflows/
	// FILE@REF); IdentityRegexp matches it instead, anchored with ^ and
	// naming the owner exactly (ending it with /), never a wildcard.
	Identity       string `json:"identity,omitempty"`
	IdentityRegexp string `json:"identityRegexp,omitempty"`
	// Issuer is the OIDC issuer of the certificate, e.g.
	// https://token.actions.githubusercontent.com.
	Issuer string `json:"issuer,omitempty"`
	// Key is a public key (a file relative to this document, or a KMS URI)
	// instead of a certificate identity.
	Key string `json:"key,omitempty"`
	// SourceRepository is the one repository (https://github.com/OWNER/REPO)
	// whose workflow runs may sign: the certificate's Source Repository URI
	// must be it. For a reusable workflow, the calling repository.
	SourceRepository string `json:"sourceRepository,omitempty"`
	// SourceRepositoryOwner accepts runs in any repository of one owner
	// (https://github.com/OWNER): the certificate's Source Repository URI
	// must be https://github.com/OWNER/<repo>, i.e. its owner segment must
	// be OWNER, and that repository is then required of cosign exactly
	// (--certificate-github-workflow-repository). An alternative to
	// SourceRepository for a reusable workflow every repository of an
	// organization calls; with SourceRepository or SourceMatchesImage too,
	// the repository they resolve to must be the owner's.
	SourceRepositoryOwner string `json:"sourceRepositoryOwner,omitempty"`
	// SourceRef is the ref the signing run must be on, e.g. refs/heads/main.
	SourceRef string `json:"sourceRef,omitempty"`
	// SourceMatchesImage requires the signing run to be in the repository the
	// image names as its source (org.opencontainers.image.source).
	SourceMatchesImage bool `json:"sourceMatchesImage,omitempty"`
	// Tlog false accepts this key signer's evidence without a transparency
	// log entry (cosign --insecure-ignore-tlog), for a key that signs
	// without one. Keyless signers can't set it.
	Tlog *bool `json:"tlog,omitempty"`
}

// Signer is the trusted signer's identity.
func (s TrustedSigner) Signer() Signer {
	return Signer{
		Identity: s.Identity, IdentityRegexp: s.IdentityRegexp, Issuer: s.Issuer, Key: s.Key,
		SourceRepository: s.SourceRepository, SourceRepositoryOwner: s.SourceRepositoryOwner,
		SourceRef: s.SourceRef, SourceMatchesImage: s.SourceMatchesImage, Tlog: s.Tlog,
	}
}

// For returns the identities of the signers that may sign role.
func (t TrustPolicy) For(role string) []Signer {
	var out []Signer
	for _, s := range t.Signers {
		roles := s.Roles
		if len(roles) == 0 {
			roles = []string{"image"}
		}
		for _, r := range roles {
			if r == role {
				out = append(out, s.Signer())
				break
			}
		}
	}
	return out
}

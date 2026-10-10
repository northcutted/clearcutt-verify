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
	// attestations; the default) and/or stack (a clearcutt-factory stack).
	Roles                 []string `json:"roles,omitempty" enum:"image,stack"`
	Identity              string   `json:"identity,omitempty"`
	IdentityRegexp        string   `json:"identityRegexp,omitempty"`
	Issuer                string   `json:"issuer,omitempty"`
	Key                   string   `json:"key,omitempty"`
	SourceRepository      string   `json:"sourceRepository,omitempty"`
	SourceRepositoryOwner string   `json:"sourceRepositoryOwner,omitempty"`
	SourceRef             string   `json:"sourceRef,omitempty"`
	SourceMatchesImage    bool     `json:"sourceMatchesImage,omitempty"`
}

// Signer is the trusted signer's identity.
func (s TrustedSigner) Signer() Signer {
	return Signer{
		Identity: s.Identity, IdentityRegexp: s.IdentityRegexp, Issuer: s.Issuer, Key: s.Key,
		SourceRepository: s.SourceRepository, SourceRepositoryOwner: s.SourceRepositoryOwner,
		SourceRef: s.SourceRef, SourceMatchesImage: s.SourceMatchesImage,
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

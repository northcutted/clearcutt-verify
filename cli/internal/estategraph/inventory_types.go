package estategraph

// The inventory (images.yaml) describes each image as clearcutt-verify's
// predecessor's catalog did; these types keep that file format.

// LanguageInfo is the language runtime an image ships, as inferred.
type LanguageInfo struct {
	ID          string  `json:"id"`
	DisplayName string  `json:"displayName"`
	Version     string  `json:"version"`
	Icon        *string `json:"icon,omitempty"`
}

// Lifecycle is an image's support status.
type Lifecycle struct {
	Status            string  `json:"status"`
	Support           string  `json:"support"`
	ProductionAllowed bool    `json:"productionAllowed"`
	DeprecatedAt      *string `json:"deprecatedAt"`
	EOLAt             *string `json:"eolAt"`
	Reason            *string `json:"reason"`
}

// RuntimeContract is what an image promises at runtime.
type RuntimeContract struct {
	User                  *string `json:"user"`
	WorkingDir            *string `json:"workingDir"`
	ShellPresent          *bool   `json:"shellPresent"`
	PackageManagerPresent *bool   `json:"packageManagerPresent"`
	CACertificatesPresent *bool   `json:"caCertificatesPresent"`
	TimezoneDataPresent   *bool   `json:"timezoneDataPresent"`
	DefaultEntrypoint     *string `json:"defaultEntrypoint"`
	ProductionTier        bool    `json:"productionTier"`
}

// ImageOrigin is where an inventory entry came from.
type ImageOrigin struct {
	Kind               string `json:"kind"`
	CreatedByClearCutt bool   `json:"createdByClearCutt"`
	SourceRef          string `json:"sourceRef,omitempty"`
	DigestRef          string `json:"digestRef,omitempty"`
	ObservedAt         string `json:"observedAt,omitempty"`
	ObservationMode    string `json:"observationMode,omitempty"`
	ProvenanceClaim    string `json:"provenanceClaim,omitempty"`
}

// ImageGovernance is who owns an imported image and how sure the import is.
type ImageGovernance struct {
	Imported                 bool     `json:"imported"`
	Owner                    string   `json:"owner,omitempty"`
	ClassificationConfidence string   `json:"classificationConfidence,omitempty"`
	ProductionIntent         string   `json:"productionIntent,omitempty"`
	Notes                    []string `json:"notes,omitempty"`
}

// EvidencePolicy says which evidence an image requires (required,
// optional).
type EvidencePolicy struct {
	Signature         string `json:"signature,omitempty"`
	SBOM              string `json:"sbom,omitempty"`
	Provenance        string `json:"provenance,omitempty"`
	VulnerabilityScan string `json:"vulnerabilityScan,omitempty"`
	Tests             string `json:"tests,omitempty"`
}

// Evidence channel statuses in an assessment.
const (
	EvidenceStatusMissing  = "missing"
	EvidenceStatusObserved = "observed"
	EvidenceStatusVerified = "verified"
	EvidenceStatusAttested = "attested"
)

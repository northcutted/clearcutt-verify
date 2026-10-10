package estategraph

const (
	APIVersion = "clearcutt.dev/v1"
)

type ImagesFile struct {
	APIVersion   string      `json:"apiVersion,omitempty"`
	Kind         string      `json:"kind,omitempty"`
	Owner        string      `json:"owner,omitempty"`
	Repo         string      `json:"repo,omitempty"`
	RegistryBase string      `json:"registryBase,omitempty"`
	GeneratedAt  string      `json:"generatedAt,omitempty"`
	Images       []ImageSpec `json:"images"`
}

type ImageSpec struct {
	ID              string           `json:"id"`
	Image           string           `json:"image"`
	Tag             string           `json:"tag,omitempty"`
	Language        LanguageInfo     `json:"language"`
	Tier            string           `json:"tier"`
	Architectures   []string         `json:"architectures,omitempty"`
	Lifecycle       *Lifecycle       `json:"lifecycle,omitempty"`
	RuntimeContract *RuntimeContract `json:"runtimeContract,omitempty"`
	Origin          *ImageOrigin     `json:"origin,omitempty"`
	Governance      *ImageGovernance `json:"governance,omitempty"`
	EvidencePolicy  *EvidencePolicy  `json:"evidencePolicy,omitempty"`
}

type ImportOptions struct {
	RefsPath         string
	Owner            string
	Repo             string
	RegistryBase     string
	DefaultTier      string
	DefaultLifecycle string
	GeneratedAt      string
}

type ImportSummary struct {
	GeneratedAt   string               `json:"generatedAt"`
	Output        string               `json:"output,omitempty"`
	ImageCount    int                  `json:"imageCount"`
	LowConfidence int                  `json:"lowConfidence"`
	Images        []ImportImageSummary `json:"images"`
}

type ImportImageSummary struct {
	ID                       string `json:"id"`
	Image                    string `json:"image"`
	Language                 string `json:"language"`
	LanguageVersion          string `json:"languageVersion"`
	Tier                     string `json:"tier"`
	ClassificationConfidence string `json:"classificationConfidence"`
}

type Observations struct {
	APIVersion  string        `json:"apiVersion"`
	Kind        string        `json:"kind"`
	GeneratedAt string        `json:"generatedAt"`
	Images      []Observation `json:"images"`
}

type Observation struct {
	ID             string               `json:"id"`
	SourceRef      string               `json:"sourceRef"`
	DigestRef      string               `json:"digestRef,omitempty"`
	ManifestDigest string               `json:"manifestDigest,omitempty"`
	ConfigDigest   string               `json:"configDigest,omitempty"`
	Platforms      []string             `json:"platforms"`
	Created        string               `json:"created,omitempty"`
	User           string               `json:"user,omitempty"`
	Entrypoint     []string             `json:"entrypoint"`
	Cmd            []string             `json:"cmd"`
	Labels         map[string]string    `json:"labels"`
	Annotations    map[string]string    `json:"annotations"`
	Layers         []LayerObservation   `json:"layers"`
	History        []HistoryObservation `json:"history"`
	Evidence       EvidenceObservation  `json:"evidence"`
	Warnings       []string             `json:"warnings"`
}

type LayerObservation struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"mediaType"`
}

type HistoryObservation struct {
	CreatedBy  string `json:"createdBy,omitempty"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"emptyLayer,omitempty"`
}

type EvidenceObservation struct {
	Signature         EvidenceChannel `json:"signature"`
	SBOM              EvidenceChannel `json:"sbom"`
	Provenance        EvidenceChannel `json:"provenance"`
	VulnerabilityScan EvidenceChannel `json:"vulnerabilityScan"`
	Tests             EvidenceChannel `json:"tests"`
}

type EvidenceChannel struct {
	Status string `json:"status"`
	Source string `json:"source"`
	Claim  string `json:"claim,omitempty"`
}

type Assessment struct {
	GeneratedAt string            `json:"generatedAt"`
	Summary     AssessmentSummary `json:"summary"`
	Images      []ImageAssessment `json:"images"`
}

type AssessmentSummary struct {
	ImportedImages               int            `json:"importedImages"`
	ResolvedDigestRefs           int            `json:"resolvedDigestRefs"`
	MutableOrUnresolvedRefs      int            `json:"mutableOrUnresolvedRefs"`
	LowConfidenceClassifications int            `json:"lowConfidenceClassifications"`
	MissingEvidenceByChannel     map[string]int `json:"missingEvidenceByChannel"`
	ObservedEvidenceByChannel    map[string]int `json:"observedEvidenceByChannel"`
	VerifiedEvidenceByChannel    map[string]int `json:"verifiedEvidenceByChannel"`
	RuntimeContractGapsByType    map[string]int `json:"runtimeContractGapsByType"`
	PolicyPostureByStatus        map[string]int `json:"policyPostureByStatus"`
	ImagesByRuntime              map[string]int `json:"imagesByRuntime"`
	ImagesByTier                 map[string]int `json:"imagesByTier"`
}

type ImageAssessment struct {
	ID                       string   `json:"id"`
	Image                    string   `json:"image"`
	Language                 string   `json:"language"`
	Tier                     string   `json:"tier"`
	DigestRef                string   `json:"digestRef,omitempty"`
	MutableRef               bool     `json:"mutableRef"`
	ClassificationConfidence string   `json:"classificationConfidence"`
	PolicyPosture            string   `json:"policyPosture"`
	MissingEvidence          []string `json:"missingEvidence"`
	ObservedEvidence         []string `json:"observedEvidence"`
	VerifiedEvidence         []string `json:"verifiedEvidence"`
	RuntimeContractGaps      []string `json:"runtimeContractGaps"`
	Warnings                 []string `json:"warnings"`
}

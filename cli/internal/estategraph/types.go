package estategraph

import "github.com/northcutted/clearcutt-verify/internal/catalog"

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
	ID              string                   `json:"id"`
	Image           string                   `json:"image"`
	Tag             string                   `json:"tag,omitempty"`
	Language        catalog.LanguageInfo     `json:"language"`
	Tier            string                   `json:"tier"`
	Architectures   []string                 `json:"architectures,omitempty"`
	Lifecycle       *catalog.Lifecycle       `json:"lifecycle,omitempty"`
	RuntimeContract *catalog.RuntimeContract `json:"runtimeContract,omitempty"`
	Origin          *catalog.ImageOrigin     `json:"origin,omitempty"`
	Governance      *catalog.ImageGovernance `json:"governance,omitempty"`
	EvidencePolicy  *catalog.EvidencePolicy  `json:"evidencePolicy,omitempty"`
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
	CatalogedImages              int            `json:"catalogedImages"`
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

type AppInventory struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Apps       []AppSpec `json:"apps"`
}

type AppSpec struct {
	ID            string `json:"id"`
	Image         string `json:"image"`
	RuntimeFamily string `json:"runtimeFamily"`
	ExpectedBase  string `json:"expectedBase"`
	TestCommand   string `json:"testCommand"`
	ProductionTag string `json:"productionTag"`
}

type RebaseCandidateSet struct {
	APIVersion  string            `json:"apiVersion"`
	Kind        string            `json:"kind"`
	GeneratedAt string            `json:"generatedAt"`
	Candidates  []RebaseCandidate `json:"candidates"`
}

type RebaseCandidate struct {
	ID                 string         `json:"id"`
	AppImage           string         `json:"appImage"`
	AppDigest          string         `json:"appDigest,omitempty"`
	OldBaseID          string         `json:"oldBaseId,omitempty"`
	OldBaseDigest      string         `json:"oldBaseDigest,omitempty"`
	NewBaseCandidates  []string       `json:"newBaseCandidates"`
	Confidence         string         `json:"confidence"`
	Signals            []RebaseSignal `json:"signals"`
	Blockers           []string       `json:"blockers"`
	RequiredValidation []string       `json:"requiredValidation"`
	TestCommand        string         `json:"testCommand,omitempty"`
}

type RebaseSignal struct {
	Type   string `json:"type"`
	Result string `json:"result"`
	Weight string `json:"weight"`
}

type RebasePlan struct {
	APIVersion                  string             `json:"apiVersion"`
	Kind                        string             `json:"kind"`
	CandidateID                 string             `json:"candidateId"`
	Confidence                  string             `json:"confidence"`
	AllowedToApplyAutomatically bool               `json:"allowedToApplyAutomatically"`
	AppImage                    string             `json:"appImage"`
	OldBase                     RebasePlanBase     `json:"oldBase"`
	NewBase                     RebasePlanBase     `json:"newBase"`
	LayerPlan                   RebaseLayerPlan    `json:"layerPlan"`
	Validation                  RebaseValidation   `json:"validation"`
	Commands                    RebasePlanCommands `json:"commands"`
	Warnings                    []string           `json:"warnings"`
}

type RebasePlanBase struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type RebaseLayerPlan struct {
	OldBaseLayerCount int `json:"oldBaseLayerCount"`
	AppLayerCount     int `json:"appLayerCount"`
	NewBaseLayerCount int `json:"newBaseLayerCount"`
	ResultLayerCount  int `json:"resultLayerCount"`
}

type RebaseValidation struct {
	CertificationRequired bool `json:"certificationRequired"`
	TestCommandRequired   bool `json:"testCommandRequired"`
	HumanApprovalRequired bool `json:"humanApprovalRequired"`
}

type RebasePlanCommands struct {
	ExperimentalApply string `json:"experimentalApply"`
	Certify           string `json:"certify"`
}

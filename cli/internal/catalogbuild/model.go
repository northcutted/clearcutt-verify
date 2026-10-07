package catalogbuild

import (
	"encoding/json"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func FirstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func PtrIfNotEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func firstNonEmptyPtr(values ...string) *string {
	return PtrIfNotEmpty(FirstNonEmptyStr(values...))
}

// -- catalog image/index assembly --------------------------------------------

type gatherLanguageDef struct {
	ID      string
	Display string
	Version string
}

type gatherTierDef struct {
	Name  string
	Blurb string
}

var gatherLanguageOrder = []string{
	"coreLTS",
	"java21",
	"java25",
	"node22",
	"node24",
	"python3.13",
	"python3.14",
	"go1.25",
	"go1.26",
	"dotnet8",
	"dotnet10",
	"rust1.95",
	"cc15",
}

var gatherLanguages = map[string]gatherLanguageDef{
	"coreLTS":    {ID: "core", Display: "Core", Version: "LTS"},
	"java21":     {ID: "java", Display: "Java", Version: "21"},
	"java25":     {ID: "java", Display: "Java", Version: "25"},
	"node22":     {ID: "node", Display: "Node.js", Version: "22"},
	"node24":     {ID: "node", Display: "Node.js", Version: "24"},
	"python3.13": {ID: "python", Display: "Python", Version: "3.13"},
	"python3.14": {ID: "python", Display: "Python", Version: "3.14"},
	"go1.25":     {ID: "go", Display: "Go", Version: "1.25"},
	"go1.26":     {ID: "go", Display: "Go", Version: "1.26"},
	"dotnet8":    {ID: "dotnet", Display: ".NET", Version: "8"},
	"dotnet10":   {ID: "dotnet", Display: ".NET", Version: "10"},
	"rust1.95":   {ID: "rust", Display: "Rust", Version: "1.95"},
	"cc15":       {ID: "cc", Display: "C/C++", Version: "15"},
}

var gatherTierOrder = []string{"dev", "slim", "distroless"}

var gatherTiers = map[string]gatherTierDef{
	"dev":        {Name: "Dev", Blurb: "Builder tier — full toolchain, shells, debug utilities, credential helper."},
	"slim":       {Name: "Slim", Blurb: "Runtime tier — language runtime plus minimal troubleshooting binaries."},
	"distroless": {Name: "Distroless", Blurb: "Hardened tier — no shells, no coreutils, runtime only."},
}

// serviceTier is the compatibility tier every service image carries. It is
// appended to the index tiers list whenever the catalog contains service
// images so images[].tier always resolves against tiers[].
var serviceTier = Tier{ID: "service", Name: "Service", Blurb: "Platform-owned service image"}

type Language struct {
	ID          string  `json:"id"`
	DisplayName string  `json:"displayName"`
	Version     string  `json:"version"`
	Icon        *string `json:"icon"`
}

type Tier struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Blurb string `json:"blurb"`
}

type ImageRecord struct {
	SchemaVersion   string               `json:"schemaVersion,omitempty"`
	ID              string               `json:"id"`
	Kind            string               `json:"kind,omitempty"`
	Language        Language             `json:"language"`
	Tier            Tier                 `json:"tier"`
	Registry        string               `json:"registry"`
	ImageName       string               `json:"imageName"`
	FullName        string               `json:"fullName"`
	Releases        []gatherReleaseEntry `json:"releases"`
	Lifecycle       Lifecycle            `json:"lifecycle"`
	RuntimeContract RuntimeContract      `json:"runtimeContract"`
	Service         *catalog.ServiceInfo `json:"service,omitempty"`
}

type gatherReleaseEntry struct {
	Tag             string                   `json:"tag"`
	PublishedAt     string                   `json:"publishedAt"`
	LastRebuiltAt   string                   `json:"lastRebuiltAt"`
	IsLatest        bool                     `json:"isLatest"`
	ManifestDigest  *string                  `json:"manifestDigest"`
	TotalSize       *int64                   `json:"totalSize"`
	Architectures   []gatherArchPayload      `json:"architectures"`
	Signature       *Signature               `json:"signature"`
	Provenance      *Provenance              `json:"provenance"`
	Attestations    []gatherAttestation      `json:"attestations"`
	AssetURLs       gatherAssetURLs          `json:"assetUrls"`
	Lifecycle       Lifecycle                `json:"lifecycle"`
	RuntimeContract RuntimeContract          `json:"runtimeContract"`
	Exceptions      catalog.ExceptionSummary `json:"exceptions"`
	Evidence        catalog.EvidenceSummary  `json:"evidence"`
}

type gatherArchPayload struct {
	Arch                   string                       `json:"arch"`
	OS                     string                       `json:"os"`
	ImageDigest            *string                      `json:"imageDigest"`
	ImageSize              *int64                       `json:"imageSize"`
	ManifestDescriptorSize *int64                       `json:"manifestDescriptorSize,omitempty"`
	LayerCount             *int                         `json:"layerCount"`
	Layers                 []json.RawMessage            `json:"layers"`
	Labels                 json.RawMessage              `json:"labels"`
	SBOM                   gatherSBOMInfo               `json:"sbom"`
	TestResults            *TestResults                 `json:"testResults"`
	Vulnerabilities        *json.RawMessage             `json:"vulnerabilities,omitempty"`
	vulnInfo               *catalog.VulnerabilitiesInfo `json:"-"`
}

type gatherSBOMInfo struct {
	Tool         string           `json:"tool"`
	CreatedAt    string           `json:"createdAt"`
	RootDigest   *string          `json:"rootDigest"`
	PackageCount int              `json:"packageCount"`
	Packages     []spdxPackageOut `json:"packages"`
}

type TestResults struct {
	Status     string      `json:"status"`
	Timestamp  *string     `json:"timestamp"`
	Assertions []Assertion `json:"assertions"`
}

type Assertion struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Signature struct {
	CosignBundlePresent bool         `json:"cosignBundlePresent"`
	RekorLogIndex       *int64       `json:"rekorLogIndex"`
	Certificate         *Certificate `json:"certificate"`
}

type Certificate struct {
	Subject       *string `json:"subject"`
	Issuer        *string `json:"issuer"`
	RunInvocation *string `json:"runInvocation"`
}

type gatherAttestation struct {
	Kind                 string   `json:"kind"`
	PredicateType        string   `json:"predicateType"`
	SubjectName          *string  `json:"subjectName"`
	SubjectDigest        *string  `json:"subjectDigest"`
	SignerIdentity       *string  `json:"signerIdentity"`
	Issuer               *string  `json:"issuer"`
	RunURL               *string  `json:"runUrl"`
	WorkflowURL          *string  `json:"workflowUrl"`
	GithubAPIURL         *string  `json:"githubApiUrl"`
	TransparencyLogIndex *int64   `json:"transparencyLogIndex"`
	TransparencyURL      *string  `json:"transparencyUrl"`
	Sources              []string `json:"sources"`
	ReleaseAssetURL      *string  `json:"releaseAssetUrl"`
}

type EnrichmentAttestation struct {
	Kind                 string   `json:"kind"`
	PredicateType        string   `json:"predicateType"`
	SubjectName          *string  `json:"subjectName"`
	SubjectDigest        *string  `json:"subjectDigest"`
	SignerIdentity       *string  `json:"signerIdentity"`
	Issuer               *string  `json:"issuer"`
	RunURL               *string  `json:"runUrl"`
	WorkflowURL          *string  `json:"workflowUrl"`
	GithubAPIURL         *string  `json:"githubApiUrl"`
	TransparencyLogIndex *int64   `json:"transparencyLogIndex"`
	TransparencyURL      *string  `json:"transparencyUrl"`
	Sources              []string `json:"sources"`
}

type gatherAssetURLs struct {
	SBOM        map[string]string `json:"sbom"`
	Provenance  *string           `json:"provenance"`
	TestResults map[string]string `json:"testResults"`
	Digest      *string           `json:"digest"`
}

type ImageSummary struct {
	ID                   string                  `json:"id"`
	Kind                 string                  `json:"kind,omitempty"`
	Language             string                  `json:"language"`
	LanguageDisplay      string                  `json:"languageDisplay"`
	LanguageVersion      string                  `json:"languageVersion"`
	Tier                 string                  `json:"tier"`
	LatestTag            string                  `json:"latestTag"`
	LatestManifestDigest *string                 `json:"latestManifestDigest"`
	LatestPackageCount   int                     `json:"latestPackageCount"`
	Architectures        []string                `json:"architectures"`
	Signed               bool                    `json:"signed"`
	Provenance           bool                    `json:"provenance"`
	Evidence             catalog.EvidenceSummary `json:"evidence"`
	Passed               bool                    `json:"passed"`
	VulnSummary          *gatherVulnSummary      `json:"vulnSummary"`
	Lifecycle            Lifecycle               `json:"lifecycle"`
	RuntimeContract      RuntimeContract         `json:"runtimeContract"`
	Service              *catalog.ServiceInfo    `json:"service,omitempty"`
}

type gatherVulnSummary struct {
	Critical    int                       `json:"critical"`
	High        int                       `json:"high"`
	Medium      int                       `json:"medium"`
	Low         int                       `json:"low"`
	ScannedAt   *string                   `json:"scannedAt"`
	Remediation catalog.RemediationCounts `json:"remediation"`
}

type Index struct {
	SchemaVersion string                   `json:"schemaVersion,omitempty"`
	GeneratedAt   string                   `json:"generatedAt"`
	Owner         string                   `json:"owner"`
	Repo          string                   `json:"repo"`
	RepoURL       string                   `json:"repoUrl"`
	RegistryBase  string                   `json:"registryBase"`
	LatestTag     string                   `json:"latestTag"`
	Releases      []catalog.ReleaseSummary `json:"releases"`
	Languages     []Language               `json:"languages"`
	Tiers         []Tier                   `json:"tiers"`
	Images        []ImageSummary           `json:"images"`
}

type Release struct {
	Tag         string
	Name        string
	PublishedAt string
	Prerelease  bool
	Assets      []Asset
}

type Asset struct {
	Name   string
	URL    string
	Size   int64
	Digest *string
}

type ReleaseSource interface {
	ListReleases(limit int) ([]Release, error)
	DownloadAsset(asset Asset) ([]byte, error)
}

type BuildOptions struct {
	RegistryBase  string
	ImagePrefix   string
	SBOMCacheDir  string
	EnrichmentDir string
	VulnDir       string
	Source        ReleaseSource
}

package estategraph

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

func ReadAppInventory(path string) (AppInventory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return AppInventory{}, err
	}
	var inventory AppInventory
	if err := yaml.Unmarshal(raw, &inventory); err != nil {
		return AppInventory{}, err
	}
	return inventory, nil
}

func DiscoverRebaseCandidates(apps AppInventory, bases ImagesFile, observations Observations, generatedAt string) (RebaseCandidateSet, error) {
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	obsByID := map[string]Observation{}
	obsBySource := map[string]Observation{}
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		if obs.ID != "" {
			obsByID[obs.ID] = obs
		}
		if obs.SourceRef != "" {
			obsBySource[obs.SourceRef] = obs
		}
	}
	baseByID := map[string]ImageSpec{}
	for _, base := range bases.Images {
		baseByID[base.ID] = base
	}
	out := RebaseCandidateSet{APIVersion: APIVersion, Kind: "RebaseCandidateSet", GeneratedAt: generatedAt, Candidates: []RebaseCandidate{}}
	appList := append([]AppSpec(nil), apps.Apps...)
	sort.SliceStable(appList, func(i, j int) bool { return appList[i].ID < appList[j].ID })
	for _, app := range appList {
		candidate := discoverAppCandidate(app, baseByID, obsByID, obsBySource)
		out.Candidates = append(out.Candidates, candidate)
	}
	return out, nil
}

func WriteRebaseCandidates(path string, candidates RebaseCandidateSet) error {
	return writeJSON(path, candidates)
}

func ReadRebaseCandidates(path string) (RebaseCandidateSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RebaseCandidateSet{}, err
	}
	var candidates RebaseCandidateSet
	if err := unmarshalJSON(raw, &candidates); err != nil {
		return RebaseCandidateSet{}, err
	}
	return candidates, nil
}

func discoverAppCandidate(app AppSpec, baseByID map[string]ImageSpec, obsByID, obsBySource map[string]Observation) RebaseCandidate {
	appObs := obsBySource[app.Image]
	if appObs.SourceRef == "" {
		appObs = obsByID[app.ID]
	}
	candidate := RebaseCandidate{
		ID:                 app.ID,
		AppImage:           app.Image,
		AppDigest:          digestOnly(appObs.DigestRef),
		OldBaseID:          app.ExpectedBase,
		Confidence:         "unsafe",
		Signals:            []RebaseSignal{},
		Blockers:           []string{},
		RequiredValidation: []string{"run app test command", "run clearcutt-verify certify", "human approval required before publish"},
		TestCommand:        app.TestCommand,
		NewBaseCandidates:  []string{},
	}
	oldBase, hasOldBase := baseByID[app.ExpectedBase]
	oldObs := obsByID[app.ExpectedBase]
	if oldObs.ID == "" && hasOldBase {
		oldObs = obsBySource[oldBase.Image]
	}
	candidate.OldBaseDigest = digestOnly(firstNonEmpty(oldObs.DigestRef, oldObs.ManifestDigest))
	for _, base := range sortedBases(baseByID) {
		if base.ID == app.ExpectedBase {
			continue
		}
		if !runtimeFamiliesCompatible(app.RuntimeFamily, base.Language.ID) {
			continue
		}
		if hasOldBase && !baseContractsCompatible(oldBase, base) {
			continue
		}
		obs := obsByID[base.ID]
		if obs.ID == "" {
			obs = obsBySource[base.Image]
		}
		newDigest := digestOnly(firstNonEmpty(obs.DigestRef, obs.ManifestDigest))
		if newDigest == "" || newDigest == candidate.OldBaseDigest || len(obs.Layers) == 0 {
			continue
		}
		if !platformsOverlap(observationPlatforms(appObs, nil), observationPlatforms(obs, base.Architectures)) {
			continue
		}
		candidate.NewBaseCandidates = append(candidate.NewBaseCandidates, base.ID+"@"+newDigest)
	}
	if !hasOldBase {
		candidate.Blockers = append(candidate.Blockers, "expected base is not present in base inventory")
	}
	if appObs.DigestRef == "" && appObs.ManifestDigest == "" {
		candidate.Blockers = append(candidate.Blockers, "app image digest unknown")
	}
	if candidate.OldBaseDigest == "" {
		candidate.Blockers = append(candidate.Blockers, "old base digest unknown")
	}
	if len(candidate.NewBaseCandidates) == 0 {
		candidate.Blockers = append(candidate.Blockers, "new base digest unknown")
	}
	if hasOldBase && !runtimeFamiliesCompatible(app.RuntimeFamily, oldBase.Language.ID) {
		candidate.Blockers = append(candidate.Blockers, "runtime family mismatch")
	}
	if hasLayerPrefix(appObs.Layers, oldObs.Layers) && len(candidate.Blockers) == 0 {
		candidate.Confidence = "verified"
		candidate.Signals = append(candidate.Signals, RebaseSignal{Type: "layer-prefix", Result: "matched", Weight: "strong"})
		return candidate
	}
	if len(appObs.Layers) > 0 && len(oldObs.Layers) > 0 {
		candidate.Blockers = append(candidate.Blockers, "base layer prefix did not match")
		candidate.Signals = append(candidate.Signals, RebaseSignal{Type: "layer-prefix", Result: "not-matched", Weight: "strong"})
	}
	if labelOrHistoryMatches(appObs, app.ExpectedBase, candidate.OldBaseDigest) && len(candidate.Blockers) == 0 {
		candidate.Confidence = "assisted"
		candidate.Signals = append(candidate.Signals, RebaseSignal{Type: "labels-or-history", Result: "matched", Weight: "medium"})
		return candidate
	}
	if len(candidate.Blockers) == 0 {
		candidate.Blockers = append(candidate.Blockers, "base boundary cannot be proven")
	}
	return candidate
}

func PlanRebase(candidates RebaseCandidateSet, candidateID, newBase string, observations Observations) (RebasePlan, error) {
	var candidate *RebaseCandidate
	for i := range candidates.Candidates {
		if candidates.Candidates[i].ID == candidateID {
			candidate = &candidates.Candidates[i]
			break
		}
	}
	if candidate == nil {
		return RebasePlan{}, fmt.Errorf("candidate %q not found", candidateID)
	}
	if candidate.Confidence == "unsafe" {
		return RebasePlan{}, fmt.Errorf("candidate %q is unsafe; rebase plan requires verified or assisted confidence", candidateID)
	}
	if !contains(candidate.NewBaseCandidates, newBase) {
		return RebasePlan{}, fmt.Errorf("new base %q is not one of the discovered candidates", newBase)
	}
	obsByID := map[string]Observation{}
	obsBySource := map[string]Observation{}
	for _, obs := range observations.Images {
		normalizeObservation(&obs)
		obsByID[obs.ID] = obs
		obsBySource[obs.SourceRef] = obs
	}
	if candidate.OldBaseID == strings.SplitN(newBase, "@", 2)[0] {
		return RebasePlan{}, fmt.Errorf("new base must differ from old base %q", candidate.OldBaseID)
	}
	if candidate.OldBaseDigest == digestOnly(newBase) {
		return RebasePlan{}, fmt.Errorf("new base digest must differ from old base digest")
	}
	oldLayers := len(obsByID[candidate.OldBaseID].Layers)
	newID := strings.SplitN(newBase, "@", 2)[0]
	newObs := obsByID[newID]
	newLayers := len(newObs.Layers)
	if newLayers == 0 {
		return RebasePlan{}, fmt.Errorf("new base %q has no observed layers", newID)
	}
	appObs := obsByID[candidate.ID]
	if appObs.ID == "" {
		appObs = obsBySource[candidate.AppImage]
	}
	if !platformsOverlap(observationPlatforms(appObs, nil), observationPlatforms(newObs, nil)) {
		return RebasePlan{}, fmt.Errorf("new base %q has no observed platform overlap with app image", newID)
	}
	appLayers := 0
	if oldLayers > 0 {
		appLayers = max(0, len(appObs.Layers)-oldLayers)
	}
	return RebasePlan{
		APIVersion:                  APIVersion,
		Kind:                        "ImportedFleetRebasePlan",
		CandidateID:                 candidate.ID,
		Confidence:                  candidate.Confidence,
		AllowedToApplyAutomatically: false,
		AppImage:                    candidate.AppImage,
		OldBase:                     RebasePlanBase{ID: candidate.OldBaseID, Digest: candidate.OldBaseDigest},
		NewBase:                     RebasePlanBase{ID: newID, Digest: digestOnly(newBase)},
		LayerPlan: RebaseLayerPlan{
			OldBaseLayerCount: oldLayers,
			AppLayerCount:     appLayers,
			NewBaseLayerCount: newLayers,
			ResultLayerCount:  newLayers + appLayers,
		},
		Validation: RebaseValidation{CertificationRequired: true, TestCommandRequired: true, HumanApprovalRequired: true},
		Commands: RebasePlanCommands{
			ExperimentalApply: "",
			Certify:           "clearcutt-verify certify <rebased-image> --require-signature --require-sbom --require-provenance",
		},
		Warnings: []string{"plan only; imported-fleet rebase does not publish or mutate production tags"},
	}, nil
}

func WriteRebasePlan(path string, plan RebasePlan) error {
	return writeJSON(path, plan)
}

func sortedBases(baseByID map[string]ImageSpec) []ImageSpec {
	out := make([]ImageSpec, 0, len(baseByID))
	for _, base := range baseByID {
		out = append(out, base)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func hasLayerPrefix(appLayers, baseLayers []LayerObservation) bool {
	if len(appLayers) == 0 || len(baseLayers) == 0 || len(appLayers) < len(baseLayers) {
		return false
	}
	for i := range baseLayers {
		if appLayers[i].Digest != baseLayers[i].Digest {
			return false
		}
	}
	return true
}

func labelOrHistoryMatches(obs Observation, baseID, digest string) bool {
	for _, key := range []string{"org.opencontainers.image.base.name", "org.opencontainers.image.base.digest", "io.buildpacks.stack.id", "io.buildpacks.lifecycle.metadata"} {
		value := obs.Labels[key]
		if value != "" && (strings.Contains(value, baseID) || (digest != "" && strings.Contains(value, digest))) {
			return true
		}
	}
	for _, hist := range obs.History {
		value := strings.ToLower(hist.CreatedBy + " " + hist.Comment)
		if strings.Contains(value, strings.ToLower(baseID)) || (digest != "" && strings.Contains(value, strings.ToLower(digest))) {
			return true
		}
	}
	return false
}

func runtimeFamiliesCompatible(appFamily, baseFamily string) bool {
	if appFamily == "" || appFamily == "unknown" {
		return true
	}
	return strings.EqualFold(appFamily, baseFamily)
}

func baseContractsCompatible(oldBase, newBase ImageSpec) bool {
	if !strings.EqualFold(oldBase.Tier, newBase.Tier) {
		return false
	}
	if oldBase.RuntimeContract == nil || newBase.RuntimeContract == nil {
		return oldBase.RuntimeContract == nil && newBase.RuntimeContract == nil
	}
	oldContract := oldBase.RuntimeContract
	newContract := newBase.RuntimeContract
	return stringPointersEqual(oldContract.User, newContract.User) &&
		stringPointersEqual(oldContract.WorkingDir, newContract.WorkingDir) &&
		boolPointersEqual(oldContract.ShellPresent, newContract.ShellPresent) &&
		boolPointersEqual(oldContract.PackageManagerPresent, newContract.PackageManagerPresent) &&
		boolPointersEqual(oldContract.CACertificatesPresent, newContract.CACertificatesPresent) &&
		boolPointersEqual(oldContract.TimezoneDataPresent, newContract.TimezoneDataPresent) &&
		stringPointersEqual(oldContract.DefaultEntrypoint, newContract.DefaultEntrypoint) &&
		oldContract.ProductionTier == newContract.ProductionTier
}

func stringPointersEqual(left, right *string) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func boolPointersEqual(left, right *bool) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func observationPlatforms(obs Observation, fallback []string) []string {
	if len(obs.Platforms) > 0 {
		return obs.Platforms
	}
	out := make([]string, 0, len(fallback))
	for _, architecture := range fallback {
		if strings.Contains(architecture, "/") {
			out = append(out, architecture)
		} else if architecture != "" {
			out = append(out, "linux/"+architecture)
		}
	}
	return out
}

func platformsOverlap(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(left))
	for _, platform := range left {
		set[strings.ToLower(platform)] = struct{}{}
	}
	for _, platform := range right {
		if _, ok := set[strings.ToLower(platform)]; ok {
			return true
		}
	}
	return false
}

func digestOnly(value string) string {
	if value == "" {
		return ""
	}
	if i := strings.LastIndex(value, "@"); i >= 0 {
		return value[i+1:]
	}
	if i := strings.LastIndex(value, "sha256:"); i >= 0 {
		return value[i:]
	}
	return value
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

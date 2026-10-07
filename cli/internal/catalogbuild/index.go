package catalogbuild

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
)

func Targets(filter string) []string {
	allowed := map[string]bool{}
	order := []string{}
	if filter != "" {
		for _, target := range strings.Split(filter, ",") {
			target = strings.TrimSpace(target)
			if target != "" {
				allowed[target] = true
				order = append(order, target)
			}
		}
	}
	targets := []string{}
	seen := map[string]bool{}
	for _, langKey := range gatherLanguageOrder {
		for _, tier := range gatherTierOrder {
			target := langKey + "-" + tier
			if len(allowed) == 0 || allowed[target] {
				targets = append(targets, target)
				seen[target] = true
			}
		}
	}
	for _, target := range order {
		if !seen[target] {
			targets = append(targets, target)
			seen[target] = true
		}
	}
	return targets
}

func BuildIndex(owner, repo, registryBase, generatedAt string, releases []Release, images []ImageRecord) Index {
	var latest *Release
	for i := range releases {
		if !releases[i].Prerelease {
			latest = &releases[i]
			break
		}
	}
	if latest == nil && len(releases) > 0 {
		latest = &releases[0]
	}
	releaseSummaries := make([]catalog.ReleaseSummary, 0, len(releases))
	for i := range releases {
		releaseSummaries = append(releaseSummaries, catalog.ReleaseSummary{
			Tag:         releases[i].Tag,
			PublishedAt: releases[i].PublishedAt,
			IsLatest:    latest != nil && releases[i].Tag == latest.Tag,
		})
	}
	summaries := make([]ImageSummary, 0, len(images))
	hasV2Image := false
	for _, img := range images {
		if img.Kind != "" || img.Service != nil {
			hasV2Image = true
		}
		if len(img.Releases) > 0 {
			summaries = append(summaries, SummarizeImageForIndex(img))
		}
	}
	latestTag := ""
	if latest != nil {
		latestTag = latest.Tag
	}
	schemaVersion := catalog.CatalogIndexSchemaVersion
	if hasV2Image {
		schemaVersion = catalog.CatalogIndexSchemaVersionV2
		// The v2 index schema requires kind on every image summary; runtime
		// records never carry one, so default them explicitly.
		for i := range summaries {
			if summaries[i].Kind == "" {
				summaries[i].Kind = "runtime"
			}
		}
	}
	return Index{
		SchemaVersion: schemaVersion,
		GeneratedAt:   generatedAt,
		Owner:         owner,
		Repo:          repo,
		RepoURL:       fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		RegistryBase:  registryBase,
		LatestTag:     latestTag,
		Releases:      releaseSummaries,
		Languages:     languageList(),
		Tiers:         tierList(images),
		Images:        summaries,
	}
}

func languageList() []Language {
	out := []Language{}
	seen := map[string]int{}
	for _, key := range gatherLanguageOrder {
		lang := gatherLanguages[key]
		entry := Language{ID: lang.ID, DisplayName: lang.Display, Version: lang.Version}
		seenKey := lang.ID + "-" + lang.Version
		if idx, ok := seen[seenKey]; ok {
			out[idx] = entry
			continue
		}
		seen[seenKey] = len(out)
		out = append(out, entry)
	}
	return out
}

func tierList(images []ImageRecord) []Tier {
	out := make([]Tier, 0, len(gatherTierOrder)+1)
	for _, id := range gatherTierOrder {
		tier := gatherTiers[id]
		out = append(out, Tier{ID: id, Name: tier.Name, Blurb: tier.Blurb})
	}
	// Service images reference tier "service"; surface it in the index tier
	// list so every images[].tier resolves against tiers[].
	for _, img := range images {
		if img.Kind == "service" {
			out = append(out, serviceTier)
			break
		}
	}
	return out
}

func RebuildIndexFromExistingImages(owner, repo, registryBase, outDir, vulnDir, generatedAt string) (bool, error) {
	imgDir := filepath.Join(outDir, "images")
	entries, err := os.ReadDir(imgDir)
	if err != nil {
		return false, nil
	}
	files := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return false, nil
	}
	images := []ImageRecord{}
	for _, file := range files {
		imagePath := filepath.Join(imgDir, file)
		data, err := os.ReadFile(imagePath)
		if err != nil {
			return false, err
		}
		var img ImageRecord
		if err := json.Unmarshal(data, &img); err != nil {
			return false, err
		}
		if img.SchemaVersion == "" {
			img.SchemaVersion = catalog.ImageRecordSchemaVersion
		}
		for i := range img.Releases {
			lastRebuiltAt := FirstNonEmptyStr(img.Releases[i].LastRebuiltAt, img.Releases[i].PublishedAt)
			for j := range img.Releases[i].Architectures {
				arch := &img.Releases[i].Architectures[j]
				raw, info := loadVulnerabilities(img.Releases[i].Tag, img.ID, arch.Arch, vulnDir)
				if raw != nil {
					arch.Vulnerabilities = raw
					arch.vulnInfo = info
				} else if arch.Vulnerabilities != nil {
					var parsed catalog.VulnerabilitiesInfo
					if err := json.Unmarshal(*arch.Vulnerabilities, &parsed); err == nil {
						arch.vulnInfo = &parsed
					}
				}
				if arch.vulnInfo != nil && arch.vulnInfo.ScannedAt != "" && arch.vulnInfo.ScannedAt > lastRebuiltAt {
					lastRebuiltAt = arch.vulnInfo.ScannedAt
				}
			}
			img.Releases[i].LastRebuiltAt = lastRebuiltAt
			img.Releases[i].Evidence = releaseEvidenceFromGather(&img.Releases[i])
		}
		if err := writeJSONFile(imagePath, img); err != nil {
			return false, err
		}
		if len(img.Releases) > 0 {
			images = append(images, img)
		}
	}
	if len(images) == 0 {
		return false, nil
	}

	byTag := map[string]Release{}
	for _, img := range images {
		for _, rel := range img.Releases {
			if _, ok := byTag[rel.Tag]; !ok {
				byTag[rel.Tag] = Release{Tag: rel.Tag, PublishedAt: rel.PublishedAt}
			}
		}
	}
	releases := make([]Release, 0, len(byTag))
	for _, rel := range byTag {
		releases = append(releases, rel)
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].PublishedAt > releases[j].PublishedAt })
	latestTag := ""
	if len(images[0].Releases) > 0 {
		latestTag = images[0].Releases[0].Tag
	}
	for i := range releases {
		releases[i].Prerelease = releases[i].Tag != latestTag
	}
	index := BuildIndex(owner, repo, registryBase, generatedAt, releases, images)
	index.LatestTag = latestTag
	for i := range index.Releases {
		index.Releases[i].IsLatest = index.Releases[i].Tag == latestTag
	}
	if err := writeJSONFile(filepath.Join(outDir, "index.json"), index); err != nil {
		return false, err
	}
	return true, nil
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

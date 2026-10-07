package estategraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ReadAssessmentDir(dir string) (Assessment, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "estate-summary.json"))
	if err != nil {
		return Assessment{}, err
	}
	var assessment Assessment
	if err := unmarshalJSON(raw, &assessment); err != nil {
		return Assessment{}, err
	}
	return assessment, nil
}

func ReportMarkdown(assessment Assessment) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Imported Fleet Report\n\n")
	fmt.Fprintf(&b, "## Executive summary\n\n")
	fmt.Fprintf(&b, "ClearCutt did not build this estate. It can catalog the images, preserve observed evidence, and report governance gaps without claiming false provenance.\n\n")
	b.WriteString(SummaryMarkdown(assessment))
	fmt.Fprintf(&b, "\n## What ClearCutt can govern\n\n")
	fmt.Fprintf(&b, "- Inventory and catalog visibility\n- Evidence gap reporting\n- Runtime contract posture\n- Mutable tag and digest pinning visibility\n- App/base relationship discovery\n- Rebase candidate planning\n\n")
	fmt.Fprintf(&b, "## What ClearCutt cannot prove\n\n")
	fmt.Fprintf(&b, "- It cannot infer signatures.\n- No build provenance is inferred for imported images unless actual provenance evidence is verified.\n- It cannot infer SLSA provenance.\n- It cannot prove source or build workflow for an image it did not build.\n- It cannot safely rebase every image.\n\n")
	fmt.Fprintf(&b, "## Imported image inventory\n\n")
	fmt.Fprintf(&b, "| Image | Runtime | Tier | Posture |\n|---|---|---|---|\n")
	for _, image := range assessment.Images {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", image.ID, image.Language, image.Tier, image.PolicyPosture)
	}
	fmt.Fprintf(&b, "\n## Evidence coverage\n\n")
	fmt.Fprintf(&b, "Observed evidence means the channel was seen in supplied metadata or observation output. Verified evidence means ClearCutt has an explicit verified channel status. Observed SBOM is not build provenance.\n\n")
	b.WriteString(EvidenceGapsMarkdown(assessment))
	fmt.Fprintf(&b, "\n## Runtime contract posture\n\n")
	if len(assessment.Summary.RuntimeContractGapsByType) == 0 {
		fmt.Fprintf(&b, "No runtime contract gaps were observed from available metadata.\n")
	} else {
		for _, image := range assessment.Images {
			if len(image.RuntimeContractGaps) > 0 {
				fmt.Fprintf(&b, "- %s: %s\n", image.ID, strings.Join(image.RuntimeContractGaps, ", "))
			}
		}
	}
	fmt.Fprintf(&b, "\n## Mutable tags and digest pinning\n\n")
	for _, image := range assessment.Images {
		if image.MutableRef {
			fmt.Fprintf(&b, "- %s remains mutable or unresolved: %s\n", image.ID, image.Image)
		}
	}
	fmt.Fprintf(&b, "\n## Suggested next actions\n\n")
	fmt.Fprintf(&b, "- Pin imported images to digests where possible.\n- Attach or verify SBOM, signature, vulnerability scan, test, and provenance evidence explicitly.\n- Treat low-confidence classifications as review items.\n- Use rebase plans only as auditable preparation; require tests, certification, and human approval before publishing.\n\n")
	fmt.Fprintf(&b, "## Rebase readiness\n\n")
	fmt.Fprintf(&b, "Run `clearcutt-verify rebase discover` with app and base inventories to produce candidate data. Plans never apply automatically.\n\n")
	fmt.Fprintf(&b, "## Appendix: command reproduction\n\n")
	fmt.Fprintf(&b, "```bash\nclearcutt import images --refs refs.txt --output images.yaml\nclearcutt catalog generate --images images.yaml --output dist/catalog\nclearcutt import observe --images images.yaml --output dist/imported/observations.json\nclearcutt import assess --images images.yaml --observations dist/imported/observations.json --catalog dist/catalog --output dist/governance\nclearcutt import report --assessment dist/governance --output imported-fleet-report.md\nclearcutt rebase discover --apps apps.yaml --bases images.yaml --observations dist/imported/observations.json --output dist/rebase/candidates.json\n```\n")
	return b.String()
}

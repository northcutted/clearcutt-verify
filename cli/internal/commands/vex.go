package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/catalog"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type vexFlags struct {
	tag            string
	output         string
	exceptionsFile string
}

var vexOpts vexFlags

type OpenVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Role       string             `json:"role"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []OpenVEXStatement `json:"statements"`
}

type OpenVEXStatement struct {
	Vulnerability   OpenVEXVulnerability   `json:"vulnerability"`
	Products        []OpenVEXProduct       `json:"products"`
	Status          string                 `json:"status"` // affected, not_affected, under_investigation, fixed
	Justification   string                 `json:"justification,omitempty"`
	ImpactStatement string                 `json:"impact_statement,omitempty"`
	Timestamp       string                 `json:"timestamp,omitempty"` // per-statement (OpenVEX-standard, optional)
	ClearCutt       *ClearCuttVEXExtension `json:"clearcutt,omitempty"` // policy-acceptance + expiry extension
}

type OpenVEXVulnerability struct {
	Name string `json:"name"`
}

type OpenVEXProduct struct {
	ID string `json:"@id"`
}

// The four statuses permitted by the OpenVEX spec.
const (
	vexNotAffected        = "not_affected"
	vexAffected           = "affected"
	vexFixed              = "fixed"
	vexUnderInvestigation = "under_investigation"
)

// vexStatusFromException maps the richer exception status vocabulary onto a
// valid OpenVEX status. Governance states that still acknowledge exposure, such
// as accepted_risk, must not become not_affected claims.
func vexStatusFromException(status string) string {
	switch strings.ToLower(status) {
	case "affected", "accepted_risk":
		return vexAffected
	case "fixed":
		return vexFixed
	case "under_investigation":
		return vexUnderInvestigation
	case "not_affected", "false_positive":
		return vexNotAffected
	default:
		return vexUnderInvestigation
	}
}

// vexJustificationFromReason maps an exception reason onto an OpenVEX
// justification enum. Only meaningful when the resulting status is not_affected.
func vexJustificationFromReason(reason string) string {
	switch strings.ToLower(reason) {
	case "vulnerable_code_not_present", "scanner_false_positive":
		return "vulnerable_code_not_present"
	case "vulnerable_code_not_executed", "inherited_from_base":
		return "vulnerable_code_not_in_execute_path"
	default:
		return "vulnerable_code_cannot_be_controlled_by_adversary"
	}
}

func vexReasonSupportsNotAffected(reason string) bool {
	switch strings.ToLower(reason) {
	case "vulnerable_code_not_present", "scanner_false_positive", "vulnerable_code_not_executed", "inherited_from_base":
		return true
	default:
		return false
	}
}

func NewVexCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vex <image-id>",
		Short: "Generate standard compliant OpenVEX documents dynamically",
		Long:  `Resolves base image vulnerability findings and exception statements, generating standard OpenVEX JSON documents dynamically.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVex(args[0])
		},
	}

	cmd.Flags().StringVar(&vexOpts.tag, "tag", "", "Target release tag version (defaults to latest)")
	cmd.Flags().StringVar(&vexOpts.output, "output", "", "Output JSON file path destination")
	cmd.Flags().StringVar(&vexOpts.exceptionsFile, "exceptions", "", "Path to local exceptions YAML triage governance file")

	return cmd
}

func runVex(imageID string) error {
	doc, err := buildOpenVEXDocument(imageID, vexOpts.tag, vexOpts.exceptionsFile, time.Now().UTC())
	if err != nil {
		return err
	}

	// Serialize
	outputData, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize OpenVEX document: %w", err)
	}

	if vexOpts.output != "" {
		if err := os.WriteFile(vexOpts.output, outputData, 0644); err != nil {
			return fmt.Errorf("failed to write OpenVEX file: %w", err)
		}
		if !GlobalOpts.Quiet {
			fmt.Fprintf(out, "Successfully generated OpenVEX compliance document: %s\n", vexOpts.output)
		}
	} else {
		// Output format checks
		switch strings.ToLower(GlobalOpts.Format) {
		case "yaml", "yml":
			if err := output.PrintYAML(out, doc); err != nil {
				return err
			}
		default:
			out.Write(outputData)
			fmt.Fprintln(out)
		}
	}

	return nil
}

func buildOpenVEXDocument(imageID, tag, exceptionsFile string, now time.Time) (OpenVEXDocument, error) {
	record, err := catalog.LoadImageRecord(GlobalOpts.CatalogPath, imageID)
	if err != nil {
		return OpenVEXDocument{}, err
	}

	if err := catalog.ValidateImageRecord(record); err != nil {
		return OpenVEXDocument{}, fmt.Errorf("image record validation failed: %w", err)
	}

	// Resolve the target release
	release, err := latestOrTaggedRelease(record.Releases, tag)
	if err != nil {
		return OpenVEXDocument{}, fmt.Errorf("%w for image %q", err, imageID)
	}

	// Load exceptions if provided
	var exceptionsDoc *ExceptionsDoc
	if exceptionsFile != "" {
		doc, err := LoadExceptionsFile(exceptionsFile)
		if err != nil {
			return OpenVEXDocument{}, fmt.Errorf("failed to load exceptions file: %w", err)
		}
		exceptionsDoc = doc
	}

	// Create OpenVEX Document
	doc := OpenVEXDocument{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("https://clearcutt.internal/vex/%s/%s", imageID, release.Tag),
		Author:     "ClearCutt Security Platform Gating Engine",
		Role:       "Document Creator",
		Timestamp:  now.Format(time.RFC3339),
		Version:    1,
		Statements: []OpenVEXStatement{},
	}

	// Iterate architectures and parse findings to extract VEX statements
	productID := fmt.Sprintf("pkg:nix/%s@%s", imageID, release.Tag)
	product := OpenVEXProduct{ID: productID}

	seenVulnerabilities := make(map[string]bool)

	for _, arch := range release.Architectures {
		if arch.Vulnerabilities == nil {
			continue
		}

		for _, finding := range arch.Vulnerabilities.Findings {
			if seenVulnerabilities[finding.ID] {
				continue
			}
			seenVulnerabilities[finding.ID] = true

			// Create VEX statement
			vuln := OpenVEXVulnerability{Name: finding.ID}
			stmt := OpenVEXStatement{
				Vulnerability: vuln,
				Products:      []OpenVEXProduct{product},
			}

			// An active (non-expired) exception governs the statement; expired
			// exceptions are ignored so they don't emit a stale not_affected claim.
			entry, expired := exceptionsDoc.Match(finding.ID, finding.PackageName, imageID, release.Tag, now)

			// Map onto OpenVEX. Per spec, a justification is only valid when the
			// status is not_affected, so we attach one there and nowhere else.
			switch {
			case entry != nil && !expired:
				stmt.Status = vexStatusFromException(entry.Status)
				stmt.ImpactStatement = entry.Notes
				if stmt.Status == vexNotAffected {
					if vexReasonSupportsNotAffected(entry.Reason) {
						stmt.Justification = vexJustificationFromReason(entry.Reason)
					} else {
						stmt.Status = vexUnderInvestigation
					}
				}
			case finding.Remediation != nil:
				reason := strings.ToLower(finding.Remediation.Reason)
				status := strings.ToLower(finding.Remediation.Status)
				stmt.ImpactStatement = finding.Remediation.Summary

				switch {
				case status == "deferred" && reason == "accepted_risk":
					stmt.Status = vexAffected
				case status == "ignored" && vexReasonSupportsNotAffected(reason):
					stmt.Status = vexNotAffected
					stmt.Justification = vexJustificationFromReason(reason)
				case status == "deferred":
					// base_layer, below_priority_threshold, no_fixed_version, and
					// any other deferral are policy/remediation facts, not proof
					// that vulnerable code is absent or unreachable.
					stmt.Status = vexUnderInvestigation
				case status == "eligible":
					stmt.Status = vexAffected
					stmt.ImpactStatement = "Image layer is affected; a fixed version is eligible for rebuild."
				default:
					stmt.Status = vexUnderInvestigation
				}
			default:
				stmt.Status = vexUnderInvestigation
				stmt.ImpactStatement = "Finding is active and under platform triage."
			}

			doc.Statements = append(doc.Statements, stmt)
		}
	}
	return doc, nil
}

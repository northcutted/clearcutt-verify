package commands

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

type exceptionsFlags struct {
	failOnExpired bool
}

var exceptionsOpts exceptionsFlags

type ExceptionsDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Exceptions []ExceptionEntry `json:"exceptions"`
	} `json:"spec"`
}

type ExceptionEntry struct {
	ID         string   `json:"id"`
	Package    string   `json:"package"`
	Image      string   `json:"image"`
	Release    string   `json:"release"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	Owner      string   `json:"owner"`
	CreatedAt  string   `json:"createdAt"`
	ExpiresAt  string   `json:"expiresAt"`
	References []string `json:"references,omitempty"`
	Notes      string   `json:"notes,omitempty"`
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ExceptionsValidateResponse is the structured payload for --format json|yaml,
// mirroring the check-list shape of VerifyResponse from `verify image`.
type ExceptionsValidateResponse struct {
	Status     string              `json:"status"` // pass or fail
	Document   string              `json:"document"`
	Exceptions int                 `json:"exceptions"`
	Checks     []VerifyCheckResult `json:"checks"`
}

// Match finds the exception governing a given finding, if any. It returns the
// matched entry along with whether that entry has expired as of now. Callers
// decide policy: an expired exception should never exempt a finding, but whether
// expiry is a hard failure is the caller's concern. A nil receiver matches
// nothing. Entries with an unparseable expiresAt are treated as expired.
func (d *ExceptionsDoc) Match(cveID, pkg, image, release string, now time.Time) (entry *ExceptionEntry, expired bool) {
	if d == nil {
		return nil, false
	}
	for i := range d.Spec.Exceptions {
		exc := &d.Spec.Exceptions[i]
		if exc.ID != cveID {
			continue
		}
		if exc.Package != "*" && exc.Package != pkg {
			continue
		}
		if exc.Image != "*" && exc.Image != image {
			continue
		}
		if exc.Release != "*" && exc.Release != release {
			continue
		}
		expiry, err := time.Parse("2006-01-02", exc.ExpiresAt)
		if err != nil {
			return exc, true
		}
		return exc, !expiry.After(now)
	}
	return nil, false
}

func NewExceptionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exceptions",
		Short: "Govern vulnerability exceptions and triages",
	}

	validateCmd := &cobra.Command{
		Use:   "validate <exceptions-yaml>",
		Short: "Validate an exceptions YAML configuration against schema policies",
		Long:  `Validates vulnerability exceptions YAML files for schema correctness, owner verification, references validation, and expiration dates completely offline.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExceptionsValidate(args[0])
		},
	}

	validateCmd.Flags().BoolVar(&exceptionsOpts.failOnExpired, "fail-on-expired-exceptions", true, "Fail validation if any exception is currently expired")
	cmd.AddCommand(validateCmd)

	initCmd := &cobra.Command{
		Use:   "init [output-file]",
		Short: "Initialize a boilerplate exceptions configuration YAML file",
		Long:  `Creates a standard, pre-filled VulnerabilityExceptions template YAML file at the specified path (default: exceptions.yaml) with examples of false positive, accepted risk, and temporary triaged exceptions.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "exceptions.yaml"
			if len(args) > 0 {
				path = args[0]
			}
			return runExceptionsInit(path)
		},
	}
	cmd.AddCommand(initCmd)

	return cmd
}

func runExceptionsInit(path string) error {
	template := `apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: corporate-triage-policy
spec:
  exceptions:
    - id: CVE-2024-12345
      package: openssl
      image: java25-distroless
      release: v0.2.1
      status: false_positive
      reason: scanner_false_positive
      owner: platform-security@acme.com
      createdAt: 2026-06-03
      expiresAt: 2026-12-03
      references:
        - https://github.com/northcutted/clearcutt-verify/issues/123
      notes: Upstream vulnerability scan misidentified the version mapping in the layered layout.

    - id: CVE-2023-98765
      package: glibc
      image: "*"
      release: "*"
      status: accepted_risk
      reason: vulnerable_code_not_executed
      owner: security-officer@acme.com
      createdAt: 2026-06-03
      expiresAt: 2027-06-03
      references:
        - https://nvd.nist.gov/vuln/detail/CVE-2023-98765
      notes: Wildcard mapping for base glibc finding. Analysis confirms the affected function is not compiled or used by any downstream language runtimes.
`
	if err := os.WriteFile(path, []byte(template), 0644); err != nil {
		return fmt.Errorf("failed to write exceptions template: %w", err)
	}
	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "Initialized corporate triage exceptions template at: %s\n", path)
	}
	return nil
}

func runExceptionsValidate(yamlPath string) error {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("failed to read exceptions file: %w", err)
	}

	var doc ExceptionsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse exceptions YAML: %w", err)
	}

	// Schema assertions
	if doc.APIVersion != "clearcutt.dev/v1" {
		return fmt.Errorf("invalid apiVersion: %q (expected clearcutt.dev/v1)", doc.APIVersion)
	}
	if doc.Kind != "VulnerabilityExceptions" {
		return fmt.Errorf("invalid kind: %q (expected VulnerabilityExceptions)", doc.Kind)
	}
	if doc.Metadata.Name == "" {
		return fmt.Errorf("metadata.name must not be empty")
	}

	failures := []VerifyCheckResult{}
	fail := func(prefix, msg string) {
		failures = append(failures, VerifyCheckResult{ID: prefix, Status: "fail", Message: msg})
	}
	now := time.Now().UTC()

	for i, exc := range doc.Spec.Exceptions {
		prefix := fmt.Sprintf("spec.exceptions[%d] (%s)", i, exc.ID)

		if !cveRegex.MatchString(exc.ID) {
			fail(prefix, "invalid CVE ID format")
		}
		if exc.Package == "" {
			fail(prefix, "package is required")
		}
		if exc.Image == "" {
			fail(prefix, "image is required")
		}
		if exc.Release == "" {
			fail(prefix, "release is required")
		}
		if exc.Owner == "" {
			fail(prefix, "owner is required")
		}

		// Status verification
		status := strings.ToLower(exc.Status)
		if status != "affected" && status != "not_affected" && status != "fixed" && status != "under_investigation" && status != "false_positive" && status != "accepted_risk" {
			fail(prefix, fmt.Sprintf("invalid status %q", exc.Status))
		}

		// Reason verification
		reason := strings.ToLower(exc.Reason)
		if reason != "inherited_from_base" && reason != "no_fix_available" && reason != "vulnerable_code_not_present" && reason != "vulnerable_code_not_executed" && reason != "scanner_false_positive" && reason != "temporary_business_exception" && reason != "requires_upstream_fix" {
			fail(prefix, fmt.Sprintf("invalid reason %q", exc.Reason))
		}

		// Owner and references assertions
		if status == "accepted_risk" && len(exc.References) == 0 {
			fail(prefix, "references are required for accepted_risk status")
		}

		// Dates verification
		if _, err := time.Parse("2006-01-02", exc.CreatedAt); err != nil {
			fail(prefix, fmt.Sprintf("invalid createdAt format %q (expected YYYY-MM-DD)", exc.CreatedAt))
		}

		expiry, err := time.Parse("2006-01-02", exc.ExpiresAt)
		if err != nil {
			fail(prefix, fmt.Sprintf("invalid expiresAt format %q (expected YYYY-MM-DD)", exc.ExpiresAt))
		} else {
			if exceptionsOpts.failOnExpired && expiry.Before(now) {
				fail(prefix, fmt.Sprintf("exception has expired (expired on %s)", exc.ExpiresAt))
			}
		}
	}

	if structuredFormat() {
		response := ExceptionsValidateResponse{
			Status:     "pass",
			Document:   doc.Metadata.Name,
			Exceptions: len(doc.Spec.Exceptions),
			Checks:     failures,
		}
		if len(failures) == 0 {
			response.Checks = []VerifyCheckResult{{
				ID:      "exceptions.valid",
				Status:  "pass",
				Message: fmt.Sprintf("document %q is fully valid and active (%d exceptions)", doc.Metadata.Name, len(doc.Spec.Exceptions)),
			}}
		} else {
			response.Status = "fail"
		}
		if err := printStructured(response); err != nil {
			return err
		}
		if len(failures) > 0 {
			return ErrCheckFailed
		}
		return nil
	}

	if len(failures) > 0 {
		fmt.Fprintf(errOut, "Exception validation failed with %d errors:\n", len(failures))
		for _, failure := range failures {
			fmt.Fprintf(errOut, "  - %s: %s\n", failure.ID, failure.Message)
		}
		return ErrCheckFailed
	}

	if !GlobalOpts.Quiet {
		fmt.Fprintf(out, "Vulnerability exceptions document %q is fully valid and active!\n", doc.Metadata.Name)
	}

	return nil
}

// LoadExceptionsFile reads and parses an exceptions YAML file.
func LoadExceptionsFile(path string) (*ExceptionsDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc ExceptionsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

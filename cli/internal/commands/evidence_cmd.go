package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/evidence"
	"github.com/spf13/cobra"
)

type evidenceFlags struct {
	dir      string
	files    []string
	release  string
	created  string
	output   string
	insecure bool
}

var evidenceOpts evidenceFlags

// evidenceDefaultFiles are the artifacts a release bundle is made of.
var evidenceDefaultFiles = []string{"sbom.json", "provenance.json", "scan.json", "test-results.json"}

// NewEvidenceCmd builds the `clearcutt-verify evidence` group: store release evidence
// with the image it describes, on any OCI registry.
func NewEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Attach, read, and export release evidence on any OCI registry",
		Long: `Store release evidence — SBOMs, provenance, scans, test results — attached to
the image it describes, using the OCI referrers mechanism.

This replaces putting evidence in GitHub release assets. The evidence then lives
in the same place as the images, under one credential, and reads the same way on
any OCI registry: registries implementing the Referrers API index it themselves,
and the referrers tag fallback covers those that do not.

GARBAGE COLLECTION: attached evidence is a manifest like any other, and registry
lifecycle rules can delete it — a policy that prunes untagged manifests, or
everything older than N days, will take the evidence with it. The tag fallback
protects against untagged-manifest pruning specifically, but not against age or
size rules. Use ` + "`evidence export`" + ` to keep a copy somewhere with its own
retention guarantees, and ` + "`evidence import`" + ` to put it back.`,
	}
	cmd.AddCommand(newEvidenceAttachCmd(), newEvidenceListCmd(), newEvidenceExportCmd(), newEvidenceImportCmd())
	return cmd
}

func evidenceClient() *evidence.Client {
	if evidenceOpts.insecure {
		return evidence.NewInsecureClient()
	}
	// Same resolution order as estate and fleet publish: explicit environment
	// credentials first, ambient keychain second.
	if user, token := registryDestCredentialPair(); user != "" && token != "" {
		return evidence.NewBasicAuthClient(user, token)
	}
	return evidence.NewClient()
}

func newEvidenceAttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach <image-reference>",
		Short: "Attach an evidence bundle to an image",
		Args:  cobra.ExactArgs(1),
		RunE:  func(_ *cobra.Command, args []string) error { return runEvidenceAttach(args[0]) },
	}
	cmd.Flags().StringVar(&evidenceOpts.dir, "dir", ".", "Directory holding the evidence files")
	cmd.Flags().StringSliceVar(&evidenceOpts.files, "file", nil, "Evidence file(s) to attach (default: sbom.json, provenance.json, scan.json, test-results.json)")
	cmd.Flags().StringVar(&evidenceOpts.release, "release", "", "Release tag this evidence belongs to")
	cmd.Flags().StringVar(&evidenceOpts.created, "created", "", "RFC3339 timestamp recorded on the bundle")
	cmd.Flags().BoolVar(&evidenceOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func runEvidenceAttach(ref string) error {
	wanted := nonEmptyStrings(evidenceOpts.files)
	explicit := len(wanted) > 0
	if !explicit {
		wanted = evidenceDefaultFiles
	}
	bundle := evidence.Bundle{
		Release: strings.TrimSpace(evidenceOpts.release),
		Created: strings.TrimSpace(evidenceOpts.created),
		Files:   map[string][]byte{},
	}
	var missing []string
	for _, fileName := range wanted {
		path := fileName
		if !filepath.IsAbs(path) {
			path = filepath.Join(evidenceOpts.dir, fileName)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && !explicit {
				missing = append(missing, fileName)
				continue
			}
			return fmt.Errorf("reading evidence file %s: %w", path, err)
		}
		bundle.Files[filepath.Base(fileName)] = body
	}
	if len(bundle.Files) == 0 {
		return fmt.Errorf("no evidence files found in %s (looked for %s)", evidenceOpts.dir, strings.Join(wanted, ", "))
	}
	for _, fileName := range missing {
		fmt.Fprintf(out, "[evidence] %s not present; attaching without it\n", fileName)
	}
	digest, err := evidenceClient().Attach(ref, bundle)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(bundle.Files))
	for fileName := range bundle.Files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	fmt.Fprintf(out, "[evidence] attached %d file(s) to %s\n", len(names), ref)
	for _, fileName := range names {
		fmt.Fprintf(out, "[evidence]   %s (%d bytes)\n", fileName, len(bundle.Files[fileName]))
	}
	fmt.Fprintf(out, "[evidence] bundle %s\n", digest)
	fmt.Fprintf(out, "[evidence] registry lifecycle rules can delete this; `clearcutt-verify evidence export` keeps a copy that outlives them\n")
	return nil
}

func newEvidenceListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <image-reference>",
		Short: "List evidence attached to an image",
		Args:  cobra.ExactArgs(1),
		RunE:  func(_ *cobra.Command, args []string) error { return runEvidenceList(args[0]) },
	}
	cmd.Flags().BoolVar(&evidenceOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func runEvidenceList(ref string) error {
	attachments, err := evidenceClient().List(ref)
	if err != nil {
		return err
	}
	if strings.EqualFold(GlobalOpts.Format, "json") {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(attachments)
	}
	if len(attachments) == 0 {
		fmt.Fprintf(out, "[evidence] no evidence attached to %s\n", ref)
		return nil
	}
	for _, attachment := range attachments {
		fmt.Fprintf(out, "%s\n", attachment.Digest)
		if attachment.Release != "" {
			fmt.Fprintf(out, "  release  %s\n", attachment.Release)
		}
		if attachment.Created != "" {
			fmt.Fprintf(out, "  created  %s\n", attachment.Created)
		}
		fmt.Fprintf(out, "  files    %s\n", strings.Join(attachment.Files, ", "))
	}
	return nil
}

func newEvidenceExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export <image-reference>",
		Short: "Export attached evidence so it outlives the registry",
		Long: `Copy every evidence bundle attached to an image into a directory, as both a
standard OCI image layout and plain files.

Registry lifecycle policies can delete attached evidence — a rule that prunes
untagged manifests, or everything older than N days, will take it. An export is
a copy in a store with its own retention guarantees, made before any policy can
reach it.

Two formats, because two audiences want different things:

  oci/    digest-preserving. Push it back with ` + "`clearcutt-verify evidence import`" + `,
          crane, or oras, and signatures made over the evidence still verify.
  files/  the same evidence as plain readable files, for an auditor with a zip
          and no container tooling.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error { return runEvidenceExport(args[0]) },
	}
	cmd.Flags().StringVar(&evidenceOpts.output, "output", "evidence-export", "Directory to write the export into")
	cmd.Flags().BoolVar(&evidenceOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func runEvidenceExport(ref string) error {
	manifest, err := evidenceClient().Export(ref, evidenceOpts.output)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "[evidence] exported %d bundle(s) from %s to %s\n", len(manifest.Attachments), ref, evidenceOpts.output)
	for _, attachment := range manifest.Attachments {
		fmt.Fprintf(out, "[evidence]   %s  %s\n", attachment.Digest, strings.Join(attachment.Files, ", "))
	}
	fmt.Fprintf(out, "[evidence] oci/    digest-preserving; restore with `clearcutt-verify evidence import`\n")
	fmt.Fprintf(out, "[evidence] files/  plain files, readable without container tooling\n")
	return nil
}

func newEvidenceImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <directory> <repository>",
		Short: "Restore exported evidence into a registry",
		Args:  cobra.ExactArgs(2),
		RunE:  func(_ *cobra.Command, args []string) error { return runEvidenceImport(args[0], args[1]) },
	}
	cmd.Flags().BoolVar(&evidenceOpts.insecure, "insecure", false, "Use plain HTTP without auth (test registries only)")
	return cmd
}

func runEvidenceImport(dir, repo string) error {
	restored, err := evidenceClient().Import(dir, repo)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "[evidence] restored %d bundle(s) into %s\n", len(restored), repo)
	for _, digest := range restored {
		fmt.Fprintf(out, "[evidence]   %s\n", digest)
	}
	fmt.Fprintf(out, "[evidence] digests are unchanged, so signatures over this evidence still verify\n")
	return nil
}

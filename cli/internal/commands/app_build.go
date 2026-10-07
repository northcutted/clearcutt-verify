package commands

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/northcutted/clearcutt-verify/internal/oci"
	"github.com/northcutted/clearcutt-verify/internal/output"
	"github.com/spf13/cobra"
)

type appBuildFlags struct {
	base        string
	baseID      string
	baseVersion string
	artifact    string
	dest        string
	entrypoint  string
	cmd         string
	workdir     string
	user        string
	executable  bool
	image       string
}

var appBuildOpts appBuildFlags

// AppBuildResult is the structured output of `app build`.
type AppBuildResult struct {
	Image          string `json:"image"`
	Digest         string `json:"digest"`
	BaseRef        string `json:"baseRef"`
	BaseID         string `json:"baseId"`
	BaseLastLayer  string `json:"baseLastLayer"`
	AppLayerDigest string `json:"appLayerDigest"`
}

func newAppBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Assemble a prebuilt artifact onto a ClearCutt base and push the app image",
		Long: `Lays one prebuilt artifact (a file, or a publish directory such as .NET output)
onto a ClearCutt base image as one deterministic OCI layer, stamps the
application-lifecycle labels that make the image rebasable, and pushes it — all
without a Docker daemon or Nix.

The --base may be a catalog id (resolved to a digest-pinned reference through the
catalog) or an explicit registry reference. The entrypoint must be JSON exec form.

Example:
  clearcutt-verify app build \
    --base java25-distroless \
    --artifact target/app.jar \
    --entrypoint '["java","-jar","/workspace/app.jar"]' \
    --image ghcr.io/acme/payments-api:1.0.0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAppBuild()
		},
	}

	f := cmd.Flags()
	f.StringVar(&appBuildOpts.base, "base", "", "ClearCutt base image: catalog id (e.g. java25-distroless) or a registry reference")
	f.StringVar(&appBuildOpts.baseID, "base-id", "", "Override the base catalog id stamped into labels (when --base is a raw reference)")
	f.StringVar(&appBuildOpts.baseVersion, "base-version", "", "Override the base version stamped into labels")
	f.StringVar(&appBuildOpts.artifact, "artifact", "", "Path to the prebuilt file or directory to embed (e.g. target/app.jar or out/)")
	f.StringVar(&appBuildOpts.dest, "dest", "", "Absolute path the artifact lands at inside the image (default /workspace/<artifact-name>; directories expand under this path)")
	f.StringVar(&appBuildOpts.entrypoint, "entrypoint", "", `OCI entrypoint in JSON exec form, e.g. '["java","-jar","/workspace/app.jar"]'`)
	f.StringVar(&appBuildOpts.cmd, "cmd", "", "Optional OCI cmd in JSON exec form")
	f.StringVar(&appBuildOpts.workdir, "workdir", "", "Optional working directory inside the image")
	f.StringVar(&appBuildOpts.user, "user", "", "Optional non-root user override (defaults to the base image's user)")
	f.BoolVar(&appBuildOpts.executable, "executable", false, "Mark the embedded artifact executable (for static binaries)")
	f.StringVar(&appBuildOpts.image, "image", "", "Target reference to push the assembled app image to")

	_ = cmd.MarkFlagRequired("base")
	_ = cmd.MarkFlagRequired("artifact")
	_ = cmd.MarkFlagRequired("entrypoint")
	_ = cmd.MarkFlagRequired("image")

	return cmd
}

func runAppBuild() error {
	entry, err := parseExecArray(appBuildOpts.entrypoint)
	if err != nil {
		return err
	}
	if len(entry) == 0 {
		return fmt.Errorf("--entrypoint must be a non-empty JSON array")
	}
	cmdArr, err := parseExecArray(appBuildOpts.cmd)
	if err != nil {
		return err
	}

	baseRef, baseID, baseVersion, err := resolveBaseReference(appBuildOpts.base, appBuildOpts.baseVersion)
	if err != nil {
		return err
	}
	if appBuildOpts.baseID != "" {
		baseID = appBuildOpts.baseID
	}

	dest := appBuildOpts.dest
	if dest == "" {
		dest = "/workspace/" + path.Base(appBuildOpts.artifact)
	}

	client := newOCIClient()
	res, err := client.BuildApp(oci.BuildOptions{
		BaseRef:      baseRef,
		BaseID:       baseID,
		BaseVersion:  baseVersion,
		ArtifactPath: appBuildOpts.artifact,
		DestPath:     dest,
		Entrypoint:   entry,
		Cmd:          cmdArr,
		WorkingDir:   appBuildOpts.workdir,
		User:         appBuildOpts.user,
		Executable:   appBuildOpts.executable,
		TargetRef:    appBuildOpts.image,
	})
	if err != nil {
		return fmt.Errorf("app build failed: %w", err)
	}

	result := AppBuildResult{
		Image:          appBuildOpts.image,
		Digest:         res.Digest,
		BaseRef:        res.BaseRef,
		BaseID:         baseID,
		BaseLastLayer:  res.BaseLastLayer,
		AppLayerDigest: res.AppLayerDigest,
	}
	return emitAppBuildResult(result)
}

func emitAppBuildResult(r AppBuildResult) error {
	switch strings.ToLower(GlobalOpts.Format) {
	case "json":
		return output.PrintJSON(out, r)
	case "yaml", "yml":
		return output.PrintYAML(out, r)
	default:
		fmt.Fprintf(out, "Built and pushed application image\n")
		fmt.Fprintf(out, "  image          : %s\n", r.Image)
		fmt.Fprintf(out, "  digest         : %s\n", r.Digest)
		fmt.Fprintf(out, "  base           : %s\n", r.BaseRef)
		if r.BaseID != "" {
			fmt.Fprintf(out, "  base id        : %s\n", r.BaseID)
		}
		fmt.Fprintf(out, "  base boundary  : %s\n", truncateDigest(r.BaseLastLayer))
		fmt.Fprintf(out, "  app layer      : %s\n", truncateDigest(r.AppLayerDigest))
		fmt.Fprintf(out, "\nThe image is marked rebasable; update its base later with `clearcutt-verify app rebase`.\n")
		return nil
	}
}

// parseExecArray parses a JSON exec-form array string (e.g. '["a","b"]'). An empty
// string yields a nil slice.
func parseExecArray(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil, fmt.Errorf("invalid JSON exec form %q: %w (expected e.g. '[\"java\",\"-jar\",\"/workspace/app.jar\"]')", s, err)
	}
	return arr, nil
}

package commands

import (
	"github.com/spf13/cobra"
)

// VerifyCheckResult is one assertion of a verification command.
type VerifyCheckResult struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // pass or fail
	Message string `json:"message"`
}

// NewVerifyCmd groups single-image verification. Estates are verified with
// estate verify.
func NewVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify one published image's release evidence",
		Long: `Verification of a single published image:
  release-evidence verify a published image ref's Sigstore signature + SLSA provenance

To verify every image in an estate and write the estate report, use
estate verify.`,
	}
	cmd.AddCommand(NewVerifyReleaseEvidenceCmd())
	return cmd
}

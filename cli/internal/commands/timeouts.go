package commands

import (
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/northcutted/clearcutt-verify/internal/operation"
	"github.com/spf13/cobra"
)

func validateTimeouts(cmd *cobra.Command) error {
	for _, flag := range []string{"registry-timeout", "cosign-timeout", "github-timeout", "reproduce-timeout", "grype-timeout"} {
		if cmd.Flags().Lookup(flag) != nil {
			limit, err := cmd.Flags().GetDuration(flag)
			if err != nil {
				return err
			}
			if limit <= 0 {
				return fmt.Errorf("--%s must be greater than zero", flag)
			}
		}
	}
	return nil
}

func registryTransport() http.RoundTripper {
	return operation.HTTPTimeout(remote.DefaultTransport,
		operation.Limit(GlobalOpts.RegistryTimeout, operation.RegistryTimeout), "registry request")
}

func registryOptions() []remote.Option {
	return []remote.Option{remote.WithTransport(registryTransport())}
}

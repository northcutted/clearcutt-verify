package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const defaultKEVCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type scanRefreshKEVFlags struct {
	url               string
	out               string
	statusOut         string
	timeout           time.Duration
	failOnUnavailable bool
}

var scanRefreshKEVOpts scanRefreshKEVFlags

type kevRefreshStatus struct {
	Status         string  `json:"status"`
	CatalogVersion *string `json:"catalogVersion,omitempty"`
	DateReleased   *string `json:"dateReleased,omitempty"`
	Count          *int    `json:"count,omitempty"`
	Error          *string `json:"error,omitempty"`
}

type kevCatalogSummary struct {
	CatalogVersion string `json:"catalogVersion"`
	DateReleased   string `json:"dateReleased"`
	Count          int    `json:"count"`
}

func NewScanRefreshKEVCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "refresh-kev",
		Short: "Refresh the CISA KEV catalog cache used by vulnerability scans",
		Long: `Refreshes the CISA Known Exploited Vulnerabilities catalog cache used by
clearcutt-verify scan --kev-file. By default refresh failures are recorded in the
status file and do not fail the command, matching the scheduled remediation
workflow's fallback to the active local scanner database and no KEV enrichment.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanRefreshKEV()
		},
	}
	cmd.Flags().StringVar(&scanRefreshKEVOpts.url, "url", envOr("KEV_URL", defaultKEVCatalogURL), "CISA KEV catalog URL")
	cmd.Flags().StringVar(&scanRefreshKEVOpts.out, "out", envOr("KEV_FILE", filepath.Join("core", "build-outputs", "security-intel", "known_exploited_vulnerabilities.json")), "Path to write the KEV catalog JSON")
	cmd.Flags().StringVar(&scanRefreshKEVOpts.statusOut, "status-out", envOr("KEV_STATUS_FILE", filepath.Join("core", "build-outputs", "security-intel", "kev-status.json")), "Path to write refresh status JSON")
	cmd.Flags().DurationVar(&scanRefreshKEVOpts.timeout, "timeout", 30*time.Second, "HTTP timeout for the KEV catalog refresh")
	cmd.Flags().BoolVar(&scanRefreshKEVOpts.failOnUnavailable, "fail-on-unavailable", false, "Fail the command when the KEV catalog cannot be refreshed")
	return cmd
}

func runScanRefreshKEV() error {
	status, err := refreshKEVCatalog(scanRefreshKEVOpts.url, scanRefreshKEVOpts.out, scanRefreshKEVOpts.timeout)
	if writeErr := writeKEVRefreshStatus(scanRefreshKEVOpts.statusOut, status); writeErr != nil {
		return writeErr
	}
	if err != nil {
		scanWarnf("KEV refresh unavailable: %v", err)
		if scanRefreshKEVOpts.failOnUnavailable {
			return err
		}
		return nil
	}
	scanLogf("KEV refresh available: catalog=%s count=%d", valueOrUnknown(status.CatalogVersion), intValueOrZero(status.Count))
	return nil
}

func refreshKEVCatalog(url, outPath string, timeout time.Duration) (kevRefreshStatus, error) {
	status := kevRefreshStatus{Status: "unavailable"}
	raw, err := fetchKEVCatalog(url, timeout)
	if err != nil {
		return unavailableKEVStatus(status, outPath, err)
	}
	var summary kevCatalogSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		return unavailableKEVStatus(status, outPath, fmt.Errorf("parse KEV catalog: %w", err))
	}
	if summary.CatalogVersion == "" && summary.Count == 0 {
		return unavailableKEVStatus(status, outPath, fmt.Errorf("KEV catalog missing catalogVersion/count metadata"))
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return status, fmt.Errorf("create KEV output dir: %w", err)
	}
	if err := os.WriteFile(outPath, raw, 0o644); err != nil {
		return status, fmt.Errorf("write KEV catalog: %w", err)
	}
	status.Status = "available"
	status.CatalogVersion = strPtrOrNil(summary.CatalogVersion)
	status.DateReleased = strPtrOrNil(summary.DateReleased)
	status.Count = &summary.Count
	return status, nil
}

func fetchKEVCatalog(url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clearcutt/"+Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func unavailableKEVStatus(status kevRefreshStatus, outPath string, err error) (kevRefreshStatus, error) {
	_ = os.Remove(outPath)
	msg := err.Error()
	status.Error = &msg
	return status, err
}

func writeKEVRefreshStatus(path string, status kevRefreshStatus) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create KEV status dir: %w", err)
	}
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write KEV status: %w", err)
	}
	return nil
}

func valueOrUnknown(value *string) string {
	if value == nil || *value == "" {
		return "unknown"
	}
	return *value
}

func intValueOrZero(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

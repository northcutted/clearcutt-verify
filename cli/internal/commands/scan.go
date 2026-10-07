package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/scan"
	"github.com/spf13/cobra"
)

// scan.go is the catalog vulnerability scanner command: it walks every cached
// SBOM, runs grype, and delegates normalization to internal/scan, writing one
// vulnerability JSON per (tag, target, arch). The output shape is reproduced
// exactly so the catalog site, the remediation planner, and the release gate
// that consume it see no change.

type scanFlags struct {
	mode        string
	sbomDir     string
	outDir      string
	depth       string
	tags        string
	all         bool
	kevFile     string
	concurrency int
	grypeConfig string
	updateDB    bool
	coreDir     string
}

var scanOpts scanFlags

var scanStrictModes = map[string]bool{"remediation": true, "release": true}

var scanTargetFileRe = regexp.MustCompile(`^(.+)-(amd64|arm64)\.sbom\.json$`)

func nowRFC3339Milli() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan cached SBOMs with grype and emit normalized vulnerability JSON",
		Long: `Scans each cached SBOM under --sbom-dir with grype and writes a normalized
findings JSON per (tag, target, arch) under --out-dir, classifying each finding's
layer (runtime vs base), inclusion category, and remediation status. In
remediation/release mode the scan fails closed on missing tooling or scan errors;
in catalog mode it is best-effort.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan()
		},
	}
	cmd.Flags().StringVar(&scanOpts.mode, "mode", envOr("SCAN_MODE", "catalog"), "Scan mode: catalog (best-effort), remediation, or release (fail closed)")
	cmd.Flags().StringVar(&scanOpts.sbomDir, "sbom-dir", envOr("SBOM_CACHE_DIR", filepath.Join("site", "src", "data", "sboms")), "Directory of cached SBOMs (<tag>/<target>-<arch>.sbom.json)")
	cmd.Flags().StringVar(&scanOpts.outDir, "out-dir", envOr("VULN_DIR", filepath.Join("site", "src", "data", "vulnerabilities")), "Directory to write normalized vulnerability JSON into")
	cmd.Flags().StringVar(&scanOpts.depth, "depth", os.Getenv("SCAN_TAG_DEPTH"), "Scan only the newest N tags by version (empty = all)")
	cmd.Flags().StringVar(&scanOpts.tags, "tags", os.Getenv("SCAN_TAGS"), "Comma-separated explicit tag allowlist (overrides --depth/--all)")
	cmd.Flags().BoolVar(&scanOpts.all, "all", parseScanBool(os.Getenv("SCAN_ALL_TAGS")), "Scan every cached tag (overrides --depth)")
	cmd.Flags().StringVar(&scanOpts.kevFile, "kev-file", os.Getenv("KEV_FILE"), "Optional CISA KEV catalog JSON file for known-exploited enrichment")
	cmd.Flags().IntVar(&scanOpts.concurrency, "concurrency", 0, "Parallel grype workers (0 = CPU count or $SCAN_CONCURRENCY)")
	cmd.Flags().StringVar(&scanOpts.grypeConfig, "grype-config", os.Getenv("GRYPE_CONFIG"), "Grype config file holding the ignore rules (default: core/.grype.yaml when present)")
	cmd.Flags().BoolVar(&scanOpts.updateDB, "update-db", parseScanBool(os.Getenv("SCAN_UPDATE_DB")), "Refresh the local Grype vulnerability database before scanning")
	cmd.Flags().StringVar(&scanOpts.coreDir, "core-dir", "", "Optional path to core/; when set, run Grype through the pinned Nix dev shell")
	cmd.AddCommand(NewScanRefreshKEVCmd())
	return cmd
}

// -- tag window selection (mirrors selectTags in the .mjs) -------------------

func scanVersionTuple(value string) []int {
	raw := strings.Split(strings.TrimLeft(value, "v"), ".")
	parts := make([]int, 0, len(raw))
	for _, p := range raw {
		t := strings.TrimSpace(p)
		n, err := strconv.Atoi(t)
		if err != nil {
			return []int{0, 0, 0}
		}
		parts = append(parts, n)
	}
	return parts
}

func compareScanTuples(a, b []int) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return len(a) - len(b)
}

func selectScanTags(allTags []string, strict bool) ([]string, error) {
	explicit := []string{}
	for _, t := range strings.Split(scanOpts.tags, ",") {
		if s := strings.TrimSpace(t); s != "" {
			explicit = append(explicit, s)
		}
	}
	if len(explicit) > 0 {
		allow := map[string]bool{}
		for _, t := range explicit {
			allow[t] = true
		}
		selected := []string{}
		for _, t := range allTags {
			if allow[t] {
				selected = append(selected, t)
			}
		}
		scanLogf("tag window: explicit tags=%s -> scanning %s (skipped %d)", strings.Join(explicit, ", "), joinOrNone(selected), len(allTags)-len(selected))
		return selected, nil
	}
	if scanOpts.all {
		scanLogf("tag window: all tags requested -> scanning %d tag(s)", len(allTags))
		return allTags, nil
	}
	rawDepth := strings.TrimSpace(scanOpts.depth)
	if rawDepth != "" {
		depth, err := strconv.Atoi(rawDepth)
		if err != nil || depth <= 0 {
			if msg := fmt.Sprintf("[scan] invalid tag window depth %q; scanning all tags.", rawDepth); strict {
				return nil, fmt.Errorf("%s", msg)
			} else {
				scanWarnf("invalid tag window depth %q; scanning all tags.", rawDepth)
			}
			return allTags, nil
		}
		if depth >= len(allTags) {
			scanLogf("tag window: depth=%d covers all %d tag(s)", depth, len(allTags))
			return allTags, nil
		}
		sorted := make([]string, len(allTags))
		copy(sorted, allTags)
		sort.SliceStable(sorted, func(i, j int) bool {
			return compareScanTuples(scanVersionTuple(sorted[i]), scanVersionTuple(sorted[j])) > 0
		})
		selected := sorted[:depth]
		scanLogf("tag window: depth=%d -> scanning %s (skipped %d older)", depth, strings.Join(selected, ", "), len(allTags)-len(selected))
		return selected, nil
	}
	scanLogf("tag window: default all -> scanning %d tag(s)", len(allTags))
	return allTags, nil
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

// -- execution ---------------------------------------------------------------

func scanLogf(format string, args ...any) {
	fmt.Fprintf(errOut, "[scan] "+format+"\n", args...)
}

func scanWarnf(format string, args ...any) {
	fmt.Fprintf(errOut, "[scan] "+format+"\n", args...)
}

type scanCommandSpec struct {
	name string
	args []string
	dir  string
}

func scanGrypeCommand(grypeBin string, args ...string) scanCommandSpec {
	if strings.TrimSpace(scanOpts.coreDir) == "" {
		return scanCommandSpec{name: grypeBin, args: args}
	}
	return scanCommandSpec{
		name: "nix",
		args: nixDevelopCommand(grypeBin, args...),
		dir:  scanOpts.coreDir,
	}
}

func scanCommandOutput(spec scanCommandSpec) ([]byte, error) {
	cmd := exec.Command(spec.name, spec.args...)
	cmd.Dir = spec.dir
	return cmd.Output()
}

func scanCommandCombinedOutput(spec scanCommandSpec) ([]byte, error) {
	cmd := exec.Command(spec.name, spec.args...)
	cmd.Dir = spec.dir
	return cmd.CombinedOutput()
}

func grypeVersionProbe(grypeBin string) (string, *string) {
	out, err := scanCommandOutput(scanGrypeCommand(grypeBin, "version", "-o", "json"))
	if err != nil {
		return "grype", nil
	}
	var parsed struct {
		Version     string `json:"version"`
		Application string `json:"application"`
		DB          struct {
			Built string `json:"built"`
		} `json:"db"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "grype", nil
	}
	version := parsed.Version
	if version == "" {
		version = parsed.Application
	}
	if version == "" {
		version = "grype"
	}
	var built *string
	if parsed.DB.Built != "" {
		built = &parsed.DB.Built
	}
	return version, built
}

func refreshGrypeDB(grypeBin string) {
	scanLogf("updating Grype vulnerability database")
	out, err := scanCommandCombinedOutput(scanGrypeCommand(grypeBin, "db", "update"))
	if err == nil {
		scanLogf("Grype vulnerability database update completed")
		return
	}
	detail := strings.TrimSpace(string(out))
	if len(detail) > 200 {
		detail = detail[:200]
	}
	if detail == "" {
		detail = err.Error()
	} else {
		detail = fmt.Sprintf("%v: %s", err, detail)
	}
	scanWarnf("Grype database update failed, proceeding with active local database: %s", detail)
}

type scanWorkItem struct {
	tag, target, arch, sbomPath, outPath string
}

func strPtrOrNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func loadScanKEVCatalog(path string) (*scan.KEVCatalog, string, *string) {
	if strings.TrimSpace(path) == "" {
		return nil, "unavailable", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		scanWarnf("KEV enrichment unavailable: failed to read %s: %v", path, err)
		return nil, "unavailable", nil
	}
	catalog, err := scan.ParseKEVCatalog(raw)
	if err != nil {
		scanWarnf("KEV enrichment unavailable: failed to parse %s: %v", path, err)
		return nil, "unavailable", nil
	}
	version := catalog.CatalogVersion
	scanLogf("KEV enrichment available: catalog=%s count=%d", fallbackString(version, "unknown"), catalog.Count)
	return catalog, "available", strPtrOrNil(version)
}

func runScan() error {
	strict := scanStrictModes[scanOpts.mode]
	grypeBin := envOr("GRYPE_BIN", "grype")
	grypeOpts := strings.Fields(os.Getenv("GRYPE_OPTS"))
	toolProbe := grypeBin
	if strings.TrimSpace(scanOpts.coreDir) != "" {
		toolProbe = "nix"
		scanLogf("tool resolver: using Nix dev shell at %s for Grype", scanOpts.coreDir)
	}

	// Pass a fleet suppression config explicitly when one exists: grype only
	// auto-discovers .grype.yaml from its working directory, and this command
	// runs from the repo root (catalog build, release gate), not from core/.
	// This repo ships no suppressions any more — they went with the remediation
	// subsystem — so the default path is usually absent and grype runs unfiltered,
	// which is the honest default. A fork that maintains its own core/.grype.yaml
	// still gets it. The path MUST be absolute: with --core-dir set, grype runs
	// through `nix develop` with cwd=core/, so a repo-root-relative
	// "core/.grype.yaml" would resolve to core/core/.grype.yaml and grype aborts
	// with "invalid application config: file does not exist".
	grypeConfig := strings.TrimSpace(scanOpts.grypeConfig)
	explicitConfig := grypeConfig != ""
	if !explicitConfig {
		grypeConfig = filepath.Join("core", ".grype.yaml")
	}
	if _, err := os.Stat(grypeConfig); err == nil {
		grypeConfig = absToolPath(grypeConfig)
		grypeOpts = append([]string{"-c", grypeConfig}, grypeOpts...)
		scanLogf("grype config: %s", grypeConfig)
	} else if explicitConfig {
		msg := fmt.Sprintf("[scan] grype config %s not found.", grypeConfig)
		if strict {
			return fmt.Errorf("%s", msg)
		}
		scanWarnf("grype config %s not found.", grypeConfig)
	}

	if _, err := exec.LookPath(toolProbe); err != nil {
		msg := fmt.Sprintf("[scan] %s not on PATH - install %s to enable CVE reporting.", toolProbe, toolProbe)
		if strict {
			return fmt.Errorf("%s", msg)
		}
		scanWarnf("%s not on PATH - install %s to enable CVE reporting.", toolProbe, toolProbe)
		return nil
	}
	if scanOpts.updateDB {
		refreshGrypeDB(grypeBin)
	}

	info, err := os.Stat(scanOpts.sbomDir)
	if err != nil || !info.IsDir() {
		msg := fmt.Sprintf("[scan] no SBOM cache at %s - run gather first.", scanOpts.sbomDir)
		if strict {
			return fmt.Errorf("%s", msg)
		}
		scanWarnf("no SBOM cache at %s - run gather first.", scanOpts.sbomDir)
		return nil
	}

	scannerVersion, dbBuiltAt := grypeVersionProbe(grypeBin)
	dbBuiltLabel := "unknown"
	if dbBuiltAt != nil {
		dbBuiltLabel = *dbBuiltAt
	}
	scanLogf("grype %s, db built %s", scannerVersion, dbBuiltLabel)
	kevCatalog, kevStatus, kevCatalogVersion := loadScanKEVCatalog(scanOpts.kevFile)

	entries, err := os.ReadDir(scanOpts.sbomDir)
	if err != nil {
		return fmt.Errorf("[scan] failed to read SBOM cache %s: %w", scanOpts.sbomDir, err)
	}
	allTags := []string{}
	for _, e := range entries {
		if e.IsDir() {
			allTags = append(allTags, e.Name())
		}
	}
	tags, err := selectScanTags(allTags, strict)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(scanOpts.outDir, 0o755); err != nil {
		return fmt.Errorf("[scan] failed to create output dir %s: %w", scanOpts.outDir, err)
	}

	work := []scanWorkItem{}
	for _, tag := range tags {
		tagOut := filepath.Join(scanOpts.outDir, tag)
		if err := os.MkdirAll(tagOut, 0o755); err != nil {
			return fmt.Errorf("[scan] failed to create output dir %s: %w", tagOut, err)
		}
		tagDir := filepath.Join(scanOpts.sbomDir, tag)
		files, err := os.ReadDir(tagDir)
		if err != nil {
			return fmt.Errorf("[scan] failed to read %s: %w", tagDir, err)
		}
		for _, f := range files {
			m := scanTargetFileRe.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			work = append(work, scanWorkItem{
				tag:      tag,
				target:   m[1],
				arch:     m[2],
				sbomPath: filepath.Join(tagDir, f.Name()),
				outPath:  filepath.Join(tagOut, fmt.Sprintf("%s-%s.json", m[1], m[2])),
			})
		}
	}

	concurrency := scanOpts.concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
		if env := os.Getenv("SCAN_CONCURRENCY"); env != "" {
			if n, err := strconv.Atoi(env); err == nil && n > 0 {
				concurrency = n
			}
		}
	}
	if concurrency < 1 {
		concurrency = 1
	}
	scanLogf("scanning %d SBOM(s) with concurrency %d", len(work), concurrency)

	var mu sync.Mutex
	total, failed := 0, 0
	scanOne := func(item scanWorkItem) {
		report, err := scanSBOM(grypeBin, grypeOpts, item, scannerVersion, dbBuiltAt, scan.NormalizeOptions{
			KEVCatalog:        kevCatalog,
			KEVStatus:         kevStatus,
			KEVCatalogVersion: kevCatalogVersion,
		})
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed++
			scanWarnf("%s/%s/%s: %v", item.tag, item.target, item.arch, err)
			return
		}
		c := report.CountsBySeverity
		scanLogf("%s/%s/%s: %d findings (crit=%d high=%d med=%d low=%d)", item.tag, item.target, item.arch, len(report.Findings), c.Critical, c.High, c.Medium, c.Low)
		total++
	}

	var wg sync.WaitGroup
	ch := make(chan scanWorkItem)
	workers := concurrency
	if workers > len(work) {
		workers = len(work)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ch {
				scanOne(item)
			}
		}()
	}
	for _, item := range work {
		ch <- item
	}
	close(ch)
	wg.Wait()

	scanLogf("done. %d scans succeeded, %d failed.", total, failed)
	if strict && total == 0 {
		return fmt.Errorf("[scan] strict %s mode found zero SBOMs to scan.", scanOpts.mode)
	}
	if strict && failed > 0 {
		return fmt.Errorf("[scan] strict %s mode had %d failed scan(s).", scanOpts.mode, failed)
	}
	return nil
}

func scanSBOM(grypeBin string, grypeOpts []string, item scanWorkItem, scannerVersion string, dbBuiltAt *string, opts scan.NormalizeOptions) (scan.Report, error) {
	// Absolute SBOM source for the same reason as the grype config: with
	// --core-dir set grype runs with cwd=core/, so a repo-root-relative SBOM
	// path would resolve under core/ and not be found.
	args := append([]string{"sbom:" + absToolPath(item.sbomPath), "-o", "json", "--quiet"}, grypeOpts...)
	raw, err := scanCommandOutput(scanGrypeCommand(grypeBin, args...))
	if err != nil && len(raw) == 0 {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
			if len(stderr) > 200 {
				stderr = stderr[:200]
			}
		}
		return scan.Report{}, fmt.Errorf("grype failed: %v: %s", err, stderr)
	}
	var result scan.GrypeResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return scan.Report{}, fmt.Errorf("grype produced unparseable JSON: %w", err)
	}
	report := scan.NormalizeGrypeWithOptions(result, nowRFC3339Milli(), "grype-"+scannerVersion, dbBuiltAt, scan.TargetMetadata(item.target), opts)
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return scan.Report{}, err
	}
	if err := os.WriteFile(item.outPath, out, 0o644); err != nil {
		return scan.Report{}, err
	}
	return report, nil
}

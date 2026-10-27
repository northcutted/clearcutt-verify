package estateverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/northcutted/clearcutt-verify/internal/operation"
	"github.com/northcutted/clearcutt-verify/internal/report"
)

// Scanner scans an SBOM for vulnerabilities (estate verify --rescan).
// GrypeScanner runs grype; tests replace it.
type Scanner interface {
	// Scan scans an SBOM document (CycloneDX or SPDX JSON), applying the
	// OpenVEX document vex when it isn't nil, and returns grype's output.
	Scan(ctx context.Context, sbom, vex []byte) (grypeResult, error)
}

// GrypeScanner scans SBOMs with grype (`grype sbom:FILE -o json`). The
// vulnerability database is grype's own, where grype's settings say
// (GRYPE_DB_CACHE_DIR, GRYPE_DB_UPDATE_URL, and the rest of grype's
// GRYPE_DB_* environment): PrepareDB updates it once before the run, and the
// scans then use it as it is. The check for a newer grype is turned off.
type GrypeScanner struct {
	// Binary is the grype binary (default "grype").
	Binary string
	// Timeout bounds each invocation, including database preparation.
	Timeout time.Duration
	// Run executes grype in dir and returns its standard output and error;
	// tests replace it.
	Run func(ctx context.Context, dir, bin string, args ...string) (stdout, stderr []byte, err error)

	scanned, failed atomic.Int64
	// dbPrepared: PrepareDB updated the database for the run, so scans
	// don't check for an update each (GRYPE_DB_AUTO_UPDATE=false).
	dbPrepared bool
}

// Scanned and Failed count the scans grype finished and the ones it didn't.
func (g *GrypeScanner) Scanned() int64 { return g.scanned.Load() }
func (g *GrypeScanner) Failed() int64  { return g.failed.Load() }

func (g *GrypeScanner) bin() string {
	if g.Binary == "" {
		return "grype"
	}
	return g.Binary
}

func (g *GrypeScanner) run(ctx context.Context, dir string, args ...string) ([]byte, []byte, error) {
	limit := operation.Limit(g.Timeout, operation.GrypeTimeout)
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if g.Run != nil {
		stdout, stderr, err := g.Run(ctx, dir, g.bin(), args...)
		return stdout, stderr, operation.Result(ctx, "grype "+args[0], limit, err)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, g.bin(), args...)
	cmd.WaitDelay = operation.PipeWait
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &stdout, &stderr
	cmd.Env = append(os.Environ(), "GRYPE_CHECK_FOR_APP_UPDATE=false")
	if g.dbPrepared {
		cmd.Env = append(cmd.Env, "GRYPE_DB_AUTO_UPDATE=false")
	}
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), operation.Result(ctx, "grype "+args[0], limit, err)
}

// CheckGrype checks, before anything is scanned, that grype runs here, and
// returns its version. Without it every rescan would be unknown for a reason
// that has nothing to do with the estate.
func (g *GrypeScanner) CheckGrype(ctx context.Context) (string, error) {
	if g.Run == nil {
		if _, err := exec.LookPath(g.bin()); err != nil {
			return "", fmt.Errorf("grype is not available (%s): --rescan scans each image's verified SBOMs with grype; install it (https://github.com/anchore/grype#installation), or name it with --grype-path: %w", g.bin(), err)
		}
	}
	stdout, stderr, err := g.run(ctx, "", "version", "-o", "json")
	if err != nil {
		return "", fmt.Errorf("grype (%s) didn't run: %w: %s", g.bin(), err, lastLine(string(stderr)))
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(stdout, &info); err != nil || info.Version == "" {
		return "", fmt.Errorf("couldn't tell which grype %s is (grype version -o json printed %q)", g.bin(), strings.TrimSpace(string(stdout)))
	}
	return info.Version, nil
}

// PrepareDB readies grype's vulnerability database once, before anything is
// scanned: `grype db update`, after which every scan uses the database as it
// is (GRYPE_DB_AUTO_UPDATE=false) instead of checking for, and on a fresh
// runner downloading, an update itself, all at once into the same cache.
// When GRYPE_DB_AUTO_UPDATE is already false (a database imported for an
// air-gapped run, say), it is left as it is, and only checked to be there
// (`grype db status`). Either failing is an operational error: the rescans
// would all be unknown for a reason that has nothing to do with the estate.
func (g *GrypeScanner) PrepareDB(ctx context.Context) error {
	if v, ok := os.LookupEnv("GRYPE_DB_AUTO_UPDATE"); ok {
		if auto, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil && !auto {
			if _, stderr, err := g.run(ctx, "", "db", "status"); err != nil {
				return fmt.Errorf("grype has no usable vulnerability database (grype db status: %w: %s), and GRYPE_DB_AUTO_UPDATE=false says not to download one: import one (grype db import), or unset GRYPE_DB_AUTO_UPDATE", err, lastLine(string(stderr)))
			}
			return nil
		}
	}
	if _, stderr, err := g.run(ctx, "", "db", "update"); err != nil {
		return fmt.Errorf("grype couldn't update its vulnerability database (grype db update: %w: %s): --rescan needs one; check access to grype's database (GRYPE_DB_UPDATE_URL), or import one (grype db import) and set GRYPE_DB_AUTO_UPDATE=false", err, lastLine(string(stderr)))
	}
	g.dbPrepared = true
	return nil
}

// Scan runs grype over an SBOM written to a temporary directory, with the
// VEX document beside it.
func (g *GrypeScanner) Scan(ctx context.Context, sbom, vex []byte) (grypeResult, error) {
	dir, err := os.MkdirTemp("", "clearcutt-rescan-")
	if err != nil {
		return grypeResult{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "sbom.json"), sbom, 0o600); err != nil {
		return grypeResult{}, err
	}
	args := []string{"sbom:sbom.json", "-o", "json"}
	if len(vex) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "vex.json"), vex, 0o600); err != nil {
			return grypeResult{}, err
		}
		args = append(args, "--vex", "vex.json")
	}
	stdout, stderr, err := g.run(ctx, dir, args...)
	if err != nil {
		g.failed.Add(1)
		return grypeResult{}, fmt.Errorf("grype: %w: %s", err, lastLine(string(stderr)))
	}
	var r grypeResult
	var keys map[string]json.RawMessage
	if json.Unmarshal(stdout, &keys) != nil || json.Unmarshal(stdout, &r) != nil || keys["matches"] == nil {
		g.failed.Add(1)
		return grypeResult{}, errors.New("grype's output couldn't be read as its JSON report")
	}
	g.scanned.Add(1)
	return r, nil
}

// sbomDoc is a verified SBOM: the document and the purls of its packages.
type sbomDoc struct {
	raw   json.RawMessage
	purls []string
}

// rescanImage scans each platform image's verified SBOM with the run's
// scanner and reports what it found beside the publisher's scan. Only SBOMs a
// trusted signer verified are scanned: a platform image with none, one that
// grype couldn't scan, or an image not all of whose platform images could be
// read leaves the rescan unknown, never clean.
func rescanImage(ctx context.Context, img *report.Image, platforms []report.Platform, platformsErr error, data imageData, opts Options) *report.Rescan {
	out := &report.Rescan{Status: "unknown", Platforms: map[string]string{}}
	if img.Digest == "" {
		out.Detail = "The image couldn't be read, so there was nothing to scan."
		return out
	}
	if platformsErr != nil {
		out.Detail = fmt.Sprintf("Not every platform image could be read (%v), so the image's current vulnerabilities are unknown.", platformsErr)
		return out
	}
	if len(platforms) == 0 {
		out.Detail = "No platform image was read, so there was nothing to scan."
		return out
	}
	scans := map[string]vulnScan{}
	var reasons []string
	for _, p := range platforms {
		key := firstNonEmpty(p.Platform, "default")
		doc, ok := data.sboms[key]
		if !ok {
			out.Platforms[key] = "unknown"
			reasons = append(reasons, key+": no verified SBOM (its SBOM is "+firstNonEmpty(img.Evidence.SBOM.Platforms[key], img.Evidence.SBOM.Status)+"), and only verified SBOMs are scanned")
			continue
		}
		identity := imageIdentity{repository: img.Repository, tags: img.Tags, digest: img.Digest, platform: key, platformDigest: p.Digest}
		vex, scoped := scopeVEX(opts.VEX, identity, doc.purls)
		result, err := opts.Scanner.Scan(ctx, doc.raw, vex)
		if err != nil {
			out.Platforms[key] = "unknown"
			reasons = append(reasons, key+": grype couldn't scan it: "+err.Error())
			continue
		}
		scan := vulnScan{Scanner: strings.TrimSpace(firstNonEmpty(result.Descriptor.Name, "grype") + " " + result.Descriptor.Version), ScannedAt: opts.GeneratedAt, Result: result, Database: result.database()}
		for _, m := range result.IgnoredMatches {
			scan.suppressedBy = append(scan.suppressedBy, attributeSuppressions(scoped, m))
		}
		scans[key] = scan
		out.Platforms[key] = "scanned"
	}
	if len(reasons) > 0 {
		sort.Strings(reasons)
		out.Detail = "The image's current vulnerabilities are unknown: " + strings.Join(reasons, "; ") + "."
		return out
	}
	out.Status = "scanned"
	out.Vulnerabilities = mergeScans(scans, "scan")
	return out
}

// rescanAge is how old a rescan's view is: its database's build time, when
// known (findings know nothing published after it), else when it ran.
func rescanAge(r *report.Rescan, now time.Time) (time.Duration, bool) {
	if r == nil || r.Status != "scanned" || r.Vulnerabilities == nil {
		return 0, false
	}
	at := r.Vulnerabilities.ScannedAt
	if db := r.Vulnerabilities.Database; db != nil && db.Built != "" {
		at = db.Built
	}
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return 0, false
	}
	return now.Sub(t), true
}

// NothingChecked reports whether a report shows a run that could check
// nothing: every piece of evidence of every image is unknown (cosign or the
// registries unreachable, or no image readable). Such a report is honest,
// but it isn't a result, and a run that produced it shouldn't exit as if it
// were.
func NothingChecked(r *report.Report) bool {
	if r == nil || len(r.Images) == 0 {
		return false
	}
	for _, img := range r.Images {
		for _, k := range Kinds {
			if evidenceItem(img.Evidence, k).Status != "unknown" {
				return false
			}
		}
	}
	return true
}

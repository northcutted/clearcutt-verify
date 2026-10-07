# ClearCutt CLI Reference

This page is a compact map of the current CLI surface. It is not a replacement
for `clearcutt-verify --help`; use help output for the final flag contract.

## Exit Codes

The CLI distinguishes "the gate said no" from "the gate could not run":

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded; all requested checks passed. |
| `1` | Operational error: bad flags or arguments, IO failure, missing catalog data, or required tooling not available. |
| `2` | Policy gate failed: a verification, conformance, certification, exception, or threshold check evaluated and rejected the input. |

Exit code 2 applies to the gating commands — `verify image`, `verify catalog`,
`verify rebuild`, `verify release-evidence`,
`conformance run`, `certify`, and `exceptions validate` — plus the other
check-list gates (`catalog validate`, `overlay verify`, `platform status`,
`runtime validate`, `service validate`, `app diff-base`, `app rebase`). CI
`run:` steps fail on any non-zero code, so existing workflow gates keep working;
scripts that need to branch on "policy failure vs broken pipeline" can now test
the code directly:

```text
clearcutt-verify verify image <id> ...; case $? in
  0) deploy ;;
  2) block release: policy gate rejected the image ;;
  *) investigate: verification could not run ;;
esac
```

## Output Formats

The global `--format` flag accepts `table` (default), `json`, or `yaml`.
Unknown values are rejected before the command runs. The gating commands above
emit a common machine-readable shape for `--format json|yaml`: an overall
`status` (`pass` or `fail`) plus a `checks` array of
`{id, status, message}` objects, with data on stdout and human commentary on
stderr.

## Install

Releases ship cross-compiled binaries (`clearcutt-verify-<os>-<arch>` for
`darwin`/`linux`/`windows` on `amd64`/`arm64`), a keyless Sigstore signature
bundle per binary (`<binary>.sig`), `clearcutt-cli-assets.json`, and a
`SHA256SUMS.txt` manifest. The release workflow owns the release
binary matrix, optional `cosign sign-blob` calls, and checksum manifest; GitHub
Actions supplies the OIDC identity when the release workflow runs it with
`--sign`. Download a binary and its `.sig` bundle from the
[latest release](https://github.com/northcutted/clearcutt-verify/releases/latest)
and verify before use:

```bash
cosign verify-blob \
  --bundle clearcutt-verify-linux-amd64.sig \
  --certificate-identity-regexp '^https://github\.com/northcutted/clearcutt(-verify)?/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  clearcutt-verify-linux-amd64

chmod +x clearcutt-verify-linux-amd64
./clearcutt-linux-amd64 --catalog cli/internal/testdata/catalog list
```

The identity is exact, not a pattern: releases run only from
`refs/heads/main`, and the same string is pinned as
`release.workflowIdentity` in `clearcutt.yaml` and passed to
`clearcutt-verify verify release-evidence --workflow-identity`. Build from source
(below) when contributing.

## Build

```bash
go -C cli build -o ../clearcutt-verify ./cmd/clearcutt-verify
./clearcutt-verify --help
```

Catalog-backed discovery commands need generated catalog data or a fixture:

```bash
./clearcutt-verify --catalog cli/internal/testdata/catalog list
./clearcutt-verify --catalog cli/internal/testdata/catalog inspect java21-distroless
```

## App-Team Commands

```bash
./clearcutt-verify --catalog cli/internal/testdata/catalog list
./clearcutt-verify --catalog cli/internal/testdata/catalog inspect java21-distroless

## Catalog And Trust Commands

```bash
./clearcutt-verify catalog generate --config clearcutt.yaml --include-services --output dist/catalog
./clearcutt-verify --catalog dist/catalog catalog validate
./clearcutt-verify --catalog dist/catalog catalog summarize
./clearcutt-verify --catalog dist/catalog catalog inspect java21-distroless
./clearcutt-verify catalog diff --old previous/catalog --new dist/catalog
./clearcutt-verify catalog site build --catalog dist/catalog --output dist/site --install
./clearcutt-verify catalog workflow-params --github-output "$GITHUB_OUTPUT"
./clearcutt-verify catalog vex-all --output-dir dist/site/vex
./clearcutt-verify catalog build --core-dir core --update-db --include-services

./clearcutt-verify --catalog cli/internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --allow-preview

./clearcutt-verify verify release-evidence \
  --ref ghcr.io/YOUR_ORG/YOUR_REPO/YOUR_IMAGE:TAG \
  --repo YOUR_ORG/YOUR_REPO \
  --workflow-identity 'https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main' \
  --core-dir core

./clearcutt-verify verify rebuild ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java21:TAG-distroless \
  --target java21-distroless \
  --rebuild \
  --pull-registry-archive \
  --require-digest-match \
  --require-layer-match \
  --diffoscope-out rebuild.diff.txt \
  --output-predicate


For `verify release-evidence`, `--core-dir core` runs core-pinned verifier tools
through the scaffolded Nix backend. The current backend supplies Cosign, GitHub
CLI, and a flake-local SLSA verifier binary derivation.

## Estate Discovery Commands

Discover and govern an image estate ClearCutt did not build. Every command here is
read-only against the registry: it reads manifests, configs, and tags, and writes
local files.

```bash
# Enumerate a registry namespace into an inventory
./clearcutt-verify registry scan \
  --registry ghcr.io \
  --namespace YOUR_ORG/YOUR_REPO \
  --repository YOUR_BASE_IMAGE \
  --repository YOUR_APP_IMAGE \
  --output dist/scan/images.yaml

# Read each image's manifest, config, layers, and labels
./clearcutt-verify import observe --images dist/scan/images.yaml --output dist/scan/observations.json

# Derive which images are built on which, and how stale each one is
./clearcutt-verify graph build \
  --observations dist/scan/observations.json \
  --output dist/scan/graph.json \
  --report dist/scan/inventory.md

# What the estate has in common at the layer level
./clearcutt-verify graph layers \
  --observations dist/scan/observations.json \
  --output dist/scan/layers.json \
  --report dist/scan/commonality.md \
  --mermaid dist/scan/graph.mmd

# Use it as a CI gate
./clearcutt-verify graph build --observations dist/scan/observations.json \
  --output dist/scan/graph.json --min-confidence verified --fail-on-stale

# Persist the snapshot where the images live, and read it back
./clearcutt-verify estate push ghcr.io/acme/clearcutt-estate:2026-08-31 \
  --dir dist/scan --generated-at 2026-08-31T00:00:00Z
./clearcutt-verify estate pull ghcr.io/acme/clearcutt-estate:2026-08-31 --output ./snapshot
```

`estate push` stores observations and both graphs as a single OCI artifact. It is
deterministic — identical content yields an identical digest — so a scheduled push of
an unchanged estate does not create a new version, and drift is a diff between two
tags. `estate pull` rejects any manifest that is not a ClearCutt estate artifact. See
[registry-graph.md](registry-graph.md#persisting-a-snapshot).

`registry scan` prefers the distribution `_catalog` endpoint filtered by
`--namespace`; registries that do not implement it (GHCR, Docker Hub) need
`--repository`, which is repeatable. Cosign signature and attestation sidecar tags
are skipped unless `--include-sidecar-tags` is passed.

`graph layers` is the content view: fleet core, common layers, content-identical
images, similarity clusters, per-image unique content, deduplication accounting, and
a Mermaid diagram. It never implies parentage.

`graph build` also reports shared-layer blast radius: which images carry a given
layer, which is the remediation question for estates whose images share content
without one being built on the other (Nix `dockerTools.buildLayeredImage` output,
notably). Reproducible builders that zero the creation timestamp are detected, and
currency falls back to tag order with a warning rather than ranking every version
equally old.

`graph build` establishes each relationship by layer-digest matching (proof),
`org.opencontainers.image.base.digest`, buildpacks lifecycle metadata,
`org.opencontainers.image.base.name`, or build history — in that order — and labels
every edge with the confidence that method earns. See
[Registry scan and the base image graph](registry-graph.md).

## Estate Verification

```bash
# Verify every image against a policy and write the estate report bundle
./clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out dist/estate

# Reuse a scan, verify with flags instead of a policy file, gate CI
./clearcutt-verify estate verify --observations dist/scan/observations.json \
  --require signature,sbom,provenance \
  --trusted-identity-regexp '^https://github\.com/acme/' \
  --trusted-issuer https://token.actions.githubusercontent.com \
  --out dist/estate --fail-on failed
```

See [Verifying an estate](verify-estate.md) and the [report contract](../contract/README.md).

## Scan Commands

```bash
./clearcutt-verify scan refresh-kev

./clearcutt-verify scan \
  --mode remediation \
  --sbom-dir site/src/data/sboms \
  --out-dir site/src/data/vulnerabilities \
  --depth 4 \
  --kev-file core/build-outputs/security-intel/known_exploited_vulnerabilities.json \
  --update-db
```

`scan refresh-kev` writes the CISA KEV catalog cache and a small status JSON
under `core/build-outputs/security-intel/` by default. Refresh failures are
non-fatal unless `--fail-on-unavailable` is set.

`scan --update-db` refreshes the local Grype database before scanning. If the
refresh fails, the CLI warns and continues with the active local database, which
matches the scheduled remediation behavior without requiring a separate shell
wrapper.

## Policy And Exception Commands

```bash
./clearcutt-verify --catalog cli/internal/testdata/catalog policy java21-distroless --engine kyverno --environment production --namespace apps
./clearcutt-verify exceptions validate exceptions.yaml --fail-on-expired-exceptions
./clearcutt-verify vex --help
```

`policy` generates Kubernetes admission policy examples. `exceptions` governs
time-boxed vulnerability exceptions. `vex` emits OpenVEX documents.

ClearCutt reports and gates on vulnerabilities; it does not patch images. The
`remediation` and `overlay` command groups, which drafted Nix overlay patches
for the images ClearCutt built, were removed along with the fleet they served.
`remediation.policy` in `clearcutt.yaml` still drives the severity
thresholds `scan` and `verify` gate on.

## Drift Check Scope

The PR gate validates high-traffic command snippets that are expected to be
executable from this checkout. Commands that require registry credentials,
cluster access, or fork-specific values must be marked as examples and should
use placeholders such as `YOUR_ORG`.

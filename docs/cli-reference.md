# ClearCutt Verify CLI Reference

This page is a compact map of the current CLI surface. It is not a replacement
for `clearcutt-verify --help`; use help output for the final flag contract.

## Exit Codes

The CLI distinguishes "the gate said no" from "the gate could not run":

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded; all requested checks passed. |
| `1` | Operational error: bad flags or arguments, IO failure, or required tooling not available. |
| `2` | Policy gate failed: a check evaluated and rejected the input. |

Exit code 2 comes from `estate verify --fail-on failed|unverified` and
`graph build --fail-on-stale`. `estate verify` checks its tools before it
reads anything: cosign must be on `PATH` (or `--cosign-path`) and be cosign
v3 whenever the policy trusts a signer, and `--reproduce` needs
`clearcutt-factory` (or `--factory-path`), and `--rescan` needs `grype` (or
`--grype-path`). A missing tool, or a cosign of another major version, exits
1 and writes no report. Evidence cosign couldn't check during the run (a
registry or the transparency log unreachable or refusing) is `unknown`,
which leaves the image `unverified`: exit 2 under `--fail-on unverified`,
not under `--fail-on failed`. Two outcomes write the report and still exit
1, because nothing was found out: every piece of evidence of every image
`unknown` (cosign, the registries, or the images unreachable), and, with
`--rescan`, grype unable to scan any image. Scripts can branch on the code:

```text
clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --out dist/estate --fail-on failed; case $? in
  0) publish the report ;;
  2) an image falls short of the policy (the report says which and why) ;;
  *) investigate: verification could not run ;;
esac
```

## Output Formats

The global `--format` flag accepts `table` (default), `json`, or `yaml`.
Unknown values are rejected before the command runs.

## Install

Releases ship cross-compiled binaries (`clearcutt-verify-<os>-<arch>` for
`darwin`/`linux` on `amd64`/`arm64`), a keyless Sigstore signature
bundle per binary (`<binary>.sig`), and a `SHA256SUMS.txt` manifest. Download a
binary and its `.sig` bundle from the
[latest release](https://github.com/northcutted/clearcutt-verify/releases/latest)
and verify before use:

```bash
cosign verify-blob \
  --bundle clearcutt-verify-linux-amd64.sig \
  --certificate-identity-regexp '^https://github\.com/northcutted/clearcutt(-verify)?/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  clearcutt-verify-linux-amd64

chmod +x clearcutt-verify-linux-amd64
```

In GitHub Actions, the repository's action
(`uses: northcutted/clearcutt-verify@vX.Y.Z`) does the same; see
[Verifying an estate in GitHub Actions](github-actions.md).

Releases after v0.15.0 also carry a SLSA build provenance attestation per
binary, which `gh attestation verify clearcutt-verify-linux-amd64 --repo northcutted/clearcutt-verify`
checks.

## Build

```bash
go -C cli build -o ../clearcutt-verify ./cmd/clearcutt-verify
./clearcutt-verify --help
```

## Estate Discovery Commands

Discover and govern an image estate ClearCutt did not build. Every command here is
read-only against the registry: it reads manifests, configs, and tags, and writes
local files.

```bash
# Enumerate a registry namespace into an inventory (on GHCR, an
# organization's container packages, listed through the GitHub API)
./clearcutt-verify registry scan --github-org YOUR_ORG --output dist/scan/images.yaml

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

# Persist the snapshot where the images live, sign it, and read it back
./clearcutt-verify estate push ghcr.io/acme/clearcutt-estate:2026-08-31 \
  --dir dist/scan --generated-at 2026-08-31T00:00:00Z
cosign sign --key cosign.key ghcr.io/acme/clearcutt-estate@sha256:…   # the digest push printed
./clearcutt-verify estate pull ghcr.io/acme/clearcutt-estate:2026-08-31 --output ./snapshot --key cosign.pub
```

`estate push` stores observations and both graphs as a single OCI artifact. It is
deterministic — identical content yields an identical digest — so a scheduled push of
an unchanged estate does not create a new version, and drift is a diff between two
tags. `estate pull` rejects any manifest that is not a ClearCutt estate artifact,
and writes nothing until cosign v3 has verified its signature against the signer
named with `--certificate-identity` (or `--certificate-identity-regexp`) and
`--certificate-oidc-issuer`, or `--key` (with `--insecure-ignore-tlog` for a key
that signs without a transparency log), as `cosign verify` takes them; it exits 1
when it refuses one. `--allow-unverified` writes it anyway, with a warning. See
[registry-graph.md](registry-graph.md#persisting-a-snapshot).

`registry scan --registry HOST` uses the distribution `_catalog` endpoint,
filtered by `--namespace`. Registries that do not implement it, Docker Hub among
them, need `--repository`, which is repeatable. GHCR does not implement it
either: `--github-org` lists an organization's (or user's) container packages
through the GitHub Packages API instead, with a `GITHUB_TOKEN` that can read
packages, and `--package-prefix` keeps some of them. Cosign signature and
attestation sidecar tags are skipped unless `--include-sidecar-tags` is passed.

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

# Rescan each image's verified SBOMs with grype, gate on the worse of the
# attested and the fresh findings (the policy's scanSource), apply its vex:
# documents, and observe the upstream bases without gating on them
./clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out dist/estate \
  --rescan --fail-on failed

# The images proven to be built on a base, with their source repositories
./clearcutt-verify estate dependents --report dist/estate/estate-report.json \
  --base ghcr.io/acme/platform/run-python --format json

# Keep the report next to the images, and read it back
./clearcutt-verify estate push ghcr.io/acme/estate:latest --dir dist/estate \
  --file estate-report.json --file estate-history.json
./clearcutt-verify estate pull ghcr.io/acme/estate:latest --output dist/estate \
  --certificate-identity https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To verify a single image, give `--refs` a file holding just its reference: an
estate of one image gets the same checks and the same report.

See [Verifying an estate](verify-estate.md) and the [report contract](../contract/README.md).

## Drift Check Scope

The PR gate validates command snippets that are expected to be executable from
this checkout. Commands that require registry credentials, cluster access, or
organization-specific values must be marked as examples and should use
placeholders such as `YOUR_ORG`.

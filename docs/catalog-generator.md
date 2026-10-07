# Catalog Generator

`clearcutt-verify catalog generate` writes portable catalog artifacts that can be used
by CI, policy checks, auditors, and the Astro evidence portal. It is the
data-only path: it produces JSON and schemas, but it does not build HTML.

Use `clearcutt-verify catalog build` when you want the full ClearCutt release workflow
pipeline: gather release evidence, enrich registry metadata, scan cached SBOMs,
fold results back into the catalog, and run catalog verification. Use
`clearcutt-verify catalog generate` when you already have inputs and want a portable
catalog directory.

## ClearCutt Fleet Mode

Fleet mode reads owner, repository, registry, release window, and target
defaults from `clearcutt.yaml`, then uses ClearCutt release evidence,
registry enrichment, SBOM cache data, and vulnerability scan JSON where
available.

```bash
clearcutt-verify catalog generate \
  --config clearcutt.yaml \
  --include-services \
  --output ./dist/catalog
```

Omit `--include-services` when you intentionally want a runtime-only catalog.
Configured service images are included only when that flag is present. Mixed
runtime and service catalogs emit v2 schema records; runtime-only catalogs stay
v1-compatible.

Useful flags:

- `--owner` and `--repo` override source repository discovery.
- `--registry-base` overrides the image registry namespace.
- `--limit` bounds the number of non-draft releases to inspect.
- `--targets` limits generation to a comma-separated image allowlist.
- `--include-services` includes configured first-class service images such as
  `postgres16`, `valkey8`, and `oauth2-proxy7`.
- `--sbom-cache-dir`, `--enrichment-dir`, and `--vuln-dir` point at local
  evidence inputs.
- `--force-refresh-all` and `--force-refresh-tags` control release asset
  refresh behavior.
- `--generated-at` pins timestamps for reproducible tests.

## Generic OCI Mode

Generic OCI mode does not require Nix, ClearCutt release workflows, or a
ClearCutt fork. It converts an explicit `images.yaml` inventory into catalog
records and preserves unavailable evidence as missing-evidence states.

Imported-fleet mode starts one step earlier: `clearcutt-verify import images` converts a
plain refs file into the same generic OCI `images.yaml`, with optional
`origin`, `governance`, and `evidencePolicy` metadata. Imported catalog records
mark `createdByClearCutt: false` and `provenanceClaim: none` so the catalog can
govern an image without claiming ClearCutt built it.

This is the backend used by the `catalog-only` platform bootstrap profile. The
bootstrap command renders a lightweight GitHub control-plane repo with
`images.yaml`, catalog/Pages workflows, desired GitHub state, and local docs:

```bash
clearcutt-verify catalog generate --config clearcutt.yaml --output dist/catalog
```

The generated `catalog.yml` workflow runs the same data path shown below, then
validates the catalog and builds the static site artifact.

```bash
clearcutt-verify catalog generate \
  --images images.yaml \
  --output ./dist/catalog \
  --owner acme \
  --repo base-images \
  --registry-base ghcr.io/acme/base-images
```

See [generic OCI mode](generic-oci-mode.md) for the `images.yaml` shape and
limitations, and [imported fleets](imported-fleets.md) for the import,
observation, assessment, report, and rebase planning flow.

## Output Layout

Generation writes a self-contained catalog directory:

```text
dist/catalog/
  index.json
  summary.json
  evidence-manifest.json
  images/
    java21-distroless.json
  raw/
    sbom/
    provenance/
    scans/
    test-results/
  schemas/
    catalog-index.v1.schema.json
    evidence-manifest.v1.schema.json
    evidence-manifest.v2.schema.json
    image-record.v1.schema.json
```

The `raw/` subdirectories are intentionally present even when there are no raw
artifacts yet. That keeps static-site publishing and downstream sync jobs
stable.

## Validate And Inspect

Validate generated data before publishing it:

```bash
clearcutt-verify --catalog ./dist/catalog catalog validate
clearcutt-verify --catalog ./dist/catalog catalog validate \
  --schema-version clearcutt.catalog.index/v1
clearcutt-verify --catalog ./dist/catalog catalog validate \
  --schema-version clearcutt.catalog.image/v1
clearcutt-verify --catalog ./dist/catalog catalog validate \
  --schema-version clearcutt.catalog.evidence-manifest/v2
```

Warnings are used for missing optional evidence. Turn them into failures when a
pipeline requires complete evidence:

```bash
clearcutt-verify --catalog ./dist/catalog catalog validate --warnings-as-errors
```

Summarize, inspect, or diff catalogs:

```bash
clearcutt-verify --catalog ./dist/catalog --format json catalog summarize
clearcutt-verify --catalog ./dist/catalog catalog inspect java21-distroless
clearcutt-verify catalog diff --old ./previous/catalog --new ./dist/catalog
```

## Evidence Semantics

Catalog records do not collapse trust into one boolean. Signatures, SLSA
provenance, SBOMs, tests, vulnerability scans, lifecycle, runtime contracts, and
per-architecture data are reported independently. A missing SBOM should remain a
missing SBOM, not become a generic "not secure" or "secure" flag.

`evidence-manifest.json` is the per-release evidence index. It is generated from
the image records and lists each image release, expected evidence channels,
observed channels, missing channels, immutable refs when a manifest digest is
known, signer/provenance summaries, release asset URLs, and the source catalog
record path. `catalog validate` rejects a manifest that drifts from the image
records.

That distinction matters for:

- CI gates that require only specific evidence channels.
- Security review workflows that need to see incomplete inputs.
- Generated sites that degrade gracefully when generic OCI inputs do not have
  ClearCutt release attestations.

For a reader-facing guide to catalog badges, raw evidence, missing evidence, and
generic OCI degraded-evidence mode, see
[`trust/catalog-evidence.md`](trust/catalog-evidence.md).

## Data-Only CI Example

```yaml
name: Catalog
on:
  workflow_dispatch:

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: cli/go.mod
      - run: go build -C cli -o ../clearcutt-verify ./cmd/clearcutt-verify
      - run: ./clearcutt-verify catalog generate --config clearcutt.yaml --include-services --output dist/catalog
      - run: ./clearcutt-verify --catalog dist/catalog catalog validate
```

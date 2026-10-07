# Catalog Schema

ClearCutt catalog artifacts are versioned JSON files. The schema files are
published in the repository under `schemas/` and copied into every generated
catalog under `schemas/`.

## Schema Versions

Current schema version identifiers:

- `clearcutt.catalog.index/v1`
- `clearcutt.catalog.image/v1`
- `clearcutt.catalog.index/v2`
- `clearcutt.catalog.image/v2`
- `clearcutt.catalog.evidence-manifest/v2`

Evidence manifest v1 remains published for compatibility with its legacy
presence-based status vocabulary. New catalogs emit v2, which records
`missing`, `observed`, `verified`, `attested`, `stale`, and `unknown` states and
can carry imported-image origin claims without treating observation as proof.

Runtime-only catalogs may remain on v1. Catalogs containing first-class service
records emit v2 and add `kind` plus service metadata while preserving the
runtime fields that older consumers use.

Validate a generated catalog against a required schema version:

```bash
clearcutt-verify --catalog ./dist/catalog catalog validate \
  --schema-version clearcutt.catalog.index/v1

clearcutt-verify --catalog ./dist/catalog catalog validate \
  --schema-version clearcutt.catalog.image/v1
```

## Directory Layout

```text
catalog/
  index.json
  summary.json
  evidence-manifest.json
  images/
    <image-id>.json
  raw/
    sbom/
    provenance/
    scans/
    test-results/
  schemas/
    catalog-index.v1.schema.json
    catalog-index.v2.schema.json
    evidence-manifest.v1.schema.json
    evidence-manifest.v2.schema.json
    image-record.v1.schema.json
    image-record.v2.schema.json
```

## `index.json`

`index.json` is the catalog overview. It contains:

- `schemaVersion`
- `generatedAt`
- `generator`
- `source`
- top-level `summary`
- owner, repository, repository URL, and registry base
- release summaries
- language summaries
- tier summaries
- image summaries
- `kind` on image summaries in v2: `runtime`, `service`, or `application`

The index is optimized for listing, filtering, dashboards, and the catalog grid.
It should not duplicate every package, layer, vulnerability, or attestation
detail.

## `images/<id>.json`

Each image record contains the detailed evidence used by image detail pages and
policy tools:

- language and tier metadata
- registry and image reference fields
- lifecycle and runtime contract
- release history
- per-architecture payloads
- SBOM packages
- OCI layers and labels
- test results
- vulnerability findings
- signatures, attestations, and provenance metadata when available

For `kind: service` records, v2 also includes:

- `service.template`
- `service.version`
- `service.ports`
- `service.stateful`
- `service.dataDirs`
- `service.smoke`
- `service.smokeStatus`

## `summary.json`

`summary.json` is a small report for CI logs, dashboards, and quick checks. It
summarizes image, release, SBOM, scan, and evidence counts without requiring a
consumer to parse every image record.

## `evidence-manifest.json`

`evidence-manifest.json` is a formal per-release evidence manifest generated
from `images/*.json`. It gives auditors one index of:

- image id, release tag, image ref, immutable digest ref when available, and
  catalog record path,
- imported-image origin, ClearCutt creation status, and provenance claim when
  applicable,
- expected and observed channel status for signature, provenance, SBOM, tests,
  vulnerability scans, exceptions, and VEX,
- missing evidence channels,
- per-architecture SBOM/test/scan state,
- signer identity, provenance summary, and release asset URLs when recorded.

The manifest does not replace registry-side verification. It centralizes what
the generated catalog currently reports and makes missing data queryable.
`catalog validate` rejects a present manifest if it no longer matches the image
records.

## `raw/`

The `raw/` directories are reserved for source evidence artifacts:

- `raw/sbom/`
- `raw/provenance/`
- `raw/scans/`
- `raw/test-results/`

They may be empty. They are still emitted so static-site and artifact-publishing
workflows have stable paths.

## Compatibility Rules

- Consumers should check `schemaVersion` before assuming a record shape.
- Missing optional evidence should be handled as missing evidence, not as a
  successful trust signal.
- Unknown future fields should be tolerated by readers unless they are running
  with strict validation.
- Schema files in generated catalogs should match the repository schema files
  for the same version.

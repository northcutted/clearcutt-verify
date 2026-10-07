# Catalog Evidence Walkthrough

The catalog is an evidence report, not a magic trust oracle. It is useful
because it keeps evidence channels separate and makes missing data visible.

## What The Catalog Proves

When catalog data is generated from ClearCutt release evidence, image records can
show:

- image id, runtime, tier, lifecycle, and production status,
- tag, manifest digest, architectures, and release timestamp,
- whether signature evidence is recorded,
- whether SBOM evidence is recorded for each architecture,
- whether SLSA provenance is recorded,
- whether smoke/conformance tests are recorded,
- whether vulnerability scan data is attached,
- exception and VEX-derived triage state when available.

## What The Catalog Does Not Prove

- A green catalog badge is not itself a live registry verification.
- Missing evidence is not the same as failed cryptographic verification.
- Generic OCI mode may have useful inventory data with degraded evidence.
- Vulnerability counts are scan-time facts, not future-risk guarantees.

## How To Inspect One Image

```bash
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog inspect java21-distroless
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --allow-preview
```

For generated data:

```bash
./clearcutt-verify catalog generate --config clearcutt.yaml --include-services --output dist/catalog
./clearcutt-verify --catalog dist/catalog catalog validate
./clearcutt-verify --catalog dist/catalog catalog inspect java21-distroless
jq '.releases[] | select(.imageId=="java21-distroless") | {imageRef, immutableRef, missing}' \
  dist/catalog/evidence-manifest.json
```

## Portal Labels

Generated site labels should be read literally:

- "catalog reports signature" means the catalog record reports signature evidence.
- "provenance recorded" means a provenance channel is present in the record.
- "no high/critical in current scan" means the attached scan reports no current
  Critical or High findings for the displayed scope.
- "scan pending" means no vulnerability scan data is attached.

Use the audit guide or registry-side commands to verify signatures, SBOMs, and
provenance against the registry.

## Raw Evidence

Generated catalogs include a formal `evidence-manifest.json` beside `index.json`.
Use it as the per-release checklist of expected, observed, and missing evidence
channels. Catalog directories may also include raw evidence under:

```text
raw/
  sbom/
  provenance/
  scans/
  test-results/
```

The directories can exist even when files are missing. That is intentional: it
keeps static publishing stable and lets the catalog report missing evidence as a
first-class state.

## Generic OCI Mode

Generic OCI mode starts from `images.yaml` and does not require ClearCutt
release workflows. It is useful for inventory and portal rendering, but it is a
degraded-evidence mode unless the input references real signatures, SBOMs,
provenance, scans, and tests.

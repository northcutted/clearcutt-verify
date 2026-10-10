# Imported Fleets

ClearCutt Verify does not need to create an image to govern it.

Imported-fleet mode lets a platform team point clearcutt-verify at existing OCI
image references, observe available metadata, map which images are built on
which, and report evidence gaps, without claiming anything about how the images
were built.

## What Imported-Fleet Mode Can Do

- Enumerate a registry namespace directly, without a hand-written ref list
  (`clearcutt-verify registry scan` — see [registry-graph.md](registry-graph.md)).
- Discover which images are built on which by comparing layer digests, without any
  declared `expectedBase` (`clearcutt-verify graph build`).
- Inventory existing OCI image refs from a simple list.
- Generate a ClearCutt-compatible `images.yaml`.
- Preserve missing signatures, SBOMs, provenance, scans, and tests honestly.
- Report digest pinning and mutable tag visibility.
- Report runtime contract gaps from available metadata.
- Discover base relationships from layers, labels, and history.
- Verify whatever signatures and attestations the images do carry
  (`estate verify`), and list a base's dependents (`estate dependents`).

## What Imported-Fleet Mode Cannot Claim

- It cannot infer signatures.
- It cannot infer SLSA provenance.
- It cannot prove the source or build workflow for an image ClearCutt did not
  build.
- It cannot fix CVEs: rebuilding and rebasing belong to whoever builds the
  images (for example clearcutt-factory).

## Golden Path

```bash
clearcutt-verify import images \
  --refs examples/imported-fleet/refs.txt \
  --output /tmp/clearcutt-import/images.yaml \
  --owner acme \
  --repo imported-fleet \
  --registry-base registry.acme.dev/platform \
  --generated-at 2026-01-01T00:00:00Z \
  --force

clearcutt-verify import observe \
  --images /tmp/clearcutt-import/images.yaml \
  --offline-fixtures examples/imported-fleet/observations.fixture.json \
  --output /tmp/clearcutt-import/observations.json \
  --generated-at 2026-01-01T00:00:00Z

clearcutt-verify import assess \
  --images /tmp/clearcutt-import/images.yaml \
  --observations /tmp/clearcutt-import/observations.json \
  --output /tmp/clearcutt-import/governance

clearcutt-verify import report \
  --assessment /tmp/clearcutt-import/governance \
  --output /tmp/clearcutt-import/imported-fleet-report.md

clearcutt-verify graph build \
  --observations /tmp/clearcutt-import/observations.json \
  --output /tmp/clearcutt-import/graph.json --report /tmp/clearcutt-import/inventory.md
```

## Offline Demo

```bash
./scripts/demo-imported-fleet-offline.sh
```

The offline demo uses fake registry refs plus committed observation fixtures in
`examples/imported-fleet/`. It is deterministic, safe for CI, and proves the
command flow and governance semantics without contacting a registry. It proves
that clearcutt-verify can import images it did not build, preserve missing
evidence honestly, produce assessment/report artifacts, and map base
relationships from fixture metadata. It does not prove live registry
observation.

By default the script writes to a unique `/tmp/clearcutt-import-demo.*`
directory and prints the actual path. Pass `OUT=/tmp/clearcutt-import-demo` when
you want a fixed directory for follow-up inspection.

The generated report states that ClearCutt did not build the imported fleet and
that No build provenance is inferred unless actual provenance evidence is
verified.

## Live Demo

```bash
cp examples/imported-fleet-live/refs.public.example examples/imported-fleet-live/refs.txt
$EDITOR examples/imported-fleet-live/refs.txt
./scripts/demo-imported-fleet-live.sh
```

The live demo contacts real registries and does not run in required CI. Output
may vary because public registries can rate-limit, deny access, delete images,
or move tags. Use digest-pinned refs for stable behavior. Missing provenance is
expected unless imported images publish verifiable provenance; observed metadata,
SBOM references, labels, or scans are not build provenance.

## What This Proves

- clearcutt-verify can govern images it did not build.
- It shows missing evidence as governance gaps.
- It produces assessment and report artifacts.
- It proves base relationships by layer digest where they exist.

## What This Does Not Prove

- ClearCutt cannot infer build provenance.
- ClearCutt cannot prove source repository or build workflow for arbitrary
  imported images.
- ClearCutt does not make imported images trusted by default.

## Evidence Semantics

Imported-fleet evidence channels use these meanings:

- `missing`: no evidence was observed or supplied.
- `observed`: metadata or an artifact exists, but ClearCutt has not verified it.
- `verified`: a ClearCutt verifier actually ran and recorded the result. The
  current imported observation path does not promote caller-supplied status
  strings to verified evidence.
- `attested`: an attestation artifact is present and recorded.
- `stale`: evidence exists but should be refreshed before relying on it.

Missing evidence is not the same as insecure. It is a governance gap.
Observed evidence is not the same as verified evidence. An observed SBOM is not
build provenance.

## Agentic Use

Imported-fleet mode emits structured JSON suitable for agents:

- `observations.json`
- `estate-summary.json`
- `evidence-gaps.json`
- `policy-posture.json`
- `runtime-contract-gaps.json`
- `graph.json`, and the estate report (`estate-report.json`)

Agents may open pull requests with `images.yaml` or report updates. Agents must
not publish production tags, relax policy, infer provenance, or mark imported
images production-admissible without explicit verified evidence.

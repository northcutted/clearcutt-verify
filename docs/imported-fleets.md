# Imported Fleets

ClearCutt does not need to create an image to govern it.

Imported-fleet mode builds on generic OCI mode. It lets a platform team point
ClearCutt at existing OCI image references, catalog them, observe available
metadata, report evidence gaps, and discover app/base rebase candidates without
claiming ClearCutt built the images.

## What Imported-Fleet Mode Can Do

- Enumerate a registry namespace directly, without a hand-written ref list
  (`clearcutt-verify registry scan` — see [registry-graph.md](registry-graph.md)).
- Discover which images are built on which by comparing layer digests, without any
  declared `expectedBase` (`clearcutt-verify graph build`).
- Inventory existing OCI image refs from a simple list.
- Generate a ClearCutt-compatible `images.yaml`.
- Generate catalog JSON and an evidence manifest.
- Preserve missing signatures, SBOMs, provenance, scans, and tests honestly.
- Report digest pinning and mutable tag visibility.
- Report runtime contract gaps from available metadata.
- Discover app/base relationships from layers, labels, history, and user hints.
- Produce rebase candidate sets and auditable plans.

## What Imported-Fleet Mode Cannot Claim

- It cannot infer signatures.
- It cannot infer SLSA provenance.
- It cannot prove the source or build workflow for an image ClearCutt did not
  build.
- It cannot safely rebase every image.
- It cannot fix CVEs without rebuild or rebase ownership.
- It does not require Nix.

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

clearcutt-verify catalog generate \
  --images /tmp/clearcutt-import/images.yaml \
  --output /tmp/clearcutt-import/catalog \
  --owner acme \
  --repo imported-fleet \
  --registry-base registry.acme.dev/platform

clearcutt-verify --catalog /tmp/clearcutt-import/catalog catalog validate

clearcutt-verify import observe \
  --images /tmp/clearcutt-import/images.yaml \
  --offline-fixtures examples/imported-fleet/observations.fixture.json \
  --output /tmp/clearcutt-import/observations.json \
  --generated-at 2026-01-01T00:00:00Z

clearcutt-verify import assess \
  --images /tmp/clearcutt-import/images.yaml \
  --observations /tmp/clearcutt-import/observations.json \
  --catalog /tmp/clearcutt-import/catalog \
  --output /tmp/clearcutt-import/governance

clearcutt-verify import report \
  --assessment /tmp/clearcutt-import/governance \
  --output /tmp/clearcutt-import/imported-fleet-report.md

clearcutt-verify rebase discover \
  --apps examples/imported-fleet/apps.yaml \
  --bases /tmp/clearcutt-import/images.yaml \
  --observations /tmp/clearcutt-import/observations.json \
  --output /tmp/clearcutt-import/rebase-candidates.json
```

## Offline Demo

```bash
./scripts/demo-imported-fleet-offline.sh
```

The offline demo uses fake registry refs plus committed observation fixtures in
`examples/imported-fleet/`. It is deterministic, safe for CI, and proves the
command flow and governance semantics without contacting a registry. It proves
that ClearCutt can import images it did not build, generate a governed catalog,
preserve missing evidence honestly, produce assessment/report artifacts, and
discover a verified rebase candidate from fixture metadata. It does not prove
live registry observation.

By default the script writes to a unique `/tmp/clearcutt-import-demo.*`
directory and prints the actual path. Pass `OUT=/tmp/clearcutt-import-demo` when
you want a fixed directory for follow-up inspection.

The generated report states that ClearCutt did not build the imported fleet and
that No build provenance is inferred unless actual provenance evidence is
verified.

To render the generated catalog as a site, use the printed output directory:

```bash
./scripts/demo-imported-fleet-offline.sh
clearcutt-verify catalog site build --catalog <OUT>/dist/catalog --output <OUT>/dist/site --install
```

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

- ClearCutt can catalog images it did not build.
- ClearCutt can distinguish imported images from ClearCutt-built images.
- ClearCutt can show missing evidence as governance gaps.
- ClearCutt can produce assessment and report artifacts.
- ClearCutt can discover rebase candidates when app/base relationships are
  provable.

## What This Does Not Prove

- ClearCutt cannot infer build provenance.
- ClearCutt cannot prove source repository or build workflow for arbitrary
  imported images.
- ClearCutt cannot safely rebase every app image.
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

## Rebase Confidence

- `verified`: exact layer prefix or trusted base digest labels match, old app
  digest is known, old and new base digests are known, and runtime families are
  compatible.
- `assisted`: labels, history, names, or user-supplied hints identify a likely
  base, but the base boundary is not mechanically proven.
- `unsafe`: the image appears squashed or flattened, the base boundary cannot be
  proven, architecture or runtime family is incompatible, a digest is unknown,
  or runtime contracts are incompatible.

Rebase discovery and planning do not publish images or mutate production tags.
Any apply path must require explicit confirmation, tests, certification, and
human approval.

## Agentic Use

Imported-fleet mode emits structured JSON suitable for agents:

- `observations.json`
- `estate-summary.json`
- `evidence-gaps.json`
- `policy-posture.json`
- `runtime-contract-gaps.json`
- `rebase-candidates.json`
- `ImportedFleetRebasePlan` JSON

Agents may open pull requests with `images.yaml` or report updates. Agents must
not publish production tags, relax policy, infer provenance, or mark imported
images production-admissible without explicit verified evidence.

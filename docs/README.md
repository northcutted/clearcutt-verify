# ClearCutt Documentation

Use this page as the documentation front door. Each role gets one first
document, one first command, and then deeper links.

| Role | First document | First command | Then read |
| --- | --- | --- | --- |
| App developer | [Getting started](getting-started.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless` | [App lifecycle](app-lifecycle.md), [Certification](certification.md) |
| Imported fleet owner | [Imported fleets](imported-fleets.md) | `go -C cli run ./cmd/clearcutt import images --refs ../examples/imported-fleet/refs.txt --output /tmp/clearcutt-import/images.yaml --force` | [Generic OCI mode](generic-oci-mode.md), [Catalog generator](catalog-generator.md) |
| Estate owner | [Registry scan and the base image graph](registry-graph.md) | `go -C cli run ./cmd/clearcutt registry scan --registry ghcr.io --namespace YOUR_ORG/YOUR_REPO --repository YOUR_IMAGE --output /tmp/images.yaml` | [Registry-native evidence](registry-native-evidence.md), [Imported fleets](imported-fleets.md) |
| Security or auditor | [Trust evidence walkthrough](trust/evidence-walkthrough.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --allow-preview` | [Catalog evidence](trust/catalog-evidence.md), [Security model](security-model.md), [Policy bundles](policy-bundles.md) |
| Manager | [Alternatives and fit](alternatives.md) | `sed -n '1,120p' docs/alternatives.md` | [Enterprise adoption](enterprise-adoption.md) |
| Open-source reviewer | [Demo path](demo.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list` | [Mental model](concepts/mental-model.md), [Glossary](concepts/glossary.md), [CLI reference](cli-reference.md) |

## Concept Docs

- [Mental model](concepts/mental-model.md): the platform loop, app-delivery loop,
  lanes, tiers, evidence, and ownership boundaries.
- [Glossary](concepts/glossary.md): canonical definitions for repeated terms.

## Proof Docs

- [Trust evidence walkthrough](trust/evidence-walkthrough.md): trace source,
  release workflow, image digest, SBOM, provenance, catalog record, and policy.
- [Catalog evidence walkthrough](trust/catalog-evidence.md): understand evidence
  badges, missing data, raw evidence, and generic OCI mode.
- [Verifying an estate](verify-estate.md): verify every image's signatures and
  attestations against trusted signers, and write the estate report
  ([contract](../contract/README.md)) a portal reads.
- [Registry scan and the base image graph](registry-graph.md): point ClearCutt at a
  registry, discover which images are built on which, and produce an auditable
  inventory with drift.
## One word: estate

An **estate** is what ClearCutt governs: whatever is in your registry, including
images you did not build, cannot rebuild, and did not choose. An estate is
discovered, not declared.

ClearCutt builds no images, so there is no second noun. Earlier versions also
used "fleet" for a set of images the project built itself; that capability was
removed, and with it the word.

The config file is `clearcutt.yaml`. `clearcutt.fleet.yaml` is still read when
present, so an existing fork needs no migration, and a config carrying the old
`templates`, `release` or `admission` sections still validates — those sections
are simply ignored.

- [Registry-native evidence](registry-native-evidence.md): store evidence,
  estate snapshots and history in the registry instead of GitHub releases — plus
  the two operational constraints that come with it (garbage collection, and
  which tags must stay mutable) and what to do about them.
- [Imported fleets](imported-fleets.md): import existing OCI refs, observe
  evidence without provenance claims, assess governance gaps, and plan rebases.
- [Catalog generator](catalog-generator.md): generate and validate catalog data.
- [Catalog schema](catalog-schema.md): inspect the JSON contract.

## Operating Docs

- [Site generator](site-generator.md): build and customize a generated evidence
  portal.
- [Policy bundles](policy-bundles.md): generate admission policies.

## App-Team Docs

- [Getting started](getting-started.md): choose an image, generate a starter,
  build, certify, and hand evidence to CI.
- [App lifecycle](app-lifecycle.md): app build, diff-base, rebase, and
  attestation examples across stacks.
- [Certification](certification.md): local/offline app-image checks.

## Contributor Checks

If the platform-source drift check fails, regenerate the embedded source archive
before testing or building release assets:

```bash
go -C cli run ./internal/platformsource/internal/genplatformsource
```

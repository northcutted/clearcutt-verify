# ClearCutt Reviewer Demo

This demo path is designed for a clean checkout. Steps marked "fixture-backed"
use committed catalog data. Steps marked "live" require a fork, registry, or
local container tooling.

![Terminal demo of the fixture-backed ClearCutt path](images/demo.gif)

## 1. Explain The Project

```bash
sed -n '1,140p' README.md
sed -n '1,120p' docs/README.md
```

Expected readout: ClearCutt is a CLI for bootstrapping user-owned GitHub
container image control planes, generated repos own the operating surface, and
roles have different first paths. Forking remains an advanced/reference path.

## 2. Fixture-Backed Catalog Proof

```bash
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog list
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog inspect java21-distroless
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --allow-preview
```

Expected readout: the CLI can list, inspect, and gate catalog data without
generated artifacts.

## 4. Catalog Portal Build

```bash
go -C cli run ./cmd/clearcutt-verify catalog site build \
  --catalog internal/testdata/mixed-catalog \
  --template ../site \
  --output /tmp/clearcutt-demo-site \
  --install
```

Expected readout: static HTML renders from fixture catalog data, including
service records and image detail pages.

Fixture-backed portal screenshots:

![Catalog matrix generated from the mixed fixture catalog](images/catalog-matrix.png)

![java21-distroless evidence section generated from the mixed fixture catalog](images/java21-distroless-evidence.png)

## 6. Live Trust Walkthrough

Use [trust/evidence-walkthrough.md](trust/evidence-walkthrough.md) after a fork
has published at least one release. The fixture screenshots above prove local
rendering and catalog wiring; a fork owner should additionally compare them with
the live Pages site for that fork's current registry, OIDC subject, signatures,
SBOMs, provenance, scans, tests, and exception records.

## Feedback Questions

- Can the reviewer explain what ClearCutt is in one minute?
- Can they tell what is fixture-backed versus live registry proof?
- Can an app developer find the template/dev/certify path without learning Nix?
- Can a security reviewer trace a release identity from config to policy?
- Can a platform owner see what their fork must operate?
- Can they distinguish the CLI source repository from the generated catalog
  control-plane repository?

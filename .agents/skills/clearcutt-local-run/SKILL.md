---
name: clearcutt-local-run
description: Use when building, running, previewing, or validating ClearCutt locally, especially when catalog data may be missing or stale, site builds depend on generated catalog files, or a clean-clone fixture path is needed.
---

# ClearCutt Local Run

Use this skill for local build, run, preview, and stale-catalog questions.

## First checks

1. Run `git status --short` so local generated or dirty state is visible.
2. If catalog behavior matters, identify the catalog mode:
   - fixture catalog: clean-clone, offline proof;
   - generated portable catalog: current generator output in temp or `dist/`;
   - live release-evidence catalog: `catalog build` from release assets and registry evidence;
   - `site/src/data/catalog`: ignored local state that may be stale.
3. If `site/src/data/catalog/index.json` exists, inspect `generatedAt`, `owner`, `repo`, and `registryBase` before treating it as evidence.

## Commands

CLI:

```bash
cd cli && go test ./...
cd cli && go vet ./...
cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify
```

Clean-clone fixture proof:

```bash
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog list
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog catalog validate
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog inspect java21-distroless
```

Current generator proof without touching ignored site data:

```bash
cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify
./clearcutt-verify catalog generate --config clearcutt.yaml --include-services --output /tmp/clearcutt-catalog
./clearcutt-verify --catalog /tmp/clearcutt-catalog catalog validate
```

Fixture-backed site build:

```bash
cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify
./clearcutt-verify catalog site build --catalog cli/internal/testdata/mixed-catalog --template site --output /tmp/clearcutt-site --install --clean
```

Astro source checks:

```bash
cd site && npm install
cd site && npm run typecheck
cd site && npm run build
```

Core remediation tests:

```bash
cd core && python3 -m unittest tests/test_remediation_pipeline.py
```

## Catalog rules

- Do not assume `site/src/data/catalog` is present in a clean checkout.
- Do not assume `site/src/data/catalog` is fresh when it exists locally.
- Prefer fixture-backed commands for docs, tests, clean-clone claims, and quick local proof.
- Prefer `/tmp` or `dist/` output for generated catalog experiments.
- Only write to `site/src/data/catalog` when the task explicitly requires refreshing local site data.
- Use `./clearcutt-verify catalog build` only for live release-evidence parity or publish-path work.

## Make caveat

On this host, `make` can fail before a recipe runs because of a local `xcrun`
architecture mismatch. Prefer the direct commands above unless the task is
specifically about Makefile behavior.

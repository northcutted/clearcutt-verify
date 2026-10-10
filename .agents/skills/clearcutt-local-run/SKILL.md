---
name: clearcutt-local-run
description: Use when building, running, or validating clearcutt-verify locally, including the offline demo, the estate report fixture, and live runs against registries with rate limits.
---

# ClearCutt Verify Local Run

## First checks

1. Run `git status --short` so local generated or dirty state is visible.
2. Decide whether the task needs a registry. Prefer the offline demo and
   committed fixtures for docs, tests, and quick proof.

## Commands

CLI:

```bash
cd cli && go test ./...
cd cli && go vet ./...
cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify
```

Offline proof:

```bash
./scripts/demo-imported-fleet-offline.sh
```

The estate report fixture (regenerate deliberately; it reads live registries
and, with `--reproduce`, rebuilds images):

```bash
cd contract/fixtures/northcutted-images
../../../clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name northcutted-images \
  --platforms linux/amd64,linux/arm64 --reproduce --out .
```

## Live-run rules

- Docker Hub allows 100 anonymous manifest reads an hour per IP; a run reads
  each manifest once, but other tools on the same IP share the quota. Lookups
  it refuses are `unknown`, so check the report's warnings before committing a
  fixture.
- `--reproduce` needs `clearcutt-factory` and a container runtime; on macOS the
  rebuild works under the user cache directory because the VM doesn't share
  `/tmp`.

## Make caveat

On this host, `make` can fail before a recipe runs because of a local `xcrun`
architecture mismatch. Prefer the direct commands above unless the task is
specifically about Makefile behavior.

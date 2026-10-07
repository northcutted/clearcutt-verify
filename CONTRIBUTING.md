# Contributing

ClearCutt is split into three workspaces:

- `core/` owns the Nix image matrix, runtime registry, image compiler, pipeline scripts, and shell/Python validation.
- `cli/` owns the Go command surface, catalog tooling, verification commands, app lifecycle helpers, and generated site template.
- `site/` owns the Astro catalog site used by the reference fleet and generated downstream sites.

Start with the smallest proof that matches your change. Avoid broad matrix runs for docs-only or single-command edits.

## First Clean-Clone Proof

```bash
cd cli
go run ./cmd/clearcutt-verify --catalog internal/testdata/catalog catalog validate
go run ./cmd/clearcutt-verify --catalog internal/testdata/catalog inspect java21-distroless
```

Those commands use committed fixtures and do not require release assets, registry credentials, or generated `site/src/data/catalog` state.

## Pre-PR Gate

`make check` is the canonical pre-PR command. It mirrors the `go-ci` job in
`.github/workflows/pr-gate.yml` — `go vet`, `gofmt` enforcement, the CLI
build, the Go coverage floor, documented-command validation, and workflow
hardening checks — so a clean local run means the Go gate passes in CI:

```bash
make check
```

Run it before every pull request, after the focused checks below.

## Common Checks

For CLI changes:

```bash
cd cli
go test ./...
go vet ./...
go build -o ../clearcutt-verify ./cmd/clearcutt-verify
```

For core pipeline or remediation changes:

```bash
cd core
python3 -m unittest tests/test_pipeline_evidence.py
python3 -m unittest tests/test_remediation_pipeline.py
```

For Nix image-gate changes, run the focused command first, then the full suite when the local Nix environment is ready:

```bash
cd core
nix develop --extra-experimental-features "nix-command flakes" --accept-flake-config --command ./tests/verify.sh
```

For site changes (`make site-typecheck` and `make site-build` run `npm ci`
automatically the first time and whenever `site/package-lock.json` changes):

```bash
cd site
npm install
npm run typecheck
npm run build
```

> Troubleshooting: on some macOS hosts, `make` can fail before recipes run
> because of local Xcode tooling. If `make check` aborts that way, run the
> direct commands above (and the steps from the `check` recipe in the
> `Makefile`) until the host toolchain is fixed.

## Generated State

Do not use ignored local catalog data as proof. `site/src/data/catalog` may exist on a maintainer machine but is not clean-clone evidence. Prefer `cli/internal/testdata/catalog` or generate temporary output under `/tmp`.

Agent-facing files live under `.agents/`; `.codex/` is limited to local Codex config and command guardrails. Root-level harness files such as `.cursorrules`, `.windsurfrules`, and `.claudeprompt` are ignored local outputs and should not be committed.

## Release And Security Work

Release, catalog, provenance, and vulnerability-remediation changes should include the narrow local check plus the relevant workflow/static validation. Keep evidence claims tied to concrete files, commands, and registry digests. Do not broaden product claims without updating the docs and the verification path in the same change.

See [docs/README.md](docs/README.md) for reader-facing documentation and [FORKING.md](FORKING.md) for fork-owner setup.

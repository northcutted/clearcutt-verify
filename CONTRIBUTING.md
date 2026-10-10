# Contributing

ClearCutt Verify is one Go module under `cli/`, with its data contract in
`contract/` and documentation in `docs/`.

Start with the smallest proof that matches your change.

## First Clean-Clone Proof

```bash
./scripts/demo-imported-fleet-offline.sh
```

It maps a committed snapshot of four images and needs no registry access or
credentials.

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

```bash
cd cli
go test ./...
go vet ./...
go build -o ../clearcutt-verify ./cmd/clearcutt-verify
```

When you change the estate report types in `cli/internal/report`, regenerate
the contract's JSON Schemas and commit them with the change:

```bash
go -C cli test ./internal/report -run TestContractSchemasCurrent -update
```

> Troubleshooting: on some macOS hosts, `make` can fail before recipes run
> because of local Xcode tooling. If `make check` aborts that way, run the
> steps from the `check` recipe in the `Makefile` directly until the host
> toolchain is fixed.

## Generated State

Agent-facing files live under `.agents/`; `.codex/` is limited to local Codex
config and command guardrails. Root-level harness files such as
`.cursorrules`, `.windsurfrules`, and `.claudeprompt` are ignored local outputs
and should not be committed.

## Release And Security Work

Release, provenance, and verification changes should include the narrow local
check plus the relevant workflow/static validation. Keep evidence claims tied to
concrete files, commands, and registry digests. Do not broaden product claims
without updating the docs and the verification path in the same change.

See [docs/README.md](docs/README.md) for reader-facing documentation.

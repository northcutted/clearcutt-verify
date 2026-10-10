---
name: clearcutt-cli-change
description: Use when implementing or reviewing clearcutt-verify Go CLI changes under cli/, including command UX, registry and graph commands, estate verification, the report contract, tests, or coverage gates.
---

# ClearCutt CLI Change

Use this skill for write-heavy or review-heavy work in the Go CLI.

## Contract

- Keep public CLI behavior backward compatible unless the approved action item requires a breaking change.
- Use existing Cobra command patterns under `cli/internal/commands/`.
- Use structured parsers and internal packages rather than ad hoc string manipulation when handling OCI, policy, or evidence data.
- Tests must run offline. Use in-process registries and committed fixtures (`examples/`, `contract/`).
- Do not change the report contract casually. Changes must be additive; regenerate `contract/*.schema.json` with the types, and update docs and tests in the same slice.

## Workflow

1. Inspect the current command surface before editing:
   - `cli/internal/commands/root.go`
   - the target command file
   - `docs/cli-reference.md`
   - relevant tests and fixtures
2. Keep implementation focused on the approved command or behavior.
3. Add targeted Go tests for new branches, failure modes, help behavior, or fixture-backed workflows.
4. Run `gofmt` on modified Go files.
5. Use direct workspace commands when `make` is not needed, because local macOS `make` can be blocked by `xcrun` issues on this host.

## Validation

Pick the smallest relevant set:

```bash
cd cli && go test ./...
cd cli && go vet ./...
cd cli && go build ./cmd/clearcutt-verify
cd cli && ./scripts/go-coverage.sh
git diff --check
```

For command presentation changes, also run:

```bash
cd cli && go run ./cmd/clearcutt-verify --help
```

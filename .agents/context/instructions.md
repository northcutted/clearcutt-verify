# Agent Developer Instructions

This document defines the core guidelines, command mappings, and coding standards for all AI agents working in this repository.

---

## 1. Directory Layout & Core Commands

| Path | Purpose | Key Commands |
| :--- | :--- | :--- |
| `cli/` | Go CLI (`clearcutt-verify`). | `make cli-build`<br>`make cli-test`<br>`make cli-vet` |
| `contract/` | The estate report contract: generated JSON Schemas, a synthetic example, a real fixture. | `go -C cli test ./internal/report -run TestContractSchemasCurrent -update` |
| `docs/` | Reader-facing documentation. | `./scripts/validate-doc-commands.sh ./clearcutt-verify` |

---

## 2. Gating and Verification Protocols

Never finalize a pull request or commit without running the local checks that mirror CI (`make check`, or its steps directly when `make` fails on macOS):

```bash
cd cli && go vet ./... && go test ./...
gofmt -l cli/cmd cli/internal   # must print nothing
./scripts/validate-doc-commands.sh ./clearcutt-verify
./scripts/demo-imported-fleet-offline.sh
(cd cli && COVERAGE_MIN=85.0 ./scripts/go-coverage.sh)
```

---

## 3. Go Coding Standards

When writing Go code inside `cli/`:
1. **Error Handling:** Wrap returned errors with context: `fmt.Errorf("read report: %w", err)`.
2. **Formatting:** Always run `gofmt` on all modified files.
3. **Offline tests:** Use in-process registries (`github.com/google/go-containerregistry/pkg/registry`) and committed fixtures, never live registries, in unit tests.
4. **Signatures:** When dealing with signature and attestation verification, ensure strict OIDC issuer and subject checks. Never use wildcard matching patterns in production code paths.

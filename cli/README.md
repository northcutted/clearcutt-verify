# ClearCutt Verify CLI Workspace

This workspace owns the Go `clearcutt-verify` CLI.

```bash
cd cli
go test ./...
go vet ./...
go build -o ../clearcutt-verify ./cmd/clearcutt-verify
```

From the repository root, the same operations are available through:

```bash
make cli-test
make cli-vet
make cli-build
```

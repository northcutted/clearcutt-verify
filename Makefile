.PHONY: cli-build cli-test cli-vet cli-fmt-check demo-imported-fleet-offline demo-imported-fleet-live test check agent-sync

# .agents/ is upstream-only tooling, so the target degrades to a note instead
# of erroring in checkouts without it.
agent-sync:
	@if [ -d .agents ]; then bash .agents/sync.sh; else echo "agent-sync: no .agents/ harness in this checkout; nothing to do"; fi

cli-build:
	cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify

cli-test:
	cd cli && go test ./...

cli-vet:
	cd cli && go vet ./...

cli-fmt-check:
	@unformatted="$$(gofmt -l cli/cmd cli/internal)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt required for:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

demo-imported-fleet-offline:
	./scripts/demo-imported-fleet-offline.sh

demo-imported-fleet-live:
	./scripts/demo-imported-fleet-live.sh

test: cli-vet cli-test

# Canonical pre-PR gate. Mirrors the go-ci job in
# .github/workflows/pr-gate.yml: vet, formatting, CLI build, the coverage
# floor, documented-command validation, and workflow hardening checks.
check: cli-vet cli-fmt-check cli-build
	cd cli && COVERAGE_MIN=85.0 ./scripts/go-coverage.sh
	./scripts/validate-doc-commands.sh ./clearcutt-verify
	./scripts/validate-workflow-hardening.sh

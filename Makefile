.PHONY: cli-build cli-test cli-vet cli-fmt-check site-install site-dev site-build site-typecheck site-verify-catalog core-verify core-remediation-tests catalog-generate catalog-enrich catalog-build catalog-scan demo-imported-fleet-offline demo-imported-fleet-live test check agent-sync

# .agents/ is upstream-only tooling (excluded from platform-new scaffolds), so
# the target degrades to a note instead of erroring in fork checkouts.
agent-sync:
	@if [ -d .agents ]; then bash .agents/sync.sh; else echo "agent-sync: no .agents/ harness in this checkout (upstream-only tooling); nothing to do"; fi

# The platform source archive is generated (gitignored), not committed; build
# and test through these targets so the binary ships it and its tests run.
cli-build:
	cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify

cli-test: cli-embed-source
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

# npm ci sentinel: site targets work from a clean clone without a manual
# `make site-install`, and skip the reinstall until package-lock.json changes.
# `npm ci` wipes node_modules (and the previous stamp) before reinstalling, so
# a partially deleted tree also re-syncs.
SITE_NPM_STAMP := site/node_modules/.npm-ci.stamp

$(SITE_NPM_STAMP): site/package-lock.json
	cd site && npm ci
	touch $@

site-install: $(SITE_NPM_STAMP)

site-dev: $(SITE_NPM_STAMP)
	cd site && npm run dev

site-build: $(SITE_NPM_STAMP)
	cd site && npm run build

site-typecheck: $(SITE_NPM_STAMP)
	cd site && npm run typecheck

site-verify-catalog: cli-build
	./clearcutt-verify verify catalog --catalog site/src/data/catalog

catalog-generate: cli-build
	./clearcutt-verify catalog gather

catalog-enrich: cli-build
	./clearcutt-verify catalog enrich

catalog-build: cli-build
	./clearcutt-verify catalog build

catalog-scan: cli-build
	./clearcutt-verify scan --mode catalog

demo-imported-fleet-offline:
	./scripts/demo-imported-fleet-offline.sh

demo-imported-fleet-live:
	./scripts/demo-imported-fleet-live.sh

core-verify:
	cd core && nix develop --extra-experimental-features "nix-command flakes" --accept-flake-config --command ./tests/verify.sh

core-remediation-tests:
	cd core && python3 -m unittest tests/test_remediation_pipeline.py tests/test_closure_cve_check.py tests/test_pipeline_evidence.py

test: cli-vet cli-test site-typecheck site-build core-remediation-tests

# Canonical pre-PR gate. Mirrors the go-ci job in
# .github/workflows/pr-gate.yml: vet, formatting, CLI build, the coverage
# floor, documented-command validation, and workflow hardening checks.
check: cli-vet cli-fmt-check cli-build
	cd cli && COVERAGE_MIN=85.0 ./scripts/go-coverage.sh
	./scripts/validate-doc-commands.sh ./clearcutt-verify
	./scripts/validate-workflow-hardening.sh

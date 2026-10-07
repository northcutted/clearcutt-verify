#!/usr/bin/env bash
set -euo pipefail

bin="${1:-./clearcutt-verify}"

if [[ ! -x "$bin" ]]; then
  echo "usage: $0 ./clearcutt-verify" >&2
  echo "error: clearcutt-verify binary is not executable at $bin" >&2
  exit 2
fi

docs=(
  README.md
  docs/README.md
  docs/getting-started.md
  docs/cli-reference.md
  docs/demo.md
  docs/imported-fleets.md
  docs/catalog-generator.md
  docs/site-generator.md
  docs/trust/evidence-walkthrough.md
  docs/trust/catalog-evidence.md
)

fail=0

search_fixed() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -n --fixed-strings -e "$pattern" "$@"
  else
    grep -n -F -e "$pattern" "$@"
  fi
}

search_regex() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -n -e "$pattern" "$@"
  else
    grep -n -E -e "$pattern" "$@"
  fi
}

contains_fixed() {
  local token="$1"
  if command -v rg >/dev/null 2>&1; then
    rg -q --fixed-strings -- "$token"
  else
    grep -q -F -- "$token"
  fi
}

check_absent() {
  local pattern="$1"
  local message="$2"
  if search_fixed "$pattern" "${docs[@]}" >/tmp/clearcutt-doc-drift.txt; then
    echo "docs command drift: $message" >&2
    cat /tmp/clearcutt-doc-drift.txt >&2
    fail=1
  fi
}

help_contains() {
  local description="$1"
  shift
  local token="${@: -1}"
  local cmd=("${@:1:$#-1}")
  if ! "$bin" "${cmd[@]}" --help | contains_fixed "$token"; then
    echo "docs command drift: help for 'clearcutt-verify ${cmd[*]}' does not contain '$token' ($description)" >&2
    fail=1
  fi
}

# Release-pin currency: documented CLI/image release pins (vX.Y.Z) in the files
# below are deliberate pins, but they must point at the newest published release
# so docs do not advertise stale versions. Shallow or tagless checkouts (CI uses
# fetch-depth 1, which fetches no tags) cannot see release tags; skip cleanly
# there instead of guessing.
release_pin_files=(
  docs/certification.md
  docs/app-lifecycle.md
  site/src/pages/cli.astro
  cli/internal/sitetemplate/template/src/pages/cli.astro
)
latest_release_tag="$(git tag --list 'v*' --sort=-v:refname 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)"
if [[ -z "$latest_release_tag" ]]; then
  echo "notice: no vX.Y.Z release tags visible (shallow or tagless checkout); skipping release-pin currency check" >&2
else
  stale_pins="$(grep -hoE 'v[0-9]+\.[0-9]+\.[0-9]+' "${release_pin_files[@]}" | sort -u | grep -vF -x "$latest_release_tag" || true)"
  if [[ -n "$stale_pins" ]]; then
    echo "docs command drift: release pins out of date (latest tag is $latest_release_tag): $(echo "$stale_pins" | tr '\n' ' ')" >&2
    search_regex "v[0-9]+\.[0-9]+\.[0-9]+" "${release_pin_files[@]}" | grep -vF "$latest_release_tag" >&2 || true
    fail=1
  fi
fi

check_absent "clearcutt-verify catalog gather" "use catalog generate or catalog build in docs"
check_absent "catalog site build --include-services" "--include-services belongs to catalog generate, not catalog site build"
check_absent "catalog site preview --site" "catalog site preview has no --site flag"
check_absent "clearcutt-verify policy verify" "policy generates admission policy; it is not a policy verify subcommand"
check_absent "v0.11.1" "documented ClearCutt release pins must point at a published release"
check_absent "imported images have provenance by default" "imported images must not claim provenance by default"
for token in \
  "ClearCutt does not need to create an image to govern it" \
  "ClearCutt did not build"; do
  if ! search_fixed "$token" docs/imported-fleets.md >/dev/null; then
    echo "docs command drift: docs/imported-fleets.md must include '$token'" >&2
    fail=1
  fi
done
if search_regex "build provenance and SBOM|SBOM.*gh attestation verify|gh attestation verify.*SBOM" "${docs[@]}" >/tmp/clearcutt-doc-drift.txt; then
  echo "docs command drift: GitHub CLI attestation examples must not imply SBOM verification" >&2
  cat /tmp/clearcutt-doc-drift.txt >&2
  fail=1
fi

help_contains "portable catalog generation" catalog generate "--include-services"
help_contains "site build catalog input" catalog site build "--catalog"
help_contains "site build output" catalog site build "--output"
help_contains "site build dependency install" catalog site build "--install"
help_contains "image catalog policy gate" verify image "--require-signature"
help_contains "registry-side evidence verification" verify release-evidence "--workflow-identity"
help_contains "admission policy engine" policy java21-distroless "--engine"

exit "$fail"

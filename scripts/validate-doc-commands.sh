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
  docs/cli-reference.md
  docs/imported-fleets.md
  docs/registry-graph.md
  docs/registry-native-evidence.md
  docs/verify-estate.md
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

check_absent "imported images have provenance by default" "imported images must not claim provenance by default"
for token in \
  "ClearCutt Verify does not need to create an image to govern it" \
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

help_contains "estate verification policy" estate verify "--policy"
help_contains "estate verification gate" estate verify "--fail-on"
help_contains "base dependents" estate dependents "--base"
help_contains "registry-side evidence verification" verify release-evidence "--workflow-identity"

exit "$fail"

#!/usr/bin/env bash
set -euo pipefail

fail=0

flag() {
  echo "workflow hardening drift: $*" >&2
  fail=1
}

search_regex() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg --hidden --no-ignore -n -e "$pattern" "$@"
  else
    grep -R -n -E -e "$pattern" "$@"
  fi
}

regex_exists() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -q -e "$pattern" "$@"
  else
    grep -q -E -e "$pattern" "$@"
  fi
}

fixed_exists() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -q --fixed-strings -- "$pattern" "$@"
  else
    grep -q -F -e "$pattern" "$@"
  fi
}

if search_regex 'uses:[[:space:]]+[^#[:space:]]+@(v[0-9]+|main|master)([[:space:]]|$)' .github/workflows .github/actions examples |
  grep -v -E 'generator_container_slsa3\.yml@v[0-9]+\.[0-9]+\.[0-9]+'; then
  flag "workflow and composite action references must be pinned to immutable SHAs"
fi

# requires a full vX.Y.Z tag and fails when the workflow is referenced by hash.


# GitHub-context expansion inside run: scripts is a script-injection vector:
# untrusted event payload fields are pasted into shell code by the templater.
# Pass them through the step's env: block instead. Line-based heuristic: track
# run: block scalars by indentation and flag github.event expansion inside.
run_injection="$(
  awk '
    function indent(line) { match(line, /^[[:space:]]*/); return RLENGTH }
    /^[[:space:]]*(-[[:space:]]+)?run:/ {
      in_run = 1
      run_indent = indent($0)
      if ($0 ~ /\$[{][{][[:space:]]*github\.event\./) printf "%s:%d:%s\n", FILENAME, FNR, $0
      next
    }
    in_run {
      if (NF > 0 && indent($0) <= run_indent) { in_run = 0; next }
      if ($0 ~ /\$[{][{][[:space:]]*github\.event\./) printf "%s:%d:%s\n", FILENAME, FNR, $0
    }
  ' .github/workflows/*.yml .github/actions/*/action.yml
)"

if [ -n "$run_injection" ]; then
  echo "$run_injection" >&2
  flag "run: scripts must not expand \${{ github.event.* }}; hoist values into the step env: block"
fi

if search_regex 'go-version:[[:space:]]' .github/workflows .github/actions; then
  flag "setup-go steps must use go-version-file: 'cli/go.mod' instead of a hardcoded go-version"
fi

for required in \
  "SHA256SUMS.txt" \
  "sha256sum -c -" \
  "cosign verify-blob" \
  "--certificate-identity-regexp"
do
  if ! fixed_exists "$required" .github/actions/install-clearcutt-verify/action.yml; then
    flag "install-clearcutt-verify action must verify downloaded release assets with '$required'"
  fi
done

exit "$fail"

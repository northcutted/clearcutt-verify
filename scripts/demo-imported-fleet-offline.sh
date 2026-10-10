#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$(mktemp -d /tmp/clearcutt-import-demo.XXXXXX)}"
STAMP="2026-01-01T00:00:00Z"

case "$OUT" in
  ""|"/"|"/tmp")
    echo "Refusing to use unsafe OUT directory: $OUT" >&2
    exit 2
    ;;
esac

find_go() {
  local candidate
  for candidate in "${GO:-}" /opt/homebrew/bin/go "$(command -v go 2>/dev/null || true)" /usr/local/go/bin/go; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

run_clearcutt() {
  if [[ -n "${CLEARCUTT:-}" ]]; then
    "$CLEARCUTT" "$@"
  else
    go_bin="$(find_go)"
    if "$go_bin" -C "$ROOT/cli" version >/dev/null 2>&1; then
      "$go_bin" -C "$ROOT/cli" run ./cmd/clearcutt-verify "$@"
    else
      (cd "$ROOT/cli" && "$go_bin" run ./cmd/clearcutt-verify "$@")
    fi
  fi
}

require_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "Missing required output: $file" >&2
    exit 1
  fi
}

marker="$OUT/.clearcutt-import-demo"
if [[ -d "$OUT" && -n "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit)" && ! -f "$marker" ]]; then
  echo "Refusing to replace non-demo output directory: $OUT" >&2
  exit 2
fi
if [[ -f "$marker" ]]; then
  find "$OUT" -mindepth 1 -maxdepth 1 ! -name '.clearcutt-import-demo' -exec rm -rf {} +
fi
mkdir -p "$OUT/dist"
touch "$marker"

run_clearcutt import images \
  --refs "$ROOT/examples/imported-fleet/refs.txt" \
  --output "$OUT/images.yaml" \
  --owner acme \
  --repo imported-fleet \
  --registry-base registry.acme.dev/platform \
  --generated-at "$STAMP" \
  --force

run_clearcutt import observe \
  --images "$OUT/images.yaml" \
  --offline-fixtures "$ROOT/examples/imported-fleet/observations.fixture.json" \
  --output "$OUT/dist/observations.json" \
  --generated-at "$STAMP"

run_clearcutt import assess \
  --images "$OUT/images.yaml" \
  --observations "$OUT/dist/observations.json" \
  --output "$OUT/dist/governance" \
  --generated-at "$STAMP"

run_clearcutt import report \
  --assessment "$OUT/dist/governance" \
  --output "$OUT/imported-fleet-report.md"

run_clearcutt graph build \
  --observations "$OUT/dist/observations.json" \
  --output "$OUT/dist/graph.json" \
  --report "$OUT/dist/inventory.md"

if command -v jq >/dev/null 2>&1; then
  jq -e '.kind == "ImportedFleetObservations"' "$OUT/dist/observations.json" >/dev/null
  jq -e '(.summary.importedImages // 4) == 4' "$OUT/dist/governance/estate-summary.json" >/dev/null
  jq -e '(.edges | length) >= 1' "$OUT/dist/graph.json" >/dev/null
else
  echo "jq not found; skipping optional JSON assertions."
fi

required_outputs=(
  "$OUT/images.yaml"
  "$OUT/dist/observations.json"
  "$OUT/dist/governance/estate-summary.json"
  "$OUT/dist/governance/evidence-gaps.json"
  "$OUT/dist/governance/policy-posture.json"
  "$OUT/imported-fleet-report.md"
  "$OUT/dist/graph.json"
  "$OUT/dist/inventory.md"
)

for file in "${required_outputs[@]}"; do
  require_file "$file"
done

grep -q "ClearCutt did not build" "$OUT/imported-fleet-report.md"
grep -q "No build provenance" "$OUT/imported-fleet-report.md"

echo
echo "Imported fleet offline demo completed."
echo "Output directory: $OUT"
echo
echo "Key outputs:"
echo "  images.yaml"
echo "  dist/observations.json"
echo "  dist/governance/estate-summary.md"
echo "  dist/governance/evidence-gaps.md"
echo "  dist/graph.json and dist/inventory.md"
echo "  imported-fleet-report.md"

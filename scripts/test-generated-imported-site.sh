#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$(mktemp -d /tmp/clearcutt-import-demo.XXXXXX)}"

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
    local go_bin
    go_bin="$(find_go)"
    if "$go_bin" -C "$ROOT/cli" version >/dev/null 2>&1; then
      "$go_bin" -C "$ROOT/cli" run ./cmd/clearcutt-verify "$@"
    else
      (cd "$ROOT/cli" && "$go_bin" run ./cmd/clearcutt-verify "$@")
    fi
  fi
}

OUT="$OUT" "$ROOT/scripts/demo-imported-fleet-offline.sh"

run_clearcutt catalog site build \
  --catalog "$OUT/dist/catalog" \
  --output "$OUT/dist/site" \
  --install

for expected in \
	"SBOM: Observed" \
	"Provenance: Missing" \
	"Signature: Observed" \
  "Imported image" \
  "ClearCutt did not build this image" \
  "No build provenance"; do
  if ! grep -R -F "$expected" "$OUT/dist/site" >/dev/null; then
    echo "Generated site is missing expected text: $expected" >&2
    echo "Output directory: $OUT" >&2
    exit 1
  fi
done

echo "Generated imported-fleet site contains expected evidence-status labels."
echo "Output directory: $OUT"

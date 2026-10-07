#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$(mktemp -d /tmp/clearcutt-import-live-demo.XXXXXX)}"
REFS="${REFS:-$ROOT/examples/imported-fleet-live/refs.txt}"
APPS="${APPS:-$ROOT/examples/imported-fleet-live/apps.yaml}"

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

if [[ ! -f "$REFS" ]]; then
  echo "Create examples/imported-fleet-live/refs.txt from refs.txt.example or pass REFS=/path/to/refs.txt" >&2
  exit 1
fi

echo "This demo contacts live registries. Output may vary. Public registries may rate-limit. Tags may move."
echo
echo "Preflight:"
echo "  refs: $REFS"
echo "  output: $OUT"
if [[ -n "${CLEARCUTT:-}" ]]; then
  echo "  clearcutt: $CLEARCUTT"
else
  echo "  clearcutt: go run from source"
fi
echo "  strict observation: ${STRICT:-0}"
echo
echo "Warning: live registries may rate-limit, deny access, or move tags. Prefer digest-pinned refs."

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
  --refs "$REFS" \
  --output "$OUT/images.yaml" \
  --owner acme \
  --repo imported-fleet-live \
  --registry-base registry.acme.dev/platform \
  --force

observe_args=(
  import observe
  --images "$OUT/images.yaml" \
  --output "$OUT/dist/observations.json"
)
if [[ "${STRICT:-0}" == "1" ]]; then
  observe_args+=(--strict)
fi
run_clearcutt "${observe_args[@]}"

run_clearcutt catalog generate \
  --images "$OUT/images.yaml" \
  --output "$OUT/dist/catalog" \
  --owner acme \
  --repo imported-fleet-live \
  --registry-base registry.acme.dev/platform

run_clearcutt --catalog "$OUT/dist/catalog" catalog validate

run_clearcutt import assess \
  --images "$OUT/images.yaml" \
  --catalog "$OUT/dist/catalog" \
  --observations "$OUT/dist/observations.json" \
  --output "$OUT/dist/governance"

run_clearcutt import report \
  --assessment "$OUT/dist/governance" \
  --output "$OUT/imported-fleet-report.md"

if [[ -f "$APPS" ]]; then
  run_clearcutt rebase discover \
    --apps "$APPS" \
    --bases "$OUT/images.yaml" \
    --observations "$OUT/dist/observations.json" \
    --output "$OUT/rebase-candidates.json"
else
  echo "No live apps inventory supplied; skipping rebase discovery."
fi

required_outputs=(
  "$OUT/images.yaml"
  "$OUT/dist/catalog/index.json"
  "$OUT/dist/catalog/evidence-manifest.json"
  "$OUT/dist/observations.json"
  "$OUT/dist/governance/estate-summary.json"
  "$OUT/dist/governance/evidence-gaps.json"
  "$OUT/dist/governance/policy-posture.json"
  "$OUT/imported-fleet-report.md"
)

for file in "${required_outputs[@]}"; do
  require_file "$file"
done

echo
echo "Imported fleet live demo completed."
echo "Output directory: $OUT"
echo
echo "Key outputs:"
echo "  images.yaml"
echo "  dist/catalog/index.json"
echo "  dist/catalog/evidence-manifest.json"
echo "  dist/observations.json"
echo "  dist/governance/estate-summary.json"
echo "  dist/governance/evidence-gaps.json"
echo "  dist/governance/policy-posture.json"
echo "  imported-fleet-report.md"
if [[ -f "$OUT/rebase-candidates.json" ]]; then
  echo "  rebase-candidates.json"
fi

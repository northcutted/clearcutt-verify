#!/usr/bin/env bash
# Regenerates docs/images/demo.gif from scripts/demo.tape.
# The recording is LIVE: the tape observes real public registries so that the
# creation of an observations.json is shown rather than asserted. Needs network.
# Requires vhs (https://github.com/charmbracelet/vhs); falls back to
# `nix run nixpkgs#vhs` when vhs is not on PATH.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! -x ./clearcutt-verify ]]; then
  echo "[record-demo] building CLI..." >&2
  (cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify)
fi

# The tape builds a scratch estate here from examples/runtime-estate/refs.txt.
rm -rf /tmp/clearcutt-demo

if command -v vhs >/dev/null 2>&1; then
  vhs scripts/demo.tape
else
  nix --extra-experimental-features 'nix-command flakes' run nixpkgs#vhs -- scripts/demo.tape
fi

echo "[record-demo] wrote docs/images/demo.gif" >&2

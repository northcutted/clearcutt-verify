# Verifying an estate in GitHub Actions

A scheduled job verifies the estate, keeps the report and its history in the
registry, and hands the bundle to
[clearcutt-portal](https://github.com/northcutted/clearcutt-portal) to publish.

```yaml
name: estate
on:
  schedule: [{cron: "17 6 * * *"}]
  repository_dispatch: {types: [clearcutt.estate-changed]}  # e.g. after a publish or rebase
  workflow_dispatch:
permissions:
  contents: read
  packages: write   # estate push; read is enough without it
concurrency: estate
jobs:
  verify:
    runs-on: ubuntu-latest
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
      # Installs cosign and a signature-verified clearcutt-verify release.
      - uses: northcutted/clearcutt-verify@vX.Y.Z
      # Private packages: let cosign read them too (clearcutt-verify reads
      # GITHUB_TOKEN for ghcr.io by itself).
      - run: echo "$GITHUB_TOKEN" | cosign login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
      # The last report, so this run extends its history.
      - run: clearcutt-verify estate pull ghcr.io/acme/estate:latest --output dist/estate || true
      - id: verify
        run: clearcutt-verify estate verify --refs estate/refs.txt --policy estate/policy.yaml --name acme --out dist/estate --fail-on failed
      # Keep the report even when the gate fails: that is the run to look at.
      - if: always() && hashFiles('dist/estate/estate-report.json') != ''
        run: clearcutt-verify estate push ghcr.io/acme/estate:latest --dir dist/estate --file estate-report.json --file estate-history.json
      - if: always() && hashFiles('dist/estate/estate-report.json') != ''
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with: {name: estate, path: dist/estate}
```

## What each piece does

- **Install.** `northcutted/clearcutt-verify@vX.Y.Z` installs cosign and the
  release's binary after checking it against `SHA256SUMS.txt` and its keyless
  signature from this repository's release workflow. `with: {version: source}`
  builds the action's own checkout instead; pin the action by commit SHA then.
- **Registry credentials.** clearcutt-verify reads the Docker keychain, and for
  `ghcr.io` only, the job's `GITHUB_TOKEN`; the token is never sent to another
  registry. cosign reads the Docker keychain, so private packages need the
  `cosign login` step (or `docker/login-action`). Other registries need their
  own login step.
- **History.** `estate pull` fetches the last bundle and `estate verify --out`
  extends `estate-history.json` in it; `estate push` stores the new bundle. Sign
  it if readers should be able to tell it came from this job:
  `cosign sign ghcr.io/acme/estate@sha256:…` (needs `id-token: write`).
- **Gate.** `--fail-on failed` (or `unverified`) exits **2** when an image falls
  short of the policy. Usage and runtime errors exit **1**, so a red policy
  result is distinguishable from a crash (`steps.verify.outcome` plus the exit
  code).
- **Throttling.** Registry lookups retry with backoff on 408, 429, and 5xx. A
  refusal that persists is reported as `unknown` for the images it affects, not
  as missing evidence. A run reads each manifest once; `--concurrency` bounds
  how many images are read at a time.
- **Inventory.** List the references in `estate/refs.txt`, or enumerate a
  GitHub organization's packages with `clearcutt-verify registry scan --github-org`
  (see [registry scan](registry-graph.md)).

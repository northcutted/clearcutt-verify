# Rebasable Application Lifecycle

This guide shows the supported end-to-end flow for application teams that want
to build once, sign the application payload, and later move that payload onto a
patched ClearCutt base without recompiling.

The important boundary is simple: `clearcutt-verify app build` packages one prebuilt
artifact into one OCI layer. The artifact can be a single file or a publish
directory; either way, that one app layer is preserved byte-for-byte during
`clearcutt-verify app rebase`. The base layers underneath it are swapped only after the
CLI verifies runtime compatibility and the developer signature over the source
image.

If your service needs runtime package installation or custom image assembly,
keep using a normal Containerfile and run `clearcutt-verify certify` on the finished
image.

For deployment shapes after certification, see
[`examples/oci-deployment/docker-compose.yml`](../examples/oci-deployment/docker-compose.yml)
and [`examples/k8s-deployment/deployment.yaml`](../examples/k8s-deployment/deployment.yaml).
Both examples deploy an app image built from a ClearCutt base, not the base image
itself.

---

## The Contract

- `app build` is daemonless and registry-direct. It needs registry credentials
  but no Docker daemon and no Nix installation.
- The artifact is a file or directory. File artifacts land at `--dest`; directory
  artifacts expand under `--dest`.
- Native binaries should pass `--executable` so the file lands with mode `0755`.
- `--entrypoint` and `--cmd` use OCI JSON exec form. Do not rely on a shell in
  `distroless`.
- `--base` can be a catalog id such as `java21-distroless` or a raw registry
  reference. A catalog id resolves to a digest-pinned ClearCutt base from the
  local catalog.
- `app diff-base` checks runtime-line compatibility and, when both bases are in
  the catalog, reports the offline CVE delta.
- `app rebase` verifies the developer signature over the exact source digest,
  swaps the base, signs the rebased result with the rebase workflow identity, and
  attaches a signed rebase attestation when `--sign --attest` are set.

Supported base families:

| Stack | Base ids |
| --- | --- |
| Java | `java25-dev`, `java25-slim`, `java25-distroless` |

That one line is the reference fixture the project publishes. The registry also
carries recipes for `java21`, `node22`, `node24`, `node26`, `python3.13`,
 Every
recipe is evaluated on each run, so one you have not enabled still cannot rot
without CI noticing.

Use `dev` for toolchains, `slim` when you need a diagnostic shell, and
`distroless` for the hardened production target.

early adoption. Production policies with `allowPreview: false` should use active
runtime lines until the catalog lifecycle for that line moves to active.

The sections below are live/generated-catalog examples. A clean clone only
proves the Java 21 fixture path; run `./clearcutt-verify --catalog
cli/internal/testdata/catalog inspect java21-distroless` before your fork has
published a full catalog.

---

## Common End-to-End Flow

These variables are used by the stack-specific examples below:

```bash
export APP_IMAGE="ghcr.io/acme/payments-api:1.0.0"
export REBASED_IMAGE="ghcr.io/acme/payments-api:1.0.0-rebased"
export DEV_SIGNER="https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main"
export ENGINE_SIGNER="https://github.com/acme/platform/.github/workflows/YOUR_REBASE_WORKFLOW.yml@refs/heads/main"
```

Each stack section builds a source image. After that, the signed rebase loop is
the same:

```bash
# 1. The developer release workflow signs the original application image.
cosign sign --yes "$APP_IMAGE"

# 2. Compare the patched base before changing the image.
clearcutt-verify app diff-base \
  --image "$APP_IMAGE" \
  --candidate-base "$PATCHED_BASE" \
  --candidate-base-id "$BASE_ID" \
  --fail-on-incompatible

# 3. Rebase from a dedicated CI workflow with id-token: write.
clearcutt-verify app rebase \
  --image "$APP_IMAGE" \
  --candidate-base "$PATCHED_BASE" \
  --candidate-base-id "$BASE_ID" \
  --tag "$REBASED_IMAGE" \
  --dev-identity "$DEV_SIGNER" \
  --sign \
  --attest

# 4. Verify the rebase-engine signature and signed predicate in deployment gates.
cosign verify "$REBASED_IMAGE" \
  --certificate-identity "$ENGINE_SIGNER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation "$REBASED_IMAGE" \
  --type https://clearcutt.dev/attestations/rebase/v1 \
  --certificate-identity "$ENGINE_SIGNER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

When `--candidate-base` is a catalog id, `--candidate-base-id` can be omitted.
When it is a raw registry reference, pass `--candidate-base-id` so the
compatibility gate can enforce the runtime family and major/minor line.

---

## Stack Examples

### Java 21

Use a fat JAR or another single executable JAR as the artifact.

```bash
./mvnw -DskipTests package
cp target/payments-api-*-all.jar target/app.jar

export BASE_ID="java21-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-java21:vX.Y.Z-distroless"

clearcutt-verify app build \
  --base "$BASE_ID" \
  --artifact target/app.jar \
  --dest /workspace/app.jar \
  --entrypoint '["java","-jar","/workspace/app.jar"]' \
  --image "$APP_IMAGE"
```

For Java 25, use `java25-distroless` and the matching
`clearcutt-java25:distroless-<tag>` patched base.

### Node.js 22

Bundle the service into one server file. This works best for API services that
can be bundled with esbuild, ncc, or Rollup.

```bash
npm ci
npx esbuild src/server.ts \
  --bundle \
  --platform=node \
  --target=node22 \
  --format=esm \
  --outfile=dist/server.mjs

export BASE_ID="node22-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-node22:vX.Y.Z-distroless"

clearcutt-verify app build \
  --base "$BASE_ID" \
  --artifact dist/server.mjs \
  --dest /workspace/server.mjs \
  --entrypoint '["node","/workspace/server.mjs"]' \
  --image "$APP_IMAGE"
```

If the application depends on native addons or runtime files that cannot be
bundled into one artifact, use a Containerfile and certify the finished image.

### Python 3.14

Package the application as a zipapp, PEX, or shiv artifact.
Python 3.14 is the latest production Python line in the catalog.

```bash
python -m pip install --upgrade build pex
pex . \
  -m payments_api.main \
  -o dist/payments-api.pyz

export BASE_ID="python3.14-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-python3.14:vX.Y.Z-distroless"

clearcutt-verify app build \
  --base "$BASE_ID" \
  --artifact dist/payments-api.pyz \
  --dest /workspace/payments-api.pyz \
  --entrypoint '["python","/workspace/payments-api.pyz"]' \
  --image "$APP_IMAGE"
```

### Go 1.26

Produce a Linux executable and mark it executable in the image layer.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/payments-api ./cmd/payments-api

export BASE_ID="go1.26-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-go1.26:vX.Y.Z-distroless"

clearcutt-verify app build \
  --base "$BASE_ID" \
  --artifact dist/payments-api \
  --dest /workspace/payments-api \
  --entrypoint '["/workspace/payments-api"]' \
  --executable \
  --image "$APP_IMAGE"
```

For Go 1.26, use `go1.26-distroless` and `clearcutt-go1.26`.

## Rebuild Predicate Verification

Platform owners can emit a rebuild predicate before attaching release evidence.
The verifier resolves the image ref, downloads or parses SLSA/in-toto
provenance, checks out the pinned source commit, runs `nix build`, pulls the
published registry archive, and compares ordered layer digests. If layers
differ, `--diffoscope-out` records the detailed local mismatch report.

```bash
clearcutt-verify verify rebuild \
  ghcr.io/acme/clearcutt/clearcutt-java21:vX.Y.Z-distroless \
  --target java21-distroless \
  --rebuild \
  --pull-registry-archive \
  --require-digest-match \
  --require-layer-match \
  --diffoscope-out rebuild.diff.txt \
  --output-predicate
```

---

## CI Rebase Workflow

Run rebases from a dedicated workflow identity. The developer workflow signs the
source image; the platform workflow verifies that signature, performs the base
swap, signs the result, and attaches the rebase predicate.

```yaml
name: Rebase application image

on:
  workflow_dispatch:
    inputs:
      image:
        required: true
        type: string
      tag:
        required: true
        type: string
      base_id:
        required: true
        type: string
      patched_base:
        required: true
        type: string

permissions:
  contents: read
  packages: write
  id-token: write

jobs:
  rebase:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v4
      - name: Build clearcutt
        run: go -C cli build -o ../clearcutt-verify ./cmd/clearcutt-verify
      - name: Check candidate base
        run: |
          ./clearcutt-verify app diff-base \
            --image "${{ inputs.image }}" \
            --candidate-base "${{ inputs.patched_base }}" \
            --candidate-base-id "${{ inputs.base_id }}" \
            --fail-on-incompatible
      - name: Rebase, sign, and attest
        run: |
          ./clearcutt-verify app rebase \
            --image "${{ inputs.image }}" \
            --candidate-base "${{ inputs.patched_base }}" \
            --candidate-base-id "${{ inputs.base_id }}" \
            --tag "${{ inputs.tag }}" \
            --dev-identity "$DEV_SIGNER" \
            --sign \
            --attest
        env:
          DEV_SIGNER: https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main
```

Admission policy should pin the rebase workflow identity and require the signed
predicate to carry `rebaseDecision: allowed`, `developerSignatureVerified: true`,
and the expected developer signer. See
[`examples/k8s-deployment/`](../examples/k8s-deployment/) for the Kyverno policy
shape.

---

## Multi-Architecture Notes

The examples above produce one Linux application image for the artifact you pass
to `app build`. For multi-architecture applications, build one artifact per
platform and publish an index using your release tooling. `app rebase` can rebase
multi-arch indexes when each child image carries the ClearCutt rebase labels and
uses a compatible platform-specific base.

# Downstream Application Certification

Application teams must certify their final compiled image payloads against the corporate platform security contract before scheduling deployments into production namespaces.

---

## 1. Declarative Certification Policies
Certification policies are specified in YAML files matching `schemas/certification-policy.schema.json`.

Example production policy:
```yaml
apiVersion: clearcutt.dev/v1
kind: CertificationPolicy
metadata:
  name: acme-production-policy
spec:
  base:
    allowedImages:
      - java21-distroless
      - node22-slim
    requireDigestPinned: true
    requireKnownBase: true
  supplyChain:
    requireSignature: true
    requireProvenance: true
    requireSbom: true
    minimumSlsaLevel: 3
  runtime:
    requireNonRoot: true
    forbidShell: true
    forbidPackageManagers: true
    forbidDevTier: true
```

---

## 1.5 What `certify` checks offline

`clearcutt-verify certify` operates on a local image tarball with no network access. It
accepts both legacy `docker save` archives and OCI-layout archives (`index.json` +
`blobs/`), and transparently reads gzip-compressed layers.

It **verifies offline**:
- non-root `Config.User`,
- required `org.opencontainers.image.*` / `org.clearcutt.*` labels,
- absence of shells and package managers in distroless tiers,
- declared-base allow-listing, digest pinning, and base-image CVE thresholds (against the catalog).

It **cannot verify offline** and reports these as `SKIP`, never `PASS`:
- Cosign signatures, SBOM attestations, and SLSA provenance. These live as OCI
  *referrers* in the registry, not inside the tarball, and `minimumSlsaLevel`
  likewise cannot be confirmed offline.

To enforce those, verify against the registry in the same pipeline step, e.g.:
```bash
cosign verify "$IMAGE" --certificate-identity-regexp '<your-workflow>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type slsaprovenance "$IMAGE" ...
```

A certification result of `PASS (N skipped)` means the offline contract held but
N attestation checks were deferred to registry-side verification.

---

## 2. CI/CD Pipeline Enforcement

### 2.1 GitHub Actions Integration
Use the generated app-template workflow pattern to verify the ClearCutt CLI
before running certification. Do not pin generated apps to old remote composite
action tags that predate the verified CLI install path.

```yaml
- name: Install verified ClearCutt CLI
  run: |
    set -euo pipefail
    VERSION="vX.Y.Z"
    REPO="northcutted/clearcutt-verify"
    ASSET="clearcutt-verify-linux-amd64"
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    SIGNING_IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/heads/main"
    curl -fsSL -o "${RUNNER_TEMP}/${ASSET}" "${BASE_URL}/${ASSET}"
    curl -fsSL -o "${RUNNER_TEMP}/${ASSET}.sig" "${BASE_URL}/${ASSET}.sig"
    curl -fsSL -o "${RUNNER_TEMP}/SHA256SUMS.txt" "${BASE_URL}/SHA256SUMS.txt"
    (cd "${RUNNER_TEMP}" && grep -E "  ${ASSET}$" SHA256SUMS.txt | sha256sum -c -)
    cosign verify-blob "${RUNNER_TEMP}/${ASSET}" \
      --bundle "${RUNNER_TEMP}/${ASSET}.sig" \
      --certificate-identity "${SIGNING_IDENTITY}" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
    install -m 0755 "${RUNNER_TEMP}/${ASSET}" "${RUNNER_TEMP}/clearcutt"
    echo "${RUNNER_TEMP}" >> "$GITHUB_PATH"

- name: Certify app image
  run: |
    clearcutt-verify certify app-image.tar \
      --policy policies/production.yaml \
      --base java25-distroless \
      --image-ref ghcr.io/acme/my-app@sha256:fedcba...
```

### 2.2 Rebasable Application Images

`clearcutt-verify app build` creates a registry-pushed application image from a prebuilt
artifact and a ClearCutt base. It stamps the OCI config with:
- the catalog base id and version,
- a digest-pinned base reference,
- the compressed digest of the final base layer,
- `dev.clearcutt.app.rebasable=true`.

Those labels define the base/application boundary used later by `clearcutt-verify app
rebase`. The rebase command refuses to continue if the recorded boundary does not
match the old base, and go-containerregistry re-checks the rootfs `diff_ids`
before rewriting config history for the new base.

Example:
```bash
clearcutt-verify app build \
  --base java21-distroless \
  --artifact target/app.jar \
  --dest /workspace/app.jar \
  --entrypoint '["java","-jar","/workspace/app.jar"]' \
  --image ghcr.io/acme/payments-api:1.0.0
```

For stack-specific `app build` examples covering Core/static, Java, Node.js,
Python, Go, .NET, Rust, and C/C++, see
[`docs/app-lifecycle.md`](app-lifecycle.md).

### 2.3 Compatible-Base Rebasing

`clearcutt-verify app rebase` is intentionally more privileged than the offline
governance commands: it reads and writes an OCI registry and can call `cosign`.
For production use, run it from a dedicated CI workflow with `id-token: write`.

The default trust model is dual-control at rebase time:
- the source image is verified against `--dev-identity` and `--dev-issuer`,
- the rebased image is signed by the rebase-engine workflow with `--sign`,
- the rebase predicate is attached with `--attest`,
- an `allowed` predicate cannot be emitted unless the developer signature check
  succeeded.

```bash
clearcutt-verify app rebase \
  --image ghcr.io/acme/payments-api:1.0.0 \
  --candidate-base ghcr.io/northcutted/clearcutt/clearcutt-java21:vX.Y.Z-distroless \
  --candidate-base-id java21-distroless \
  --tag ghcr.io/acme/payments-api:1.0.0-rebased \
  --dev-identity 'https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main' \
  --sign \
  --attest
```

### 2.4 GitLab CI Integration
For GitLab CI pipelines, execute the certification audit inside a secure runner stage by downloading the compiled release binary:
```yaml
certify:
  stage: test
  image: alpine:latest
  # Pin a released CLI version — never track a moving tag in a supply-chain gate.
  # Bump this as you adopt new releases.
  variables:
    CLEARCUTT_VERSION: "vX.Y.Z"
  before_script:
    - apk add --no-cache curl cosign coreutils
    - export ASSET=clearcutt-verify-linux-amd64
    - export BASE_URL="https://github.com/northcutted/clearcutt-verify/releases/download/${CLEARCUTT_VERSION}"
    - curl -fsSL -o "/tmp/${ASSET}" "${BASE_URL}/${ASSET}"
    - curl -fsSL -o "/tmp/${ASSET}.sig" "${BASE_URL}/${ASSET}.sig"
    - curl -fsSL -o /tmp/SHA256SUMS.txt "${BASE_URL}/SHA256SUMS.txt"
    - cd /tmp && grep -E "  ${ASSET}$" SHA256SUMS.txt | sha256sum -c -
    - cosign verify-blob "/tmp/${ASSET}" --bundle "/tmp/${ASSET}.sig" --certificate-identity-regexp "^https://github\.com/northcutted/clearcutt(-verify)?/\.github/workflows/release\.yml@refs/heads/main$" --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
    - install -m 0755 "/tmp/${ASSET}" /usr/local/bin/clearcutt-verify
  script:
    - clearcutt-verify certify app-image.tar --policy policy.yaml --base java25-distroless --image-ref "$APP_IMAGE@$APP_DIGEST"
  artifacts:
    paths:
      - certification-report.json
```

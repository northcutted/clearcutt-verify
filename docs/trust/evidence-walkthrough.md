# Trust Evidence Walkthrough

This walkthrough traces one release from source to image to evidence to policy.
Use the fixture commands for a clean clone, then replace placeholders with a
published image from your fork when you want registry-side proof.

## 1. Catalog Gate From A Clean Clone

```bash
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --max-critical 0 \
  --max-high 3 \
  --allow-preview
```

This checks catalog-record fields. It does not query the registry or prove the
signature cryptographically.

## 2. Pick A Published OCI Ref

For a fork, use a release tag and digest from the generated catalog:

```bash
IMAGE_REF="ghcr.io/YOUR_ORG/YOUR_REPO/YOUR_IMAGE:TAG"
IMAGE_DIGEST="sha256:REPLACE_WITH_PUBLISHED_DIGEST"
IMMUTABLE_REF="${IMAGE_REF%:*}@${IMAGE_DIGEST}"
WORKFLOW_IDENTITY="https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main"
SOURCE_REF="refs/heads/main"
```

The workflow identity is a trust boundary. It must match the identity pinned in
`clearcutt.yaml`, admission policy, and verifier commands.

## 3. Verify Registry-Side Release Evidence

```bash
./clearcutt-verify verify release-evidence \
  --ref "$IMAGE_REF" \
  --digest "$IMAGE_DIGEST" \
  --repo YOUR_ORG/YOUR_REPO \
  --workflow-identity "$WORKFLOW_IDENTITY" \
  --source-ref "$SOURCE_REF" \
  --core-dir core
```

This is the ClearCutt wrapper around registry-side signature, SBOM, and SLSA
checks for a published ref. In a scaffolded fleet repo, `--core-dir core` runs
Cosign, SLSA verifier, and GitHub attestation verification through the pinned
Nix backend.

Release workflows also write the same checklist as
`<image-id>.release-verification.json` and upload it as a GitHub Release asset.
Use that file as durable proof of the registry-side verification result that ran
at release time; rerun the command above when you need to re-check current
registry state.

## 4. Verify Individual Channels Manually

Cosign signature:

```bash
cosign verify "$IMMUTABLE_REF" \
  --certificate-identity "$WORKFLOW_IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

SPDX SBOM attestation:

```bash
cosign verify-attestation "$IMMUTABLE_REF" \
  --type spdxjson \
  --certificate-identity "$WORKFLOW_IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

SLSA provenance:

```bash
slsa-verifier verify-image "$IMMUTABLE_REF" \
  --source-uri "github.com/YOUR_ORG/YOUR_REPO" \
  --source-branch main
```

GitHub-native provenance attestation:

```bash
gh attestation verify "oci://$IMMUTABLE_REF" \
  --repo YOUR_ORG/YOUR_REPO \
  --cert-identity "$WORKFLOW_IDENTITY" \
  --source-ref "$SOURCE_REF"
```

The GitHub CLI command verifies the GitHub-native provenance attestation by
default. Use Cosign attestation commands for SBOM predicate verification.

## 5. Compare The Catalog Record

```bash
./clearcutt-verify --catalog dist/catalog catalog inspect java21-distroless
```

Check that the record reports the same tag, digest, workflow identity, signature
state, SBOM state, provenance state, scan state, tests, lifecycle, and raw
evidence URLs you verified above.

## 6. Connect To Policy

```bash
./clearcutt-verify policy java21-distroless \
  --catalog dist/catalog \
  --engine kyverno \
  --environment production \
  --namespace apps
```

Admission policy should pin the exact release workflow identity and, for app
rebases, a separate rebase workflow identity. Broad identity regexes reduce the
value of the trust gate.

## What This Does Not Prove

- It does not prove a fork operates releases correctly unless the fork has run
  the workflow and published evidence.
- It does not make catalog badges live cryptographic checks.
- It does not replace vulnerability triage, exception review, or runtime
  controls.

# Kubernetes Admission Control Policy Examples

ClearCutt emits admission-policy examples from catalog records. Treat the
generated YAML as a starting point that must be validated with the admission
controller version and registry trust model your cluster actually runs.

---

## 1. Canonical Kyverno Policy Generation
Kyverno policies are generated dynamically using `clearcutt-verify policy`. They can
express digest mutation/verification and keyless signature/provenance checks for
the selected catalog image pattern:
```bash
clearcutt-verify --catalog cli/internal/testdata/catalog policy java21-distroless \
  --engine kyverno \
  --environment production \
  --namespace apps
```

> The admission engine is selected with `--engine kyverno|gatekeeper`. The global
> `--format` flag is reserved for `table|json|yaml` output across the CLI.

### Current Kyverno Output
- **Cosign signature check**: requires a keyless signature from the cataloged
  GitHub OIDC workflow identity when `requireSignature` is active.
- **Digest mutation/verification parameters**: sets Kyverno `mutateDigest` and
  `verifyDigest` when digest policy is active; validate this behavior against
  your installed Kyverno version before treating it as a production control.
- **SLSA provenance attestation check**: requires an SLSA provenance attestation
  from the same OIDC workflow identity when provenance policy is active.

The generated production Kyverno path is the canonical admission example in this
repository today. SBOM presence is still checked by catalog gates and
registry-side release-evidence verification, but the generated admission policy
does not currently emit an SPDX SBOM predicate gate.

### Environment Profiles (`--environment`)
- **development**: requires signatures only.
- **production**: turns on digest, signature, provenance, and dev-tier policy
  knobs. Preview enforcement is release-record-derived, not a live catalog
  lifecycle lookup.
- **strict**: everything `production` turns on, plus a mandatory
  `runAsNonRoot` workload guarantee.

---

## 2. OPA Gatekeeper Integration
For OPA Gatekeeper environments, generate ConstraintTemplate and Constraint
scaffolds:
```bash
clearcutt-verify --catalog cli/internal/testdata/catalog policy java21-distroless \
  --engine gatekeeper \
  --namespace apps
```
This emits a `ConstraintTemplate` named `K8sCosignSignatureVerify` plus
parameters that describe the expected signature, provenance, digest, tier, and
preview policy. Treat the current Gatekeeper output as a scaffold for teams that
already run verifying admission integrations; Kyverno is the stronger generated
path in this repository today.

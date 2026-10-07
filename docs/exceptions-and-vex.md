# Vulnerability Exceptions & OpenVEX Compliance

> **Two different mechanisms, two different claims.** `exceptions.yaml` is the
> consumer-side waiver against `verify image` thresholds for *your application
> image*. `core/vulnerability-acceptances.yaml` is the platform-side, expiring
> acceptance the *build gate* consults when a base image ships a real finding
> with no reachable fix. Neither is a VEX `not_affected` claim, which asserts the
> vulnerability does not apply at all — see [security-model.md](security-model.md).


This document explains how the ClearCutt platform manages vulnerability exceptions and dynamically exports standard-compliant OpenVEX documents.

---

## 1. Exception Governance Policy
In enterprise environments, blocking builds on every detected CVE is operationally impractical. Vulnerabilities require governance, not just blockers. 

ClearCutt implements an explicit, schema-validated exception model:
- All exceptions are declared inside an `exceptions.yaml` file conforming to `schemas/exceptions.schema.json`.
- Initialize a boilerplate exceptions configuration template file using the CLI:
  ```bash
  clearcutt-verify exceptions init [output-file]
  ```
- Every exception **must** specify:
  - The target `CVE` ID and package name.
  - An unexpired expiration date (`expiresAt` formatted as `YYYY-MM-DD`).
  - An owner and detailed remediation reasoning (`reason`).
  - Cryptographic references if status is `accepted_risk`.

`exceptions.yaml` is the **consumer-side** control: a scoped, expiring waiver against `verify image` thresholds for your own application image. It is now the only exception mechanism ClearCutt ships. The platform-side CVE route decisions that used to sit alongside it — overlay and ignore evidence under `core/overlays/cve/`, produced by `clearcutt-verify remediation triage` — were removed with the remediation subsystem ([decision 6](decisions.md)).

---

## 2. Dynamic OpenVEX Generation
The `clearcutt-verify vex` command queries exceptions and dynamically outputs OpenVEX (`https://openvex.dev/ns/v0.2.0`) documents:
- Only **active** exceptions are honored; expired ones are ignored so the document never carries a stale `not_affected` claim.
- Maps exceptions onto **valid** OpenVEX statements:
  - `status` is always one of the four spec values: `not_affected`, `affected`, `fixed`, `under_investigation`.
  - `accepted_risk` remains `affected` in OpenVEX output. It is a governance waiver, not proof that the product is unaffected.
  - `false_positive` and explicit `not_affected` exceptions can emit `not_affected` only when backed by a reason such as vulnerable code not present or not in the execute path.
  - `justification` is emitted **only** when `status` is `not_affected` (as the spec requires). Reasons map as: `vulnerable_code_not_present`/`scanner_false_positive` -> `vulnerable_code_not_present`; `vulnerable_code_not_executed`/`inherited_from_base` -> `vulnerable_code_not_in_execute_path`. A `not_affected` exception with any other reason remains `under_investigation`.

---

## 3. Enforcement in CI Verification
When executing policy gating:
```bash
clearcutt-verify --catalog cli/internal/testdata/catalog verify image java21-distroless \
  --max-critical 0 --max-high 3 \
  --exceptions exceptions.yaml \
  --allow-preview
```
Supplying `--exceptions` is enough to honour active exceptions — the older `--allow-exceptions` flag is now implied and optional. This deducts all active (non-expired) exempted CVEs from the severity thresholds. An expired exception is **never** applied; with `--fail-on-expired-exceptions` (the default) a matched-but-expired exception additionally raises a dedicated `exceptions.expired` failure, so stale waivers actively break the build rather than silently lapsing. Pass `--fail-on-expired-exceptions=false` to downgrade that to a silent skip.

> Note: exceptions are only evaluated when a threshold is set (`--max-critical` / `--max-high`).

# Architectural Constraints & Security Decisions

Every agent MUST respect and preserve the following design decisions, constraints, and security models when modifying the codebase.

---

## 1. Nix hermetic overlay isolation

* **RPATH / RUNPATH Isolation:** Distroless run-times compiled by the Nix image factory must resolve dynamic libraries from Nix store subpaths and must not ship `/lib` or `/lib64` fallback shims. Slim, dev, and service tiers may retain documented FHS compatibility shims for downstream binaries; do not describe those tiers as the strict dynamic-linkage boundary.
* **Mac OS Cross-Compilation Constraint:** You can run development shells on macOS, but **cross-compiling runtimes (like Java JDK, Node, .NET) from macOS to Linux target layers via Nix `pkgsCross` is unstable and unsupported**. Production matrix builds MUST be built on native Linux (e.g., standard Linux VM or CI runner).

---

## 2. Matrix Lifecycle Hardening

* **`distroless` Tier:** This is a zero-utility tier containing **exactly zero interactive shells or coreutils** (No `/bin/sh`, `/bin/bash`, `ls`, or `cat`).
* **Privilege Restriction:** Containers are configured to drop all Linux kernel capabilities (`cap_drop: - ALL`) and run under the unprivileged rootless boundary **`user: "10001:10001"`**.
* **OpenShift Arbitrary UID Support:** To comply with OpenShift SCC (which assigns random random high-range dynamic UIDs at runtime and mounts them inside group ID `0`), container manifests should omit hardcoded UIDs and run with `runAsNonRoot: true` alongside `runAsGroup: 0`.

---

## 3. Supply Chain Security Gating

* **Signature and Attestation:** `clearcutt-verify verify` and `clearcutt-verify app rebase` require cryptographic verification via Cosign and OIDC keyless signing.
* **Wildcard Prohibition:** **Never use wildcards in verification constraints**. In particular, `mirror verify` and `verify` command flows must never use `--certificate-identity-regexp '.*'` or equivalent wildcards. You must always require a pinned, verifiable developer or workflow signer identity.
* **Rebase Attestation Schema:** The rebase attestation schema (`schemas/rebase-attestation.schema.json`) enforces that a rebase attestation requires a validated developer signature, source image digest, compressed app-layer digests, and a record of the added/removed layers.

---

## 4. Exception & Policy Validation

* **Exceptions Schema:** All declarative exception triage files must conform exactly to `schemas/exceptions.schema.json`.
* **Kind Constraint:** The resource type MUST be defined exactly as **`kind: VulnerabilityExceptions`**. Defining it as `kind: Exceptions` or `VulnerabilityException` will fail schema validation and trigger gating failures.
* **Certification Policy Schema:** Dynamic policies must conform exactly to `schemas/certification-policy.schema.json` and declare `kind: CertificationPolicy`.

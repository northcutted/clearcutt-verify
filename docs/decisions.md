# ClearCutt Architecture Decisions (ADR)

This document traces the design logic and rationale behind the key security constraints and architectural choices implemented across the ClearCutt ecosystem.

---

## 1. Rootless Context & Hardcoded UID/GID `10001`

* **Decision**: All container images in the slim and distroless tiers are statically configured to run as unprivileged user `10001` and group `10001` (`appuser`).
* **Rationale**: Running as `root` (UID 0) inside container namespaces increases the blast radius of container escape vulnerabilities (such as CVE-2024-21626). Using the unprivileged UID `10001` means a successful application exploit starts from a lower-privilege user context.
* **Enterprise Alignment**: The `10001` UID aligns with Kubernetes Pod Security Standards (`restricted` profile). OpenShift deployments use a separate arbitrary-UID pattern documented in `examples/openshift-deployment/`.

---

## 2. Cryptographic Digest-Pinning (`@sha256`)

* **Decision**: Digest-pinning is the required **production** posture: production deployments and certified app images must pin OCI image references using their immutable SHA-256 digest rather than standard mutable version tags. Scaffolded app templates and documentation examples deliberately start on mutable tags (`:dev`, `:distroless`) to keep the inner development loop fast, and must carry an explicit "pin your base before production" step.
* **Rationale**: In standard container registries, tags (like `:latest` or `:1.0.0`) are mutable. An attacker who gains write access to a registry can overwrite the tag with a compromised layer graph without altering downstream deployment configurations. Digest-pinning makes the intended image content explicit.
* **Reproducibility**: Pinned digests ensure that every deployment, whether local, CI, or production, resolves to the same image archive and closes the common tag-drift path.
* **Where the gate lives**: `clearcutt-verify certify` rejects app images that are not digest-pinned (`--image-ref ...@sha256:...`), and the generated certification policies require digest-pinned refs. Catalog records carry `latestManifestDigest`; `clearcutt-verify inspect <id>` prints the digest-pinned reference to copy into a production `FROM` line. Digest-resolving scaffolds (generating templates with the digest already substituted) are a deferred follow-up.

---

## 3. Selecting Java (JVM) as the Premier Template Runtime

* **Decision**: Java (specifically Java 21 LTS) was selected as the first comprehensive end-to-end template implementation.
* **Rationale**: The JVM ecosystem represents the largest enterprise application footprint and has historically been the target of catastrophic classloader injection vulnerabilities (like Log4Shell). Hardening Java applications presents the highest immediate business value.
* **Hermetic class paths**: By wrapping the Java runtime in a Nix store closure on top of the distroless tier, classpath and dynamic-linker resolution stay inside the declared runtime closure unless the downstream application explicitly adds more files.

---

## 4. Total Elimination of Shells and Utilities in Distroless

* **Decision**: The `distroless` tier strips out every interactive shell (`/bin/sh`, `/bin/bash`, `/bin/ash`, `/bin/zsh`) and core utility binary (`ls`, `cat`) in both `/bin` and `/usr/bin`.
* **Rationale**: Many post-exploitation paths rely on spawning a local shell binary (such as executing `exec("/bin/sh")` or using shell pipe redirects) to download malware, crawl networks, or extract credentials. Removing shell binaries blocks that class of behavior.
* **Attack Surface Reduction**: Stripping core utilities removes the developer's "convenience tools" (like `cat` or `ls`). That reduces built-in discovery and scripting options after compromise, while the security model still treats other RCE paths as in scope.

---

## 5. Tracking `nixpkgs-unstable` For Runtime Inputs

* **Decision**: ClearCutt pins `nixpkgs-unstable` in `core/flake.nix` rather than a stable NixOS channel.
* **Rationale**: The image fleet is vulnerability-gated at build/release time and needs fast access to fixed upstream packages. The unstable channel usually carries language-runtime patch releases sooner than stable channels, which reduces the need for custom backports in `core/overlays/cve/`.
* **Consequence**: Some runtimes can surface preview or beta upstream versions when nixpkgs exposes them — for example, a future Python beta during its pre-GA lifecycle. Any such preview runtime must remain policy-bounded in the catalog and should not be promoted as a production default until upstream lifecycle status and package stability are acceptable for the consuming platform.
* **Control**: The pinned `flake.lock`, release evidence, SBOM, vulnerability gate, and catalog lifecycle metadata are the review points for each released digest. Moving to a stable channel remains a valid downstream fork decision when slower package movement is preferable to preview-runtime availability.

---

## 6. Priced CVE Triage Routes with Self-Retiring Decisions (SUPERSEDED)

* **Status**: Removed. `clearcutt-verify remediation triage` priced six CVE routes
  (`version_bump`, `substitute_vex`, `unstable_optin`, `fetchpatch_rebuild`,
  `scanner_ignore`, `wait`), each with a cost-now / risk-carried / retirement
  triple, and recorded self-retiring decision records with a `decidedBy`
  attribution seam. It was deleted with the rest of the remediation subsystem.
* **Why it went**: every route it priced was a way to patch a Nix image
  ClearCutt builds, and the probe that made pricing possible swept nixpkgs refs.
  With the fleet reduced to four reference fixtures, there was nothing for it to
  decide about, and none of it transferred to governing an estate ClearCutt did
  not build.
* **What is worth rebuilding**: the *idea* — an honest, expiring ledger of
  findings nobody can fix yet, with an attribution field that distinguishes a
  human decision from a policy default from an agent's call. That belongs on top
  of `graph` and `import assess`, where it would be registry-agnostic. Nothing
  in the current tree implements it.

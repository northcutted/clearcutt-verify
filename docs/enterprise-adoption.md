# ClearCutt Enterprise Adoption Roadmap

ClearCutt adoption should read like a platform rollout, not a base-image swap.
Stand up the fleet once, then move application teams through a repeatable
delivery loop: adopt, certify, admit, and update.

For build-vs-buy positioning and when not to use ClearCutt, see
[`alternatives.md`](alternatives.md).

## 1. Own And Publish The Fleet

Start with a platform fork that runs under your GitHub organization, registry,
workflow identities, and catalog site.

- Configure `clearcutt.yaml` for the runtimes, tiers, architectures, scan
  windows, and remediation limits you intend to support.
- Treat the catalog as the product surface: signatures, SBOMs, provenance, test
  results, and vulnerability scans should each show their own status.

## 2. Give App Teams A Low-Friction Path

Adoption should start where developers already work: local builds, devcontainers,
and CI.

- Use `clearcutt-verify list` and `clearcutt-verify inspect` to choose a runtime line and tier.
- Keep Nix out of the app-team path unless the team is intentionally customizing
  the platform fleet.

## 3. Bridge Mandated Base Images When Needed

If your organization mandates Red Hat UBI, Ubuntu Pro, Amazon Linux, or another
approved base, use overlays as a migration bridge rather than pretending they
are equivalent to ClearCutt from-scratch distroless images.

- Use `clearcutt.lib.graftOntoBase` from `core/flake.nix` to graft the
  reproducible `/nix` runtime closure onto the mandated base. (The
  `clearcutt-verify overlay generate` CLI wrapper was removed; the Nix helper remains.)
- Preserve required agents and OS policy while standardizing language runtimes.
- Be explicit about the trade-off: overlays inherit the parent image's shell,
  package manager, and CVE footprint.

## 4. Gate Delivery Before Production

Make certification and verification normal CI steps before enforcing cluster
admission.

- Run `clearcutt-verify certify` against downstream application images to catch shells,
  package managers, root users, and policy violations before release.
- Run `clearcutt-verify verify image` for catalog evidence and vulnerability thresholds.
- Use `clearcutt-verify conformance run` inside containers when you need runtime
  environment checks such as CA trust, timezone data, UID, and writable `/tmp`.

## 5. Admit And Operate Under Review

Admission and remediation should be explicit control points.

- Generate Kyverno or OPA bundles with `clearcutt-verify policy` and pin expected OIDC
  workflow identities.
- Use `clearcutt-verify scan`, `remediation`, `exceptions`, and `vex` to triage current
  risk instead of reducing the story to raw CVE counts.
- For compatible rebasable apps, use `clearcutt-verify app diff-base` and
  `clearcutt-verify app rebase --sign --attest` from a dedicated CI workflow. The
  rebase path preserves app layers, verifies the developer signature, and emits a
  separate rebase attestation; it should not silently merge or deploy changes.

# ClearCutt Claims Register

This register keeps public claims conservative and verifiable. Use it when
reviewing README, docs, site copy, examples, and generated catalog language.

## Safe Core Claims

| Claim family | Preferred wording | Evidence or boundary |
| :--- | :--- | :--- |
| Product identity | ClearCutt is a CLI for bootstrapping user-owned GitHub container image control planes. | The adopter runs the generated repository under their registry, workflows, catalog, and admission policies. |
| Fleet ownership | Platform teams own and publish their base-image fleet as code. | `clearcutt.yaml`, `matrix add`, `runtime scaffold`, release workflows, catalog build. |
| Evidence publishing | Signatures, SBOMs, provenance, tests, scans, and catalog status are reported independently. | Catalog data and site telemetry must show missing channels instead of collapsing them into one trust badge. |
| App onboarding | App teams can use published images, devcontainers, templates, and CLI gates without learning Nix. | Nix stays on the platform-authoring path unless an app team intentionally customizes the fleet. |
| Governance gates | CI and admission can block images that miss evidence, runtime, lifecycle, or vulnerability policy. | `clearcutt-verify certify`, `verify`, `conformance`, `policy`, and generated Kyverno/OPA bundles. |
| Remediation | Scans and remediation tooling support reviewed, bounded updates. | Do not imply silent merge, deployment, or production mutation. |
| Rebase | Compatible rebasable apps can move unchanged app layers onto patched bases under dual-control. | Requires ClearCutt labels, runtime compatibility, developer signature verification, and rebase-engine signing/attestation. |
| BYO base overlays | Overlays are an adoption bridge for mandated bases. | They inherit the parent base shell, package manager, and CVE footprint; they are not equivalent to from-scratch distroless images. |

## Claims Requiring Caveats

- **Hermetic or reproducible:** scope to Nix store closures and current build
  inputs. Do not imply every downstream overlay remains bit-for-bit identical to
  the from-scratch image.
- **Distroless or zero-utility:** safe for the distroless tier when backed by
  conformance/certification checks. Do not apply it to BYO base overlays.
- **SLSA Build L3:** safe when referring to the SLSA provenance channel. Do not
  call the whole product "SLSA certified."
- **FIPS/STIG:** safe only as structural or customization language unless formal
  validation artifacts are added.
- **No rebuild:** use "without rebuilding the app artifact" or "rebase
  compatible app layers"; avoid broad "zero-rebuild" claims.

## Avoid

- "Zero risk", "guaranteed secure", "completely mitigates supply-chain attacks".
- "Autonomous remediation" unless a reviewed, scheduled, closed-loop process
  actually merges and deploys safely.
- "Managed service", "hosted control plane", or "vendor feed" framing.
- "Every app can be rebased" or "all CVEs are patched automatically".

## Current Verification Hooks

- CLI command tree and grouped help: `cd cli && go test ./...`.
- Site copy and generated pages: `cd site && npm run typecheck && npm run build`.
- Catalog trust-data consistency: `./clearcutt-verify --catalog site/src/data/catalog verify catalog`.
- Claim hygiene scans: search for `zero risk`, `autonomous`, `certified`,
  `FIPS`, `STIG`, and broad `guarantee` language before publishing.

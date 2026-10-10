# ClearCutt Alternatives And Fit

ClearCutt governs container image estates. It is a poor fit when what you
actually want is a hardened image feed — that is a different product, and
several vendors do it well.

## Read This First

If your problem is *"our base images have too many CVEs"*, you do not need
ClearCutt. Pick a hardened image provider:

| Provider | Note |
| --- | --- |
| [Docker Hardened Images](https://www.docker.com/products/hardened-images/) | Free and Apache-2.0 since December 2025; paid Enterprise tier for customization, compliance variants, and SLA. |
| [Chainguard Containers](https://images.chainguard.dev/) | 2,000+ images rebuilt from source, low-to-zero known CVEs. |
| Minimus, RapidFort, Echo | Same lane, differing catalogs and pricing. |
| [gcr.io/distroless](https://github.com/GoogleContainerTools/distroless) | Free, narrow, upstream-maintained. |
| Red Hat UBI Micro, Canonical Chiselled Ubuntu, BellSoft Alpaquita | Distro-vendor minimal bases with support contracts. |

If your problem is *"I do not know what is in my registry, what it is built on,
or what I can prove about it"* — that is the gap ClearCutt fills, and the
providers above do not.

## Manager Readout

Choose ClearCutt when the business value is **knowing and proving**: which
images exist, what each is built on, how far it has drifted from its base, what
content the estate shares, what evidence each image carries, and which of those
claims are proven versus self-reported.

Choose a managed feed such as Chainguard or Docker Hardened Images when the
business value is **outsourcing** patch cadence and buying vendor
accountability. These are complementary, not competing: ClearCutt is happy to
govern an estate built entirely from someone else's hardened images, and that is
arguably its best use.

Choose plain `pkgs.dockerTools`, apko, or Docker multi-stage when you want
build mechanics without a governance layer on top.

## What ClearCutt Verify Is Not

- **Not an image feed.** It publishes no images. Governance features are
  demonstrated against real public images (see `examples/public-estate/`) and
  the clearcutt-factory example fleet: the product has to work on images it did
  not build.
- **Not a builder or patcher.** It reports and gates. It will tell you an image
  is on a stale base or missing a signature; it will not rebuild or re-tag it.
  [clearcutt-factory](https://github.com/northcutted/clearcutt-factory) builds
  and rebases, and `estate dependents` tells it which images a new base affects.
- **Not a scanner.** It reads the vulnerability attestations images carry and
  gates on policy; it does not maintain a vulnerability database.
- **Not hosted.** There is no service, no account, and no telemetry.

## What The Repo Proves Today

The offline demo maps four images from committed observations, with no
registry access:

```bash
./scripts/demo-imported-fleet-offline.sh
```

`contract/fixtures/northcutted-images/` is a real estate report: the
clearcutt-factory example fleet verified signature, SBOM, vulnerability scan,
provenance, and recipe against its signer, rebuilt bit for bit, with every base
proven by layer digest, next to Chainguard and Docker Hub bases that carry less.

## Comparison Matrix

| Axis | ClearCutt | Hardened image feed (Chainguard, DHI, Minimus) | gcr.io/distroless | Plain `pkgs.dockerTools` |
|---|---|---|---|---|
| Primary value | Know what your estate contains, what it is built on, and what you can prove. | Someone else keeps your base images current. | Free minimal upstream bases. | Precise closure control over images you build. |
| Works on images you did not build | Yes — this is the main path. | N/A (they are the builder). | N/A | No. |
| Base-relationship discovery | Layer-digest proof, plus OCI/buildpacks labels as declared claims. | Not offered. | Not offered. | Not offered. |
| Drift detection | Versions and days behind, per consumer, per base family. | Vendor tells you a newer tag exists. | Watch the upstream repo. | Your own tooling. |
| Evidence handling | Reports what exists, preserves what is missing, never infers provenance. | Vendor-signed evidence for vendor images. | Whatever your pipeline adds. | Whatever you build. |
| Patch cadence | None — not its job. | The core of the offering, often SLA-backed. | Upstream's cadence. | Yours. |
| Operational burden | Low: read-only registry access plus a scheduled job. | Lowest, for money. | Low. | High. |
| Best fit | Platform and security teams that must answer for an estate. | Teams that want fewer CVEs and will pay to stop thinking about it. | Teams wanting quick minimal bases. | Nix-first teams. |

## Static Measurement Axes

Use these axes when comparing base-image strategies.

| Measurement | ClearCutt command or source | Why it matters |
|---|---|---|
| Compressed image size | The estate report's per-platform sizes, or registry manifest layer sums. | Shows network and startup cost. |
| Package count | The estate report's package counts, from SBOM attestations. | Provides a rough review-surface signal. |
| Critical/high CVEs | The estate report's vulnerability summary, from scan attestations. | Helps compare risk posture, but must include scanner version and scan time. |
| SBOM source | Where the estate report says each SBOM came from. | Separates scanned evidence from build-graph-derived evidence. |
| Signature identity | `verify release-evidence` expected OIDC subject and issuer. | Proves which workflow identity signed a release. |
| Provenance builder | SLSA/GitHub attestation payloads. | Connects source, builder, and subject digest. |
| Base drift | `graph build` `versionsBehind` / `daysBehind` per consumer. | Shows whether adoption actually keeps up with the base. |
| Shared exposure | `graph layers` blast radius and fleet core. | Shows how far one bad layer reaches. |
| Storage cost of the estate | `graph layers` stored-once versus unshared bytes. | Quantifies what layer reuse is buying. |

## When To Use ClearCutt

- You have images in a registry and no reliable inventory of what is built on what.
- You need to show an auditor which images carry which evidence, and which
  claims are proven rather than asserted.
- You need to know the blast radius of a vulnerable layer across the estate.
- You need to catch consumers drifting off a base that has moved on.
- You want a paved path that works whether the images came from a vendor feed,
  a Dockerfile, buildpacks, or your own Nix build.

## When Not To Use ClearCutt

- You want hardened base images maintained for you. Use one of the providers above.
- You want something to automatically patch and republish your images.
- You need FIPS/STIG certification out of the box.
- You want a hosted product with centralized policy management and support.
- Your estate is small enough that you already know all of it by heart.

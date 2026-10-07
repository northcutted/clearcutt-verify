# ClearCutt Verify

**Point it at a registry. Find out which images are built on what, how stale
they are, and what you can actually prove about them.**

[![Live Catalog Site](https://img.shields.io/badge/Live%20Catalog-Site-blueviolet.svg?logo=astro&logoColor=white)](https://northcutted.github.io/clearcutt-verify)
[![ClearCutt PR Gating](https://github.com/northcutted/clearcutt-verify/actions/workflows/pr-gate.yml/badge.svg)](https://github.com/northcutted/clearcutt-verify/actions/workflows/pr-gate.yml)
[![Cosign Signed](https://img.shields.io/badge/Sigstore-Cosign%20Signed-orange.svg)](https://sigstore.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

ClearCutt Verify (`clearcutt-verify`) is a free, open-source CLI for governing
and verifying container image estates — including estates it did not build. It enumerates a registry, works out which
images are layered on which, measures how far each consumer has drifted from its
base, reports what the estate has in common, and produces an auditable inventory
that is honest about what it cannot prove.

There is no hosted control plane and no image feed to subscribe to. ClearCutt
Verify reads registries you already have and writes files you own.

It is part of ClearCutt, a family of open-source OCI tools:
[clearcutt-factory](https://github.com/northcutted/clearcutt-factory) builds
reproducible, signed images from YAML; clearcutt-verify checks an estate,
including factory-built fleets, and writes the estate report;
clearcutt-portal (in progress) publishes
it as a website.

![Terminal demo walking through four stages — observing eight public images live from a list of refs, proving five of five base relationships by layer digest, answering UNKNOWN rather than zero when Debian records no package list, and answering the same question for free where the builder does record one](docs/images/demo.gif)

The demo below is live, not staged, and it is meant to stand on its own — each
stage names the problem, says what you would have to do without ClearCutt, then
shows the command. It starts from eight public image references (debian, node,
python, ruby, postgres, nginx), observes them in about two seconds without
pulling a single layer, proves one debian layer sits under six of the eight,
names the two it cannot place and why, and then **fails honestly**: asked which
images ship openssl, it answers UNKNOWN rather than zero, because Debian records
no package list — and prices the fetch that would resolve it. The last stage
shows the same question answered for free where the builder does record one.

## What It Does

| | Command | Question it answers |
| --- | --- | --- |
| **Discover** | `registry scan` | What is actually published under this namespace? |
| **Map** | `graph build` | Which images are built on which, and how stale is each one? |
| **Compare** | `graph layers` | What does the fleet have in common, and what would a fix reach? |
| **Assess** | `import observe` → `import assess` | What evidence exists per image, and what is missing? |
| **Verify** | `estate verify` | Is every image signed, attested, and current, by whom, and can it be rebuilt? Writes the estate report clearcutt-portal reads. |
| **Gate** | `verify`, `certify`, `policy` | Does this image meet policy, at CI and at admission? |
| **Publish** | `catalog build`, `catalog site build` | A static evidence portal anyone can read. |

None of that requires ClearCutt to have built the image, or requires anyone to
adopt Nix, buildpacks, or a particular Dockerfile.

### It says what it cannot prove

The distinguishing behaviour is refusal to overclaim. A base relationship found
by comparing layer digests is reported as **proof**; one read from an
`org.opencontainers.image.base.digest` label is reported as a **claim its author
made**, and a self-reported label never outranks layer evidence. Imported images
never gain provenance they did not come with. Images whose base cannot be
determined are listed as findings, with the reason.

## ClearCutt Builds No Images

ClearCutt governs estates; it does not produce them. There is no image feed to
subscribe to, no base images to adopt, and nothing to migrate onto.

That is deliberate. Hardened base images are a solved and competitive market —
Docker Hardened Images went free and Apache-2.0 in December 2025, and Chainguard
publishes thousands. What none of them tells you is what is actually in *your*
registry, what it is built on, and what you can prove about it. That is the layer
ClearCutt works at. If you want a hardened image feed, use one of the
[alternatives](docs/alternatives.md).

Because ClearCutt builds nothing, it works the same on images from anywhere:
Debian- or Alpine-based, Wolfi, Nix, buildpacks, or something you assembled
yourself. It reports how each was built and picks the analysis that fits.

## First Proof From A Clean Clone

These commands use the committed catalog fixture, so they work before you
generate or publish your own catalog data:

```bash
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog list
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog inspect java21-distroless
go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog catalog validate

go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --max-critical 0 \
  --max-high 3 \
  --allow-preview
```

`verify image` is a catalog policy gate. It checks catalog-record evidence flags,
smoke tests, lifecycle status, and vulnerability thresholds. Use
`verify release-evidence`, Cosign, GitHub attestations, and SLSA verification
when you need registry-side cryptographic proof for a published OCI ref.

## Point It At A Registry

The clean-clone commands above read a committed fixture. This reads a real
registry. Every step is read-only: it lists tags and reads manifests and image
configs, and writes local files. Nothing is pulled, mutated, or published.

```bash
go -C cli build -o ../clearcutt-verify ./cmd/clearcutt-verify

# 1. Ask the registry what it holds. Registries without a _catalog endpoint
#    (GHCR, Docker Hub) need --repository, which repeats.
export GHCR_TOKEN=$(gh auth token)
./clearcutt-verify registry scan \
  --registry ghcr.io --namespace YOUR_ORG/YOUR_REPO \
  --repository YOUR_BASE_IMAGE --repository YOUR_APP_IMAGE \
  --username YOUR_USER --password-env GHCR_TOKEN \
  --output dist/scan/images.yaml

# 2. Read each image's manifest, config, layers, and labels.
./clearcutt-verify import observe \
  --images dist/scan/images.yaml --output dist/scan/observations.json

# 3. Work out which images are built on which, and how stale each one is.
./clearcutt-verify graph build \
  --observations dist/scan/observations.json \
  --output dist/scan/graph.json --report dist/scan/inventory.md

# 4. Report what the estate has in common, with a diagram.
./clearcutt-verify graph layers \
  --observations dist/scan/observations.json \
  --output dist/scan/layers.json --report dist/scan/commonality.md
```

`graph build` writes an auditable inventory: base families, which consumers sit
on which version, how many versions and days behind each one is, and how every
relationship was established. `graph layers` answers the remediation question —
if a layer carries a vulnerable package, which images ship it.

Both can gate CI. `graph build --min-confidence verified --fail-on-stale` exits
2 when anything is on a stale base, and still writes the report.

Pass the results to the site builder to publish them as pages — `/estate` and
`/estate/layers` — with `catalog site build --graph … --layers …`.

See [registry scan and the base image graph](docs/registry-graph.md).

### Which images ship a vulnerable package

`graph packages` answers the question an advisory actually raises. For estates
built by Nix `dockerTools` it costs **no extra requests at all**: the package set
with exact versions is already in the image config that step 2 fetched.

```bash
./clearcutt-verify graph packages --observations dist/scan/observations.json --package openssl
```

```
openssl  3.6.2      259 images
openssl  3.6.2-bin   66 images
  → then names every one of them
```

Builders that record no package set need an SBOM, which has to be fetched.
That is opt-in via `--fetch-sboms`, and the command prints how many requests it
will make — and what deduplication saves — before making them.

### Keep the answers, and show they improved

Snapshots persist as OCI artifacts in the registry the images already live in,
so there is no database to run and evidence travels with a mirror.

```bash
./clearcutt-verify estate push ghcr.io/acme/estate:$(date +%F) \
  --dir dist/scan --history ghcr.io/acme/estate:history

./clearcutt-verify estate history ghcr.io/acme/estate:history
```

The history is an OCI index whose entries carry each run's metrics as
annotations, so reading a trend costs one request no matter how long the series
gets. `evidence attach` stores SBOMs, scans and provenance against the image
digest they describe, and `evidence export` copies them somewhere with its own
retention guarantees — registry lifecycle rules can delete attachments.

See [registry-native evidence](docs/registry-native-evidence.md) for the
garbage-collection and tag-mutability constraints that come with this.

## Install

Each release publishes cross-compiled CLI binaries named
`clearcutt-verify-<os>-<arch>` for `darwin`, `linux`, and `windows` on `amd64` and
`arm64`, a keyless Sigstore signature bundle (`<binary>.sig`) for each, and a
`SHA256SUMS.txt` checksum manifest. (Releases before the rename to ClearCutt
Verify name them `clearcutt-<os>-<arch>` and were signed as
`northcutted/clearcutt`; the identity below accepts both.) Download the binary
for your platform and
its `.sig` bundle from the
[latest release](https://github.com/northcutted/clearcutt-verify/releases/latest),
then verify the signature before running anything:

```bash
# Example assets: Apple Silicon macOS. Pick the pair matching your OS/arch.
cosign verify-blob \
  --bundle clearcutt-verify-darwin-arm64.sig \
  --certificate-identity-regexp '^https://github\.com/northcutted/clearcutt(-verify)?/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  clearcutt-verify-darwin-arm64

chmod +x clearcutt-verify-darwin-arm64
```

The certificate identity is the release workflow pinned to `refs/heads/main` —
the same identity recorded in `clearcutt.yaml` and matched exactly by
`clearcutt-verify verify release-evidence`. From a repo clone, the verified binary
runs the same fixture-backed first proof as above:

```bash
./clearcutt-darwin-arm64 --catalog cli/internal/testdata/catalog list
```

Building from source stays the contributor path; see
[CONTRIBUTING.md](CONTRIBUTING.md) and the clean-clone proof above.

## Where To Start

| Role | First document | First useful command |
| --- | --- | --- |
| Estate owner | [Registry scan and the base image graph](docs/registry-graph.md) | `go -C cli run ./cmd/clearcutt-verify registry scan --registry ghcr.io --namespace YOUR_ORG/YOUR_REPO --repository YOUR_IMAGE --output /tmp/images.yaml` |
| App developer | [Getting started](docs/getting-started.md) | `go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog inspect java21-distroless` |
| Imported fleet owner | [Imported fleets](docs/imported-fleets.md) | `go -C cli run ./cmd/clearcutt-verify import images --refs ../examples/imported-fleet/refs.txt --output /tmp/clearcutt-import/images.yaml --force` |
| Estate owner | [Registry scan and the base image graph](docs/registry-graph.md) | `go -C cli run ./cmd/clearcutt-verify registry scan --registry ghcr.io --namespace YOUR_ORG/YOUR_REPO --repository YOUR_IMAGE --output /tmp/images.yaml` |
| Security or auditor | [Trust evidence walkthrough](docs/trust/evidence-walkthrough.md) | `go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --allow-preview` |
| Engineering manager | [Alternatives and fit](docs/alternatives.md) | `sed -n '1,120p' docs/alternatives.md` |
| Open-source evaluator | [Demo path](docs/demo.md) | `go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog list` |

For a deterministic imported-fleet proof that does not require Nix or registry
access:

```bash
# Offline deterministic demo
./scripts/demo-imported-fleet-offline.sh

# The script prints a unique output directory. To use a fixed path:
OUT=/tmp/clearcutt-import-demo ./scripts/demo-imported-fleet-offline.sh
cat /tmp/clearcutt-import-demo/imported-fleet-report.md
```

ClearCutt can govern imported images without trusting them by default. It
records what can be observed, preserves missing evidence, and only treats
provenance as verified when actual provenance evidence exists.

The full documentation index is [docs/README.md](docs/README.md).

Contributor note: if the platform-source drift check fails, refresh the
embedded source archive with:

```bash
go -C cli run ./internal/platformsource/internal/genplatformsource
```

## Portal Preview

These screenshots are generated from the committed mixed catalog fixture, not
from ignored local site data.

![Fixture-backed catalog matrix showing runtime and service image records](docs/images/catalog-matrix.png)

![Fixture-backed java21-distroless evidence view showing verification commands and recorded release evidence](docs/images/java21-distroless-evidence.png)

## Proof Map

- [Mental model](docs/concepts/mental-model.md) explains the two loops:
  platform teams publish the fleet; app teams adopt, gate, admit, and update.
- [Glossary](docs/concepts/glossary.md) defines lanes, tiers, evidence,
  certification, verification, exceptions, VEX, rebase, preview, and scaffold.
- [CLI reference](docs/cli-reference.md) maps the current command surface.
- [Catalog generator](docs/catalog-generator.md) explains generated catalog
  data, raw evidence directories, validation, and generic OCI mode.
- [Catalog evidence walkthrough](docs/trust/catalog-evidence.md) explains what
  the portal proves, what it only reports, and how missing evidence appears.
- [Security model](docs/security-model.md) documents trust boundaries and
  non-claims.
- [Policy bundles](docs/policy-bundles.md) covers Kyverno and Gatekeeper policy
  generation.

## Repo Layout

| Workspace | Purpose |
| --- | --- |
| `cli/` | Go governance CLI and tests. |
| `site/` | Astro catalog portal and generated-site template source. |
| `docs/` | Role-routed documentation, trust walkthroughs, and operating guides. |
| `examples/` | A real public-estate snapshot, deployment manifests, and policy examples. |
| `.github/` | CLI release, catalog/Pages, and PR gate workflows. |

## Boundaries

ClearCutt is pre-1.0 and intentionally conservative in its claims.

**It reports and gates. It does not patch.** ClearCutt will tell you an image is
on a stale base, is missing a signature, or ships a layer with a known CVE. It
will not rebuild, re-tag, or mutate a published image to fix that. `app rebase`
prepares and proves a base swap; publishing it stays a human decision.

**Currency is measured against what a scan observed**, not against upstream. A
base family that is itself out of date will still report its consumers current.

**The reference fleet is a fixture.** It is built from a nixpkgs pin that moves
when someone merges the update PR. Do not run it in production, and do not read
its single runtime line as a supported image feed.

Use ClearCutt when you need to know what is in your registry and prove things
about it. Do not use it when you primarily want a vendor SLA, a hosted control
plane, a managed patch stream, or FIPS/STIG certification out of the box — see
[alternatives and fit](docs/alternatives.md).

## Security

See [SECURITY.md](SECURITY.md) for the supported-release policy and how to
report vulnerabilities privately.

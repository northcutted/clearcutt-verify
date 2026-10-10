# Registry Scan And The Base Image Graph

ClearCutt can discover an image estate instead of being handed one.

`clearcutt-verify registry scan` asks a registry what it actually holds. `clearcutt-verify graph
build` then works out which of those images are built on which, how that was
established, and how far behind each consumer is from the newest version of its base.

The result is a governance inventory for images ClearCutt did not build, did not sign,
and knows nothing about in advance.

## Why This Exists

A hand-written list of image references inverts the actual problem: the reason a
platform team needs an inventory is that nobody knows what is running on what.
`graph build` answers the discovery question: *"given these images, which are built
on which?"*

## Golden Path

```bash
# 1. Ask the registry what it holds
clearcutt-verify registry scan \
  --registry ghcr.io \
  --namespace acme/platform \
  --repository base-java21 \
  --repository payments-api \
  --output dist/scan/images.yaml

# 2. Read each image's manifest, config, layers, and labels
clearcutt-verify import observe \
  --images dist/scan/images.yaml \
  --output dist/scan/observations.json

# 3. Derive the graph and an auditable report
clearcutt-verify graph build \
  --observations dist/scan/observations.json \
  --output dist/scan/graph.json \
  --report dist/scan/inventory.md
```

Every step is read-only against the registry. Nothing is pulled beyond manifests and
configs, no tag is mutated, and nothing is published.

## Enumerating A Registry

`registry scan` prefers the distribution `_catalog` endpoint, filtered by
`--namespace`. Several major registries — GHCR and Docker Hub among them — do not
implement `_catalog` for a user namespace. Name the repositories instead:

```bash
clearcutt-verify registry scan --registry ghcr.io --namespace acme/platform \
  --repository base-java21 --repository base-node22 \
  --output dist/scan/images.yaml
```

`--repository` is repeatable and accepts either a bare name (qualified against
`--namespace`) or a full path.

On GHCR, `--github-org` enumerates an organization's (or user's) container
packages through the GitHub Packages API instead, so new repositories show up
without anyone listing them. It needs a `GITHUB_TOKEN` that can read packages;
`--package-prefix` (repeatable) keeps only some of them:

```bash
GITHUB_TOKEN=$(gh auth token) clearcutt-verify registry scan --github-org acme \
  --package-prefix apps/ --package-prefix platform/ --output dist/scan/images.yaml
```

### Sidecar Tags

Cosign signatures, attestations, and SBOM references are published as tags shaped like
`sha256-<digest>.sig`. They are evidence *about* an image, not images a workload runs,
and in a signed estate they outnumber real tags. `registry scan` skips them and reports
the count. Pass `--include-sidecar-tags` to keep them.

### Filters

| Flag | Effect |
| --- | --- |
| `--tag-pattern` | Keep only tags matching this glob. Repeatable. |
| `--exclude-tag` | Reject tags matching this glob, even if included. Repeatable. |
| `--max-tags` | Cap tags per repository (default 25), keeping the highest-sorting. |

### Credentials

`registry scan` authenticates from the ambient keychain (Docker config, cloud
credential helpers) by default. For explicit credentials:

```bash
export ACME_TOKEN=...
clearcutt-verify registry scan --registry ghcr.io --namespace acme/platform \
  --username acme-ci --password-env ACME_TOKEN --output dist/scan/images.yaml
```

The password is read from an environment variable rather than a flag so a registry
token never lands in shell history or a process listing.

## How A Base Relationship Is Established

`graph build` applies five detectors, strongest first, and records every one that
matched so a reviewer sees what was tried rather than only the verdict.

| Method | Confidence | What it rests on |
| --- | --- | --- |
| `layer-prefix` | `verified` | The consumer's leading layer digests **are** the base's layers. |
| `oci-base-digest` | `declared` | `org.opencontainers.image.base.digest`, which BuildKit stamps automatically. |
| `buildpacks-metadata` | `declared` | `io.buildpacks.lifecycle.metadata` run-image reference or top layer. |
| `oci-base-name` | `assisted` | `org.opencontainers.image.base.name` — names the repository, not a version. |
| `history` | `weak` | The base repository appears in the consumer's build history. |

**Only `layer-prefix` is proof.** It compares content digests, so it holds regardless
of what an image claims about itself and cannot be forged by writing a label. It also
needs no cooperation from whoever built the image, which is what makes it work on an
estate that predates any of this tooling.

Everything else is a claim the image's own author made. The graph labels it as such,
and a self-reported label never outranks layer proof — if an image claims one base and
its layers prove another, the graph reports the proven one and keeps the contradicting
claim visible on the edge.

## Drift

A base *family* is every observed version of one repository. Currency is decided by the
image config's creation timestamp, not by tag name: tags lie (`latest` moves, `v2` can
predate `v10`) while the timestamp is baked into the artifact being scanned. Tag order
is only the tiebreak when timestamps are missing, and the report says so when it had to
fall back.

Each edge carries:

- `drift`: `current`, `stale`, or `unknown`
- `versionsBehind`: published versions between the matched base and the newest one
- `daysBehind`: days between the matched base and the newest one

Reproducible builders zero the creation timestamp on purpose — Nix `dockerTools`
stamps `1970-01-01T00:00:01Z` on everything. Those are treated as *no* timestamp
rather than as a real date, so currency falls back to tag order, `daysBehind` stays
0, and the base family carries a warning saying exactly that. Ranking a whole
reproducible fleet as equally old would be worse than admitting there is no signal.

Scanning several tags per base repository is what makes drift measurable. A scan of
only the newest tag can prove a consumer is current but cannot tell a stale consumer
from an unrecognised one.

## Shared Layers And Blast Radius

Images can share content without one being built on the other. A builder that
distributes store paths across layers by popularity — Nix
`dockerTools.buildLayeredImage`, most notably — produces sibling images that share
most of their content while neither is a prefix of the other. So does any workflow
that rebuilds from a common recipe rather than stacking a base.

`graph build` reports that separately, and never as parentage:

```
Shared layers (blast radius): 100 of 167 distinct layers are in more than one image; the widest is in 14
```

Each shared layer records every image carrying it. That answers the remediation
question directly: if a layer ships a vulnerable package, these are the images
affected — regardless of whether any of them is "based on" any other.

`--max-shared-layers` caps how many are retained (default 100, widest reach first;
`-1` keeps all).

When an image cannot be placed in the graph but does share layers, the unresolved
reason says so and points here rather than leaving a dead end.

### Composed Builders: Nix, Wolfi, And Friends

Base detection rests on layer prefixes — a derived image begins with exactly its
base's layers, in order. That holds for Docker, buildkit and buildpacks, where a
build literally starts FROM another image.

It does not hold for **Nix `dockerTools`** or **apko** (Wolfi, Chainguard). Those
take a package set and lay it out across layers by size and sharing. Two images
built from the same package set share most of their layers and neither is a
prefix of the other, because neither was built *on* the other. They are siblings,
not ancestor and descendant.

So ClearCutt classifies how each image was assembled, from metadata it already
has — no extra pulls:

| builder | signal | layering |
| --- | --- | --- |
| `nix` | history entries naming `/nix/store/…` paths | composed |
| `apko` | `createdBy: apko`, or `dev.chainguard.*` labels | composed |
| `buildpacks` | `io.buildpacks.*` labels | stacking |
| `buildkit` | `buildkit.dockerfile.v0` in history | stacking |
| `debuerreotype` | Debian's official base builder | stacking |
| `docker` | `#(nop)` / `RUN /bin/sh -c` history | stacking |

`graph build` reports the mix, and when an estate is predominantly composed and
resolves no bases, it says so explicitly:

```
[graph] 404 image(s) observed: 0 base famil(ies), 404 consumer(s), 0 root(s)
[graph] resolved 0 consumer(s): 0 on the current base, 0 stale, 404 undetermined
[graph] built by: nix x395, unidentified x9 (9 stacking, 395 composed)

[graph] No base relationships were found, and for this estate that is the correct
        answer rather than a gap: it is built by nix, which composes layers from a
        package set instead of stacking them on a base image...
```

**Zero resolved means opposite things on the two estate shapes.** On a Docker
estate it is missing provenance worth chasing. On a Nix or Wolfi estate it is the
correct answer, and chasing it wastes an afternoon. The note only fires when the
estate is at least 75% composed AND nothing resolved — a mixed estate still wants
its stacking images resolved, and a stacking estate with nothing resolved has a
real gap that must not be explained away.

An unidentified builder is assumed to STACK. That is the direction that keeps
coverage honest: assuming composed would silently exempt an image from base
detection on no evidence.

For a composed estate the useful lens is the layer view — what images have in
common, and which of them one vulnerable layer reaches.

## Package-Level Governance

`graph packages` analyses an estate by what it INSTALLS, not by what it stacks.
It is the view that works for composed builders, and it answers the question a
layer view cannot: when a CVE lands against a named package at a named version,
which images ship it.

```bash
clearcutt-verify graph packages --observations observations.json --output packages.json

# An openssl advisory just landed.
clearcutt-verify graph packages --observations observations.json --package openssl
```

### For Nix this costs nothing

Nix `dockerTools` writes one history entry per layer naming the store paths that
layer carries, and the image **config** — already fetched to observe the image at
all — therefore contains the exact package set with content hashes.

Measured on a real 404-image Nix estate: 395 images resolved, 581 distinct
packages with exact versions, in under a second, with **zero registry requests**.

A store hash is stronger identity than a version string: two images carrying
`openssl-3.6.2` may still carry different builds of it, and the hash tells them
apart.

### For other builders it costs requests, and says so first

Builders that leave no package trail in their config need an SBOM, which has to
be fetched. That is opt-in, and the cost is reported before it is spent:

```
[graph-packages] 5 image(s) record no package set in their config.
[graph-packages] --fetch-sboms would recover them with 1 registry fetch(es)
                 (4 avoided by deduplicating identical content).
```

Two things keep this affordable:

- **Only unresolved images are fetched.** Nix images never enter the expensive
  path.
- **Fetches deduplicate by manifest digest.** An estate re-tags the same content
  on every release, so the number of distinct images is far below the number of
  tags. Ten tags on one image cost one fetch.

With `--fetch-sboms`, the command warns on stderr before making any request,
naming the request count, the concurrency, and how many fetches deduplication
avoided. A failed or missing SBOM leaves that image's packages **unknown**, never
silently empty — the distinction matters when the answer feeds a vulnerability
question.

SBOMs are read from OCI referrers first, then the cosign `sha256-<digest>.sbom`
sidecar convention. SPDX and CycloneDX are both parsed.

**`--fetch-sboms` only helps when someone attached one.** This is not a switch
that produces packages for every image; it retrieves documents that already
exist. Checked against real public images: `docker.io/library/python:3.12-slim`
has no attachment, and `cgr.dev/chainguard/static:latest` returns an empty
referrers list and a 404 on the sidecar tag — Chainguard publishes SBOMs through
their own API rather than as registry attachments. Both correctly come back as
**unknown**.

That is the argument for the free path in one line: reading Nix store paths out
of a config depends on nobody, while fetching an SBOM depends on the publisher
having attached one.

### Lineage: the relation composed estates actually have

For a composed estate the meaningful relation is not ancestry but shared build
inputs. `graph packages` reports lineage pairs by package-set overlap, using the
same budgeted, narrowest-first comparison as the layer graph — so a package
nearly every image carries, which cannot distinguish any two of them, is dropped
from scoring before it can blow up memory, and is still reported in full under
reach.

### Layer-Prefix Detection Assumes A Stacked Base

This is the main limitation to know about. `layer-prefix` proof requires the base's
layers to be a *leading run* of the consumer's — the shape Dockerfile/BuildKit, jib,
ko, and buildpacks all produce. It does not fire on:

- Nix `dockerTools.buildLayeredImage` output, where content is distributed by
  popularity rather than stacked.
- Images squashed to a single layer after the fact.
- Any rebuild-from-recipe workflow that does not inherit a parent image.

For those estates the label-based detectors still apply if the builder stamps
`org.opencontainers.image.base.*`, and the shared-layer blast radius applies always.

## Layer-Level Commonality

`clearcutt-verify graph layers` answers the other half of the question. Where `graph build`
asks what an image is built **on** — parentage, answered by layer *order* —
`graph layers` asks what the fleet has **in common** — content, answered by layer
*membership*. The two are independent, and neither implies the other.

```bash
clearcutt-verify graph layers \
  --observations dist/scan/observations.json \
  --output dist/scan/layers.json \
  --report dist/scan/commonality.md \
  --mermaid dist/scan/graph.mmd
```

It reports:

| Section | Answers |
| --- | --- |
| Fleet core | Which layers are in **every** image. A vulnerability here hits everything at once. |
| Common layers | Which layers reach `--coverage` (default 0.75). The highest-leverage remediation targets. |
| Content-identical images | Which references carry byte-identical layer sets. |
| Clusters | Which images move together when shared content changes. |
| Similar pairs | Jaccard and containment for every pair above `--min-similarity` (default 0.5). |
| Per-image profile | How much of each image is content nothing else carries. |
| Deduplication | What the registry stores versus what the fleet would cost with no reuse. |

### Content-Identical Images

This one is worth calling out. Images published under different references with
identical layer sets usually mean a release republished something that did not
change. On this repository's own fleet, all 16 scanned images fall into 6 identical
groups — `v0.12.2`, `v0.13.0`, and `v0.14.0` are content-identical for every tier.
Three releases, no new content.

Note that identical layers mean identical *content*, not identical *configuration*:
two images can share every layer and still differ in entrypoint, user, or labels.

### The Diagram

`--mermaid` writes the clustered commonality graph, with edges labelled by shared
layer count. It renders on GitHub, in an Artifact, and anywhere else Mermaid is
supported. The report embeds the same diagram inline.

Both are capped for readability (24 images, 40 edges) and say what was elided.

### Scale

Pair generation walks the layer index rather than the image list, so images with
nothing in common are never compared — on a sparse estate that turns a quadratic scan
into work proportional to the sharing that actually exists.

That is not the whole story, though, and the exception is the interesting case. Cost
is the sum over layers of `C(carriers, 2)`, so a single layer carried by every image
contributes `C(N, 2)` on its own — and a well-governed estate is exactly where that
happens. The better the fleet, the more images sit on one base, the wider that base's
layers reach.

A pair budget bounds it. Layers are processed narrowest-first, so when the budget is
reached the layers dropped are the widest ones — the layers nearly everything carries,
which say the least about whether any two images are alike. A layer present in every
image adds the same constant to every pair's intersection; it cannot separate them.
Those layers are still reported in full as fleet core and blast radius, which is where
a wide layer is the interesting answer rather than noise.

A dropped layer is excluded from the union as well as the intersection, so Jaccard is
computed over the layers that actually discriminate. Excluding it from only one side
would depress every score by an arbitrary constant.

When the budget bites, the graph says so in `warnings` with the count of excluded
layers. A 2000-image estate with a universal base layer keeps full similarity and
clustering; core, coverage and deduplication accounting are linear in total layers and
are never affected.

`--max-pairs` (default 250, `-1` for all) caps reporting only. Clustering always sees
every qualifying pair.

## Persisting A Snapshot

`clearcutt-verify estate push` stores a snapshot — the observations plus both graphs — in a
registry as an OCI artifact, and `estate pull` reads it back.

```bash
clearcutt-verify estate push ghcr.io/acme/clearcutt-estate:$(date +%F) \
  --dir . --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

clearcutt-verify estate pull ghcr.io/acme/clearcutt-estate:2026-08-31 --output ./snapshot
```

The registry is a deliberate backing store rather than a convenient one. The evidence
lives under the same auth boundary, replication and retention policy as the images it
describes; digests make each snapshot immutable and addressable; tags give history, so
estate drift is a diff between two tags; and a mirrored registry carries its own
evidence into an air gap. Nothing new has to be operated — no database to run, back
up, or get paged for.

Snapshots are deterministic: files are sorted, so identical content produces an
identical manifest digest. A nightly job that re-pushes an unchanged estate does not
mint a new version, and "has anything changed?" is answerable by comparing digests
rather than diffing content.

See [registry-native-evidence.md](registry-native-evidence.md) for the full
picture, including release evidence, the garbage-collection risk and how to hedge
it with `evidence export`, and which tags must stay mutable.

Two things worth knowing:

- **Sign it.** When the registry is the thing being audited, storing the audit inside
  it is a mild conflict of interest. `clearcutt-verify` already wraps cosign; a signed
  snapshot makes tampering detectable rather than merely unlikely.
- **`pull` refuses foreign artifacts.** A manifest whose config media type is not
  `application/vnd.clearcutt.estate.v1+json` is rejected rather than read. Pulling an
  ordinary image and treating its layers as governance evidence would be worse than
  failing.

Storage is not the scaling limit here — an observation is metadata, never image
content, so a 10,000-image estate is tens of MB. The limit is the observe fan-out:
every image costs an index fetch, a per-platform manifest and a config, so a large
estate is bounded by registry rate limits long before anything else.

## Published

`estate verify` carries the same base relationships, proven by layer digest, into
the estate report, and
[clearcutt-portal](https://github.com/northcutted/clearcutt-portal) publishes it.
`estate dependents` lists the images built on a base, with their source
repositories.

## Roots Versus Orphans

An image with no parent is not automatically a finding.

- **Roots** are images other images were proven to sit on, repositories named by
  `--base-repository`, or versions of a repository that is serving as a base elsewhere.
  A from-scratch base image belongs here.
- **Orphans** are images whose base genuinely could not be determined. These are audit
  findings, and the report says why each one could not be placed.

## Narrowing And Gating

```bash
# Only these repositories may act as bases
clearcutt-verify graph build --observations obs.json --output graph.json \
  --base-repository 'ghcr.io/acme/platform/base-*'

# Accept only proven relationships
clearcutt-verify graph build --observations obs.json --output graph.json \
  --min-confidence verified

# Fail CI when anything is on a stale base, or cannot be placed
clearcutt-verify graph build --observations obs.json --output graph.json \
  --fail-on-stale --fail-on-unknown
```

`--fail-on-stale` and `--fail-on-unknown` exit 2, the same contract as ClearCutt's
other gates. The graph and report are still written when a gate fails: the failure is
a verdict, not a crash.

## What This Does Not Prove

- A `layer-prefix` edge proves the consumer contains the base's layers. It does not
  prove that base was the intended one, nor that either image is signed, scanned, or
  fit for production.
- A `declared`, `assisted`, or `weak` edge rests on metadata the image's author
  supplied. Treat it as a claim to verify, not a finding.
- Currency is measured against the newest version **observed in this scan**, not
  against upstream. A base family that is itself out of date will still report its
  consumers as current.
- A shared layer means shared content, not a base relationship.
- No CVE, signature, SBOM, or provenance conclusion is drawn. Run
  `clearcutt-verify estate verify` for verified evidence, and
  `clearcutt-verify import assess` for the evidence-gap view.

## Related

- [`imported-fleets.md`](imported-fleets.md) — governing images ClearCutt did not build
- [`verify-estate.md`](verify-estate.md) — verifying evidence and writing the estate report

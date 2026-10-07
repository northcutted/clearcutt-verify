# Public estate fixture

A real, committed snapshot of 19 well-known public container images, observed
from live registries on 2026-08-31.

This is the demo set for ClearCutt's governance features. It is deliberately not
built from ClearCutt images: the product's claim is that it can govern an estate
you did not build and cannot control, and demonstrating that against images we
built ourselves would prove the weaker version of it.

## Why it is committed rather than fetched

`clearcutt-verify import observe` will happily re-observe these refs live. The snapshot
is committed so the demo, the site build, and the regression test are hermetic
and deterministic — a tag that moves upstream must not change what CI asserts.

Re-observing today will produce different digests. That is the point of the
snapshot, not a defect in it.

## Regenerating

```sh
clearcutt-verify import images   --refs refs.txt --output images.yaml \
                          --owner public-estate --repo demo \
                          --generated-at 2026-08-31T00:00:00Z --force
clearcutt-verify import observe  --images images.yaml --output observations.json \
                          --generated-at 2026-08-31T00:00:00Z
clearcutt-verify graph build     --observations observations.json --output graph.json \
                          --generated-at 2026-08-31T00:00:00Z --force
clearcutt-verify graph layers    --observations observations.json --output layers.json \
                          --generated-at 2026-08-31T00:00:00Z --force
```

Those two `graph` commands are written out in full because `graph.json` and
`layers.json` are committed here and the recipe has to reproduce them. To just
*look* at this estate, both flags are optional — `--observations` defaults to
`./observations.json`, and without `--output` the report goes to the terminal
and nothing is written:

```sh
cd examples/public-estate && clearcutt-verify graph build
```

Expect `TestPublicEstateFixtureDetectorCoverage` to need updating afterwards; it
pins what this data proves, so a regeneration that changes the findings should
be a deliberate, reviewed change.

## What the snapshot shows

19 images observed, **3 base relationships resolved, 14 undetermined**. That
ratio is the headline finding, not a shortfall: most public images declare
nothing about what they are built on, so provenance has to be proven from layer
digests or admitted as unknown.

| what it demonstrates | evidence |
| --- | --- |
| **Proof** — `layer-prefix` | `node:22-slim` and `python:3.12-slim-bookworm` each start with exactly the layers of `debian:bookworm-slim`. Confidence `verified`: this is a fact about bytes, not a claim. |
| **Claim** — `oci-base-name` | `bitnami/nginx` declares `org.opencontainers.image.base.name = docker.io/library/photon:5.0`. Confidence `assisted`, and the edge carries the caveat that the label names a repository but not a digest, so the specific version is inferred. |
| **Absence as a first-class state** | 14 images resolve to nothing and say why — no labels, or shared layers that do not form a base prefix. They are reported, not dropped. |
| **Shared-layer blast radius** | 12 of 96 distinct layers appear in more than one image; the widest is in 3. Storing once costs 671MB against 786MB without reuse. |

### The finding worth looking at

`python:3.12-slim` and `python:3.12-slim-bookworm` are commonly assumed to be
the same image under two tags. In this snapshot they were built **42 seconds
apart** and sit on **different debian base layers**:

```
python:3.12-slim           layers[0] = sha256:6310eb16bf425…   (an older debian)
python:3.12-slim-bookworm  layers[0] = sha256:a8ac7f6c67abc…   (current bookworm-slim)
debian:bookworm-slim       layers[0] = sha256:a8ac7f6c67abc…
```

So only one of the two is provably on the current base. The other resolves to
nothing, because the debian build it was made from is no longer what the
`bookworm-slim` tag points at.

Nobody would find that by reading tags, and it is the ordinary case rather than
a curiosity: base tags move, and images built before the move keep pointing at
content the tag no longer names.

## The history series

`history.json` is a real two-snapshot series, exported from an estate history
index with `clearcutt-verify estate history --format json`.

Between 2026-08-31 and 2026-09-01, **6 of the 19 images moved** — new manifest
digests for `python:3.11-slim`, `python:3.12-slim`, `python:3.12-slim-bookworm`,
`python:3.12-alpine`, `paketobuildpacks/run-jammy-base` and
`chainguard/static`, all within 24 hours.

And the governance numbers did not move at all:

| | 2026-08-31 | 2026-09-01 |
|---|---|---|
| images | 19 | 19 |
| resolved | 3 | 3 |
| proven | 2 | 2 |
| coverage | 18% | 18% |

That flat line is deliberately not dressed up. It is the honest baseline every
real estate starts from, and it makes the argument for measuring better than a
rising chart would: **the content churns constantly and the provenance does not
improve on its own.** Coverage rises when someone does the work, and the series
is what shows whether they did.

It also demonstrates why the incremental scan matters. On the second day, 13 of
19 images were unchanged and cost one HEAD request each instead of a full read.

One nuance visible here: these two snapshots share **no** blobs, because all
three files changed when six images moved. Content-addressed storage makes an
unchanged file free, not a changed one — dedup pays on a stable estate or a
slower cadence, and does nothing when everything moves.

## Regenerating the history

```sh
clearcutt-verify estate push ghcr.io/acme/estate:$(date +%F) \
  --dir . --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --history ghcr.io/acme/estate:history
clearcutt-verify --format json estate history ghcr.io/acme/estate:history > history.json
```

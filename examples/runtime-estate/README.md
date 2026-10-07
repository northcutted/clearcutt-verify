# Runtime estate fixture

Eight real public images, observed live and committed as a snapshot:
`debian:bookworm-slim` and seven runtimes that ship on top of it — two Node
versions, two Python versions, Ruby, Postgres, nginx.

This is the shape a real estate has: **one base, and the things built on it.**
That matters, because it is the shape the tooling is actually for.

## Why this exists alongside `public-estate`

[`examples/public-estate/`](../public-estate/) is 19 *unrelated* public images.
It is deliberately hostile input — different builders, no common ancestry — and
only 3 of 19 base relationships resolve there. That is the right answer for that
data, and it is a good regression fixture precisely because it is hard.

It is a bad demonstration, though, and not because the tool does badly on it.
Nobody governs 19 unrelated public images. They govern a base and the fleet
built from it, where lineage genuinely exists and can genuinely be proven:

```
$ clearcutt-verify graph build
[graph] 8 image(s) observed: 1 base famil(ies), 7 consumer(s), 1 root(s)
[graph] resolved 5 consumer(s): 5 on the current base, 0 stale, 2 undetermined
[graph] 5 of 5 relationship(s) are proven by layer digests
Shared layers (blast radius): 1 of 40 distinct layers are in more than one image; the widest is in 6
```

Five of five proven by layer digest — no label was trusted to get there. One
debian layer sits under six of the eight images, so patching it moves six.

The two that do not resolve are reported, with reasons: `nginx:1.27-bookworm`
shares no layer with any observed base, and `node:20-bookworm-slim` shares none
*and* declares no labels. Both are honest outcomes, not silent omissions.

## What it does not answer

`graph packages` reports all 8 as unknown. Debian's builder records no package
set in the image config, so there is nothing to read for free:

```
[graph-packages] 8 of 8 image(s) record no package set in their config. Their
packages are UNKNOWN, not absent — attach or fetch an SBOM to include them.
[graph-packages] --fetch-sboms would recover them with 8 registry fetch(es)
```

That is the honest state of package-level questions on ordinary images: they
cost network, and the command prices them before spending it. Where a builder
does record its packages — see [`examples/nix-estate/`](../nix-estate/) — the
same command answers for free.

## Regenerating

```sh
cd examples/runtime-estate
clearcutt-verify import images  --refs refs.txt --output images.yaml \
                         --owner runtime-estate --repo demo \
                         --generated-at 2026-09-01T00:00:00Z --force
clearcutt-verify import observe --images images.yaml --output observations.json \
                         --generated-at 2026-09-01T00:00:00Z
```

These are moving tags. Re-observing will produce different digests, and may
change how many relationships resolve — that is a property of the upstream
images, not a defect in the snapshot.

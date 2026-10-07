# Nix estate fixture

Ten real ClearCutt-built images, observed from GHCR and committed as a
deterministic snapshot.

It exists for one reason: **to demonstrate package-level governance**, which the
[public estate fixture](../public-estate/) cannot. Those 19 images are built by
Debian, buildkit, apko and buildpacks — none of which records a package set in
the image config — so `graph packages` correctly reports them all as unknown.

Nix `dockerTools` does record one. It writes the store paths of every layer into
the image config, which ClearCutt already fetches to observe the image at all.
So for a Nix estate the exact package set, with versions and content hashes,
costs **no extra registry requests**:

```sh
clearcutt-verify graph packages --package openssl
```

```
10 image(s): 10 with a readable package set, 0 unknown
evidence: nix-store-paths x10
166 distinct package(s), 148 carried by more than one image

openssl  3.6.2   4 images
  → then names all four
```

That is the question a CVE advisory actually raises, answered from data already
on disk.

## Regenerating

```sh
clearcutt-verify import observe --images images.yaml --output observations.json
```

The images are ClearCutt's own former base images. The project no longer builds
or maintains them; they remain published, and they are useful here precisely
because they are real Nix output rather than something hand-written.

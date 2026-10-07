# Generic OCI Mode

Generic OCI mode lets ClearCutt produce a catalog and static evidence portal
from ordinary OCI image references. It does not require Nix, ClearCutt release
workflows, or ClearCutt-specific GitHub release assets.

Use this mode when you want the portal shape first and will add richer evidence
later.

Imported-fleet mode builds on this data path. Use
`clearcutt-verify import images` when you have a plain list of external image refs and
want ClearCutt to generate the compatible `images.yaml` for you.

## Inventory File

Create an `images.yaml` file:

```yaml
images:
  - id: java21-distroless
    image: ghcr.io/acme/base/java21:v1.2.3
    language:
      id: java
      displayName: Java
      version: "21"
    tier: distroless
    architectures:
      - amd64
      - arm64
    lifecycle:
      status: active
      support: lts
      productionAllowed: true
      deprecatedAt: null
      eolAt: null
      reason: null
    runtimeContract:
      shellPresent: false
      packageManagerPresent: false
      user: "10001"
      caCertificatesPresent: true
      timezoneDataPresent: true
      productionTier: true
```

Required fields:

- `id`
- `image`
- `language.id`
- `language.displayName`
- `language.version`
- `tier`

Optional fields:

- `tag`
- `architectures`
- `lifecycle`
- `runtimeContract`
- `origin`
- `governance`
- `evidencePolicy`

Supported tiers are `distroless`, `slim`, and `dev`. Supported architectures
are currently `amd64` and `arm64`.

## Generate A Catalog

```bash
clearcutt-verify catalog generate \
  --images images.yaml \
  --output ./dist/catalog \
  --owner acme \
  --repo base-images \
  --registry-base ghcr.io/acme/base-images
```

If `tag` is omitted, the tag or digest identifier is read from `image`.
Digest-pinned references preserve the digest as the manifest digest when it is
available from the reference itself.

## Build A Site Directly

```bash
clearcutt-verify catalog site build \
  --images images.yaml \
  --owner acme \
  --repo base-images \
  --registry-base ghcr.io/acme/base-images \
  --output ./dist/site \
  --install
```

## Evidence Limitations

Generic OCI mode intentionally records unavailable evidence as missing:

- signatures are not inferred,
- SLSA provenance is not inferred,
- SBOM package tables start empty unless supplied by a future enrichment path,
- vulnerability scan data starts empty,
- test results start empty.

That means `catalog validate` may report warnings such as missing signature
evidence or incomplete SBOM evidence. These warnings are useful: they tell
operators which evidence channels have not been wired yet.

For imported images, `origin.kind: imported`,
`origin.createdByClearCutt: false`, and `origin.provenanceClaim: none` make the
boundary explicit. ClearCutt does not infer signatures or SLSA provenance for
images it did not build.

## Validation

```bash
clearcutt-verify --catalog ./dist/catalog catalog validate
```

Use `--warnings-as-errors` only after your generic catalog has enough evidence
for the policy you want to enforce.

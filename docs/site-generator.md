# Astro Site Generator

`clearcutt-verify catalog site ...` renders catalog artifacts as a portable Astro
evidence portal. The site generator is separate from catalog data generation:
catalog data lives under `public/catalog`, while the Astro project owns layout,
search, routes, and customization.

## Commands

```bash
clearcutt-verify catalog site scaffold
clearcutt-verify catalog site build
clearcutt-verify catalog site preview
clearcutt-verify catalog site eject
```

Use the `catalog site` namespace because the site is a renderer for catalog
data, not a general website generator.

## Scaffold A Persistent Project

```bash
clearcutt-verify catalog generate \
  --config clearcutt.yaml \
  --include-services \
  --output ./dist/catalog

clearcutt-verify catalog site scaffold \
  --catalog ./dist/catalog \
  --output ./clearcutt-catalog-site

cd clearcutt-catalog-site
npm install
npm run dev
```

The scaffold command copies the Astro template, writes or preserves
`clearcutt.site.yaml`, writes a README when the template does not include one,
copies catalog data into `public/catalog`, and preserves raw evidence
directories.

The default homepage is a practical catalog navigator: current catalog status,
start-here links, and role-specific workflow sections for platform,
application, and security/audit engineers. Customize that surface through
`site.home` in `clearcutt.site.yaml` before reaching for page overrides.

Generated portals identify the catalog owner, registry, source repository,
generation time, and ClearCutt tooling. The intended reading is: "this site
renders catalog data for `<owner>/<repo>`; ClearCutt is the generator." Fork
owners should customize `site.title`, `site.description`, and links, but the
portal should keep ownership and evidence scope visible.

The Astro template is embedded in the `clearcutt-verify` binary, so `scaffold`,
`build`, `preview`, and `eject` work from any directory — no ClearCutt checkout
required. When you run inside the repository, the live `site/` directory is used
instead (and its `node_modules` is reused to speed up builds). Override the
source explicitly with `--template <dir>`.

> Maintainers: the embedded template mirrors `site/`. After changing `site/`,
> run `go generate ./...` in `cli/` to refresh it; the `sitetemplate` drift test
> fails in CI if it is stale.

## Build Static HTML

Build from an existing catalog directory:

```bash
clearcutt-verify catalog site build \
  --catalog ./dist/catalog \
  --output ./dist/site \
  --install \
  --clean
```

Generate mixed runtime/service catalog data, then build the static site from that
catalog:

```bash
clearcutt-verify catalog generate \
  --config clearcutt.yaml \
  --include-services \
  --output ./dist/catalog

clearcutt-verify catalog site build \
  --catalog ./dist/catalog \
  --output ./dist/site \
  --install
```

Use `catalog generate --include-services` whenever the site should show service
image records. Without it, the generated catalog is runtime-only even if
`clearcutt.yaml` contains `services[]`.

To verify service rendering without release data, build from the committed
mixed fixture:

```bash
clearcutt-verify catalog site build \
  --catalog cli/internal/testdata/mixed-catalog \
  --template site \
  --output ./dist/service-demo \
  --install
```

Build and generate catalog data in one command from generic OCI inventory:

```bash
clearcutt-verify catalog site build \
  --images images.yaml \
  --owner acme \
  --repo base-images \
  --registry-base ghcr.io/acme/base-images \
  --output ./dist/site \
  --install
```

`--config` and `--images` are mutually exclusive. `--catalog` can be used with
either one to choose where the generated catalog data is written before the site
build.

## Preview Locally

```bash
clearcutt-verify catalog site preview \
  --catalog ./dist/catalog \
  --install \
  --host 127.0.0.1 \
  --port 4321
```

If dependencies are missing and `--install` is not set, preview prints next
steps instead of failing the catalog workflow.

## Eject The Template

```bash
clearcutt-verify catalog site eject \
  --output ./astro-catalog-template
```

Use eject when you want to vendor and maintain the renderer separately from a
specific catalog artifact. Eject does not copy generated catalog data.

## Base Paths And Static Hosts

For GitHub Pages or a nested static path, pass `--base-path`:

```bash
clearcutt-verify catalog site build \
  --catalog ./dist/catalog \
  --output ./dist/site \
  --base-path /clearcutt \
  --install
```

The build command passes `BASE_PATH` to Astro and then copies `dist/` into the
requested output directory. Use `--clean` when the output directory already has
files.

## Customization

Use `--site-config` and `--overrides` to customize without forking ClearCutt:

```bash
clearcutt-verify catalog site build \
  --catalog ./dist/catalog \
  --site-config ./clearcutt.site.yaml \
  --overrides ./site-overrides \
  --output ./dist/site \
  --install
```

See [customization](customization.md) for supported config keys and override
roots.

## Deployment Shape

The generated site is a normal static Astro site. Any host that can serve files
from the output directory can publish it:

- GitHub Pages
- Cloudflare Pages
- S3 plus CloudFront
- Netlify
- an internal static web server

Keep `catalog/index.json`, `catalog/images/*.json`, `catalog/schemas/*.json`,
and `catalog/raw/*` together with the generated HTML.

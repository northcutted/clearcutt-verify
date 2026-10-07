# ClearCutt Catalog Site

This Astro workspace renders ClearCutt catalog data as a static evidence portal.
It can run inside the ClearCutt repository or as a scaffolded standalone site.

## Run Locally

```bash
npm install
npm run dev
```

Build static output with:

```bash
npm run build
```

In the ClearCutt repository, the site reads generated catalog data from
`src/data/catalog` when that build output exists locally. Scaffolded sites
receive generated catalog data under `public/catalog`.

## Generate A Site

With the ClearCutt CLI on your `PATH` (the Astro template is bundled in the
binary, so this works from any directory):

```bash
clearcutt-verify catalog generate --config clearcutt.fleet.yaml --include-services --output ./dist/catalog
clearcutt-verify catalog site scaffold --catalog ./dist/catalog --output ./clearcutt-catalog-site
clearcutt-verify catalog site build --catalog ./dist/catalog --output ./dist/site
```

The scaffold command copies the Astro site and the catalog data you pass with
`--catalog`. The build command emits static HTML that can be deployed to GitHub
Pages or any static host.

Use `catalog generate --include-services` when the generated site should show
service image records such as Postgres, Valkey, and oauth2-proxy. The committed
`cli/internal/testdata/mixed-catalog` fixture can be used to preview mixed
runtime and service rendering without waiting for a release.

## Customize

Edit `clearcutt.site.yaml` to customize branding and behavior:

- `site.title`, `site.description`, and `site.logo` set the catalog identity.
- `site.theme.mode` and `site.theme.accent` set the theme preference and accent color.
- `site.navigation` toggles the home, getting started, operator, CLI, and audit nav links.
- `site.features` toggles SBOMs, vulnerabilities, layers, provenance, OCI labels, release history, and Kyverno policy examples.
- `site.terminology` renames tier labels such as distroless, slim, and dev.
- `site.links` adds source repository, registry, support, and docs links.
- `site.home` customizes homepage title, notice, quick links, persona workflow sections, and per-step CTA labels.

Use `--site-config ./clearcutt.site.yaml` when scaffolding, building, or
previewing to copy an external config into the generated project.

## Override Content

Pass `--overrides ./site-overrides` to copy targeted customizations without
forking ClearCutt:

```text
site-overrides/
  components/  -> src/components/
  pages/       -> src/pages/
  styles/      -> src/styles/
  public/      -> public/
```

Markdown page overrides automatically use the default site layout when no layout
frontmatter is provided. Page overrides also replace conflicting Astro,
Markdown, or MDX routes with the same path.

Common override examples:

- `site-overrides/pages/index.md` replaces homepage prose.
- `site-overrides/styles/theme.css` adds custom CSS.
- `site-overrides/public/branding/logo.svg` adds a logo referenced by `site.logo`.
- `site-overrides/components/ImageHeader.astro` replaces the image detail header.

---
name: clearcutt-site-qa
description: Use for ClearCutt Astro catalog site, generated site template, visual QA, copy QA, catalog evidence UX, responsive layout, or site-config driven customization work.
---

# ClearCutt Site QA

Use this skill for `site/` and embedded catalog-site template work.

## Contract

- Treat the site as an evidence-oriented catalog/operator portal, not generic marketing.
- Keep customization config-driven through `clearcutt.site.yaml` and `site/src/lib/site-config.ts` when possible.
- Keep `site/` and `cli/internal/sitetemplate/template/` behavior aligned when changes affect scaffolded sites.
- Do not make incomplete/demo data look production-real.
- Treat `site/src/data/catalog` as ignored generated state that may be stale.
  Inspect its `index.json` before relying on it.
- For visual work, use the Browser plugin or another rendered browser check when available.

## Workflow

1. Inspect the current route/component/data boundary:
   - `site/src/pages/`
   - `site/src/components/`
   - `site/src/lib/catalog.ts`
   - `site/src/lib/site-config.ts`
   - `cli/internal/sitetemplate/template/`
2. Check whether the same change belongs in both live site source and the embedded template.
3. Prefer concise content changes that preserve conservative claims.
4. For rendered QA, start the dev server or use a built preview, then inspect desktop and mobile states.
5. Check catalog fixture, generated catalog, and missing-catalog states when the change affects data loading.

## Validation

```bash
cd site && npm run typecheck
cd site && npm run build
git diff --check
```

For reproducible rendered validation, prefer a fixture-backed build that does
not depend on stale local site data:

```bash
cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify
./clearcutt-verify catalog site build --catalog cli/internal/testdata/mixed-catalog --template site --output /tmp/clearcutt-site --install --clean
```

When the generated template changes, also validate the scaffold/build path or at least inspect the matching template files.

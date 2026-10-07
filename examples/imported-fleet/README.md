# Imported Fleet Example

This example works offline. It shows the principle that ClearCutt does not need to create an image to govern it.

```bash
rm -rf /tmp/clearcutt-import
mkdir -p /tmp/clearcutt-import

clearcutt-verify import images \
  --refs examples/imported-fleet/refs.txt \
  --output /tmp/clearcutt-import/images.yaml \
  --owner acme \
  --repo imported-fleet \
  --registry-base registry.acme.dev/platform \
  --generated-at 2026-01-01T00:00:00Z \
  --force

clearcutt-verify catalog generate \
  --images /tmp/clearcutt-import/images.yaml \
  --output /tmp/clearcutt-import/catalog \
  --owner acme \
  --repo imported-fleet \
  --registry-base registry.acme.dev/platform

clearcutt-verify --catalog /tmp/clearcutt-import/catalog catalog validate

clearcutt-verify import observe \
  --images /tmp/clearcutt-import/images.yaml \
  --offline-fixtures examples/imported-fleet/observations.fixture.json \
  --output /tmp/clearcutt-import/observations.json \
  --generated-at 2026-01-01T00:00:00Z

clearcutt-verify import assess \
  --images /tmp/clearcutt-import/images.yaml \
  --observations /tmp/clearcutt-import/observations.json \
  --catalog /tmp/clearcutt-import/catalog \
  --output /tmp/clearcutt-import/governance

clearcutt-verify import report \
  --assessment /tmp/clearcutt-import/governance \
  --output /tmp/clearcutt-import/imported-fleet-report.md

clearcutt-verify rebase discover \
  --apps examples/imported-fleet/apps.yaml \
  --bases /tmp/clearcutt-import/images.yaml \
  --observations /tmp/clearcutt-import/observations.json \
  --output /tmp/clearcutt-import/rebase-candidates.json
```

The fixture intentionally leaves one imported image unresolved and records missing provenance for every imported base. Missing evidence is a governance gap, not a claim that an image is insecure.

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

clearcutt-verify import observe \
  --images /tmp/clearcutt-import/images.yaml \
  --offline-fixtures examples/imported-fleet/observations.fixture.json \
  --output /tmp/clearcutt-import/observations.json \
  --generated-at 2026-01-01T00:00:00Z

clearcutt-verify import assess \
  --images /tmp/clearcutt-import/images.yaml \
  --observations /tmp/clearcutt-import/observations.json \
  --output /tmp/clearcutt-import/governance

clearcutt-verify import report \
  --assessment /tmp/clearcutt-import/governance \
  --output /tmp/clearcutt-import/imported-fleet-report.md

clearcutt-verify graph build \
  --observations /tmp/clearcutt-import/observations.json \
  --output /tmp/clearcutt-import/graph.json --report /tmp/clearcutt-import/inventory.md
```

The fixture intentionally leaves one imported image unresolved and records missing provenance for every imported base. Missing evidence is a governance gap, not a claim that an image is insecure.

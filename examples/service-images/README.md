# Service Images Example

This example shows the first-class ClearCutt service image flow for Postgres,
Valkey, and oauth2-proxy.

```bash
clearcutt-verify service scaffold postgres16 --template postgres --version 16
clearcutt-verify service scaffold valkey8 --template valkey --version 8
clearcutt-verify service scaffold oauth2-proxy7 --template oauth2-proxy --version 7

clearcutt-verify service validate --all
clearcutt-verify service build postgres16 --system x86_64-linux
clearcutt-verify service smoke postgres16 --engine docker

clearcutt-verify catalog generate \
  --config clearcutt.fleet.yaml \
  --include-services \
  --output dist/catalog

clearcutt-verify --catalog dist/catalog catalog validate
clearcutt-verify catalog site build --catalog dist/catalog --output dist/site
```

The service entries are intentionally `preview` and
`productionAllowed: false`. Promote them after your organization has validated
runtime flags, storage policy, backup/restore posture, and release evidence.

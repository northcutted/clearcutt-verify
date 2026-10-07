# ClearCutt Docker Compose App Deployment Example

This example runs an application image built from a ClearCutt base image. It is
not a base-image deployment example.

The compose file builds `ghcr.io/acme/payments-api:1.0.0` from the Java app
template, runs it as UID/GID `10001`, drops Linux capabilities, mounts the root
filesystem read-only, and keeps writable scratch data in `/tmp`.

## Build and certify the app image

```bash
cd examples/oci-deployment
APP_IMAGE=ghcr.io/acme/payments-api:1.0.0
docker compose build
docker push "$APP_IMAGE"
APP_DIGEST=$(docker buildx imagetools inspect "$APP_IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"')
docker save "$APP_IMAGE" -o payments-api.tar
clearcutt-verify certify payments-api.tar \
  --base java21-distroless \
  --policy ../clearcutt-template-java/certification-policy.yaml \
  --image-ref "${APP_IMAGE%:*}@${APP_DIGEST}"
```

The generated policy requires a digest-pinned image ref. For production, deploy
the same immutable digest ref that certification checked.

## Run the local deployment

```bash
docker compose up -d
docker compose exec payments-api id
docker compose exec payments-api sh -lc 'touch /test'
```

The final command should fail if the image has no shell or if the read-only root
filesystem blocks the write. Either result is useful: it confirms the runtime is
not behaving like a writable general-purpose container.

## What this example proves

- App teams can build an application image from a ClearCutt base without
  learning Nix.
- The resulting image can be checked with `clearcutt-verify certify` before deployment.
- Compose hardening is separate from catalog trust. Runtime settings reduce
  process privileges, while signatures, SBOMs, provenance, scans, and
  certification policy are inspected through ClearCutt evidence paths.

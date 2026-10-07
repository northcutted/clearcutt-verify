# clearcutt-template-go

This starter app is the app-team path for one ClearCutt runtime line. It keeps
Nix in the platform fleet and uses normal container tooling for application
delivery.

- build stage: ghcr.io/northcutted/clearcutt/clearcutt-go1.25:dev
- runtime stage: ghcr.io/northcutted/clearcutt/clearcutt-go1.25:distroless
- ClearCutt CLI release: northcutted/clearcutt-verify@v0.17.0 (checksum and Sigstore bundle verified in CI)
- base id for policy/rebase: go1.25-distroless

## Local path

The generated policy requires a digest-pinned image reference. Push the image,
resolve the registry digest, and pass that immutable ref to certification:

~~~bash
APP_IMAGE=ghcr.io/acme/clearcutt-template-go:1.0.0
docker build -t "$APP_IMAGE" .
docker push "$APP_IMAGE"
APP_DIGEST=$(docker buildx imagetools inspect "$APP_IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"')
docker save "$APP_IMAGE" -o clearcutt-template-go.tar
clearcutt-verify certify clearcutt-template-go.tar --base go1.25-distroless --policy certification-policy.yaml --image-ref "${APP_IMAGE%:*}@${APP_DIGEST}"
~~~

Open this repository in a devcontainer to build with the matching ClearCutt dev
image, then ship the final app image from the runtime stage.

## CI path

The release workflow builds, signs, attests, and certifies the image. The rebase
workflow lets a platform workflow move the app layer onto a patched ClearCutt
base without recompiling the application.
These are starter workflows; fork owners must pin identities, registry
permissions, branch policy, and admission rules before production use.

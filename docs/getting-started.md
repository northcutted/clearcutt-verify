# App-Team Getting Started

This guide is for application developers consuming a ClearCutt fleet. You do
not need Nix to choose an image, generate a starter, build an app container, or
certify it locally.

If you review trust evidence, start with
[`trust/evidence-walkthrough.md`](trust/evidence-walkthrough.md).

## 1. Prove The CLI Path From A Clean Clone

Use the committed catalog fixture before your organization publishes its own
catalog data:

```bash
go -C cli build -o ../clearcutt-verify ./cmd/clearcutt-verify
./clearcutt-verify --catalog cli/internal/testdata/catalog list
./clearcutt-verify --catalog cli/internal/testdata/catalog inspect java21-distroless
./clearcutt-verify --catalog cli/internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --max-critical 0 \
  --max-high 3 \
  --allow-preview
```

`verify image` is a catalog policy gate. It checks recorded catalog evidence,
smoke tests, lifecycle state, and vulnerability thresholds. It is not a live
registry-side cryptographic verification.

## 2. Choose A Runtime And Tier

ClearCutt publishes three runtime tiers:

| Tier | Use it for | Avoid it for |
| --- | --- | --- |
| `dev` | Local development, CI build stages, compilers, package managers, and shells. | Production runtime. |
| `slim` | Runtime workloads that need a diagnostic shell. | Shell-free production policy. |
| `distroless` | Production-oriented runtime images without shells or package managers. | Debugging inside the final image. |

Use catalog inspection to pick the base id:

```bash
./clearcutt-verify --catalog cli/internal/testdata/catalog inspect java21-distroless
```

## 3. Generate A Starter App

Build the CLI, then scaffold an app starter with Dockerfile, devcontainer,
certification policy, release workflow, and rebase workflow:

```bash
```

The generated README explains the chosen build tier, runtime tier, certification
policy, and rebase path.

## 4. Open The Devcontainer Or Run The Dev Image

The generated starter includes `.devcontainer/devcontainer.json` pinned to the
matching ClearCutt `dev` image. You can also generate one directly:

The first command below is fixture-backed and prints the devcontainer JSON
without writing into the checkout. The container command requires Docker,
Podman, or another engine that can pull the configured dev image.

```bash
./clearcutt-verify --catalog cli/internal/testdata/dev-catalog dev java21-distroless --devcontainer --print
./clearcutt-verify --catalog cli/internal/testdata/dev-catalog dev java21-distroless --container --engine docker --command 'java -version'
```

The dev tier gives app teams build tools without making them install Nix.

## 5. Build And Certify The App Image

Use the generated Dockerfile or your existing build to produce an app image.
The generated policy requires a digest-pinned image ref, so push the image,
resolve its registry digest, then certify the archived image with `--image-ref`:

```bash
docker build -t ghcr.io/acme/payments-api:1.0.0 examples/my-java-service
docker push ghcr.io/acme/payments-api:1.0.0
APP_DIGEST=$(docker buildx imagetools inspect ghcr.io/acme/payments-api:1.0.0 \
  --format '{{json .Manifest.Digest}}' | tr -d '"')
docker save ghcr.io/acme/payments-api:1.0.0 -o payments-api.tar

./clearcutt-verify certify payments-api.tar \
  --base java21-distroless \
  --policy examples/my-java-service/certification-policy.yaml \
  --image-ref "ghcr.io/acme/payments-api@${APP_DIGEST}"
```

Certification checks the downstream image against your local hardening policy:
known base, digest pinning, shell/package-manager restrictions, non-root
requirements, and vulnerability thresholds.

## 6. Hand Evidence To CI

The generated release workflow builds, pushes, signs, attests, and runs the
certification action:

```bash
sed -n '1,140p' examples/my-java-service/.github/workflows/release.yml
```

Treat the generated workflows as starters. Fork owners still need to pin signer
identities, registry permissions, branch policy, and admission rules before
production use.

For app images that support the rebase contract, the generated rebase workflow
shows the separate trust boundary: developer workflow signs the original app
image; platform rebase workflow verifies that signature, swaps compatible base
layers, signs the rebased result, and attaches a rebase attestation.

## 7. Pin The Base Image Digest Before Production

The scaffolded Dockerfiles intentionally start on mutable tags (`:dev`,
`:distroless`) to keep the inner development loop fast. Before a production
build, switch the runtime `FROM` line to an immutable digest pin — that is the
required production posture ([ADR #2](decisions.md)). Catalog records carry the
released manifest digest (`latestManifestDigest`), and `inspect` prints it as
the `Digest Reference:` line:

```bash
./clearcutt-verify --catalog cli/internal/testdata/catalog inspect java21-distroless
# Digest Reference:   ghcr.io/northcutted/clearcutt/clearcutt-java21@sha256:...
```

Copy that digest-pinned reference into the runtime stage of your Dockerfile:

```dockerfile
FROM ghcr.io/northcutted/clearcutt/clearcutt-java21@sha256:<digest>
```

Mutable tags stay convenient for local iteration; the digest pin is what
production deployments, `clearcutt-verify certify`, and admission policy key on.

## Manual Dockerfile Fallback

If the app template does not fit your stack, keep the same tier pattern:

```dockerfile
FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:dev AS builder
WORKDIR /workspace
COPY . .
RUN ./mvnw -DskipTests package

FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless
WORKDIR /workspace
COPY --from=builder /workspace/target/app.jar /workspace/app.jar
USER 10001:10001
ENTRYPOINT ["java", "-jar", "/workspace/app.jar"]
```

Use JSON exec form for `ENTRYPOINT` and `CMD`. The `distroless` tier has no
shell, so shell-form commands fail by design.

## More App Paths

- [App lifecycle](app-lifecycle.md) covers app build, diff-base, rebase, and
  attestation examples across supported stacks.
- [Certification](certification.md) covers local app-image checks.
- [Catalog evidence](trust/catalog-evidence.md) explains what image detail pages
  report and what still needs registry-side verification.

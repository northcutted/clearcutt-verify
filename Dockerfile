# ClearCutt governance CI image.
#
# This is the whole control plane. Point it at a registry, give it a config, and
# it runs anywhere that can run a container — GitHub Actions, GitLab CI, Jenkins,
# Tekton, a cron on a box. There is nothing to bootstrap per platform, because
# the storage plane is the registry and the declaration is a file.
#
# It is deliberately built with Docker rather than with this project's own Nix
# factory. The image whose purpose is to remove a platform dependency must not
# require Nix to build, or the dependency has just moved. Anyone with a container
# builder can produce this; the Nix factory remains for building base images,
# which is a different job.
#
# No Nix inside either: the governance path — registry scan, import observe,
# graph, estate, evidence, certify, scan — is pure Go and needs none. Only the
# image factory does, and that is a separate concern with a separate image.

FROM golang:1.26-bookworm AS build
WORKDIR /src

# Module graph first, so dependency downloads cache independently of source edits.
COPY go.work go.work.sum* ./
COPY cli/go.mod cli/go.sum ./cli/
RUN --mount=type=cache,target=/go/pkg/mod go mod download -C cli

COPY . .

# CGO off so the result is a static binary that runs on a scratch-like base.
# Trimpath and an empty build id keep the binary reproducible between builds of
# the same source, which matters for a tool that argues for reproducibility.
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -C cli \
      -trimpath \
      -ldflags "-s -w -buildid= -X github.com/northcutted/clearcutt-verify/internal/commands.Version=${VERSION}" \
      -o /out/clearcutt ./cmd/clearcutt-verify

# distroless/static carries CA certificates — required to speak TLS to a
# registry — and nothing else. No shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/clearcutt /usr/local/bin/clearcutt

LABEL org.opencontainers.image.title="clearcutt" \
      org.opencontainers.image.description="Govern container image estates on any OCI registry" \
      org.opencontainers.image.source="https://github.com/northcutted/clearcutt-verify" \
      org.opencontainers.image.licenses="Apache-2.0"

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/clearcutt"]

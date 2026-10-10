# ClearCutt Verify CI image.
#
# Point it at a registry, give it a policy, and it runs anywhere that can run a
# container: GitHub Actions, GitLab CI, Jenkins, Tekton, a cron on a box. There
# is nothing to bootstrap per platform, because the storage plane is the
# registry and the declaration is a file. It is pure Go; nothing inside needs
# Nix.
#
#   docker build -t clearcutt-verify .

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
      -o /out/clearcutt-verify ./cmd/clearcutt-verify

# distroless/static carries CA certificates — required to speak TLS to a
# registry — and nothing else. No shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/clearcutt-verify /usr/local/bin/clearcutt-verify

LABEL org.opencontainers.image.title="clearcutt-verify" \
      org.opencontainers.image.description="Govern container image estates on any OCI registry" \
      org.opencontainers.image.source="https://github.com/northcutted/clearcutt-verify" \
      org.opencontainers.image.licenses="Apache-2.0"

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/clearcutt-verify"]

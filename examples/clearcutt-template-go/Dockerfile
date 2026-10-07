# ---------------------------------------------------------------------------
# PIN YOUR BASE BEFORE PRODUCTION
#
# The FROM lines below use mutable tags (:dev, :distroless) so the scaffold
# and inner development loop stay fast. Per docs/decisions.md ADR #2, the
# required production posture is an immutable digest pin. Resolve the digest
# recorded in the catalog (latestManifestDigest):
#
#   clearcutt-verify inspect go1.25-distroless   # copy the "Digest Reference:" line
#
# then replace the runtime FROM with the digest-pinned form:
#
#   FROM ghcr.io/northcutted/clearcutt/clearcutt-go1.25@sha256:<digest>
# ---------------------------------------------------------------------------
FROM ghcr.io/northcutted/clearcutt/clearcutt-go1.25:dev AS builder
WORKDIR /workspace
COPY go.mod .
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /workspace/app ./cmd/app

FROM ghcr.io/northcutted/clearcutt/clearcutt-go1.25:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="go1.25-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/app /workspace/app
ENTRYPOINT ["/workspace/app"]

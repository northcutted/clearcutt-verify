# ---------------------------------------------------------------------------
# PIN YOUR BASE BEFORE PRODUCTION
#
# The FROM lines below use mutable tags (:dev, :distroless) so the scaffold
# and inner development loop stay fast. Per docs/decisions.md ADR #2, the
# required production posture is an immutable digest pin. Resolve the digest
# recorded in the catalog (latestManifestDigest):
#
#   clearcutt-verify inspect node22-distroless   # copy the "Digest Reference:" line
#
# then replace the runtime FROM with the digest-pinned form:
#
#   FROM ghcr.io/northcutted/clearcutt/clearcutt-node22@sha256:<digest>
# ---------------------------------------------------------------------------
FROM ghcr.io/northcutted/clearcutt/clearcutt-node22:dev AS builder
WORKDIR /workspace
COPY package.json .
COPY src ./src
RUN npm test && npm run build

FROM ghcr.io/northcutted/clearcutt/clearcutt-node22:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="node22-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/dist/server.js /workspace/server.js
ENTRYPOINT ["node","/workspace/server.js"]

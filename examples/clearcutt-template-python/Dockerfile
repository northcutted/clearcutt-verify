# ---------------------------------------------------------------------------
# PIN YOUR BASE BEFORE PRODUCTION
#
# The FROM lines below use mutable tags (:dev, :distroless) so the scaffold
# and inner development loop stay fast. Per docs/decisions.md ADR #2, the
# required production posture is an immutable digest pin. Resolve the digest
# recorded in the catalog (latestManifestDigest):
#
#   clearcutt-verify inspect python3.14-distroless   # copy the "Digest Reference:" line
#
# then replace the runtime FROM with the digest-pinned form:
#
#   FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.14@sha256:<digest>
# ---------------------------------------------------------------------------
FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.14:dev AS builder
WORKDIR /workspace
COPY requirements.txt .
COPY app ./app
RUN python -m compileall app

FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.14:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="python3.14-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/app /workspace/app
ENTRYPOINT ["python","/workspace/app/main.py"]

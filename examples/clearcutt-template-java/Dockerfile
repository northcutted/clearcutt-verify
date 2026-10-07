# ---------------------------------------------------------------------------
# PIN YOUR BASE BEFORE PRODUCTION
#
# The FROM lines below use mutable tags (:dev, :distroless) so the scaffold
# and inner development loop stay fast. Per docs/decisions.md ADR #2, the
# required production posture is an immutable digest pin. Resolve the digest
# recorded in the catalog (latestManifestDigest):
#
#   clearcutt-verify inspect java21-distroless   # copy the "Digest Reference:" line
#
# then replace the runtime FROM with the digest-pinned form:
#
#   FROM ghcr.io/northcutted/clearcutt/clearcutt-java21@sha256:<digest>
# ---------------------------------------------------------------------------
FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:dev AS builder
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B package

FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless
LABEL org.opencontainers.image.source="https://github.com/example/app" \
      org.clearcutt.base="java21-distroless"
WORKDIR /workspace
COPY --from=builder /workspace/target/app.jar /workspace/app.jar
ENTRYPOINT ["java","-jar","/workspace/app.jar"]

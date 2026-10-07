# Layering ClearCutt onto a Mandated Base Image

ClearCutt's published images are built **from scratch** — a pure `/nix/store`
closure plus CA certificates and a rootless account. That is what lets the
`distroless` tier be genuinely shell-less and minimal, and it's the recommended
target if you're free to choose your base.

But plenty of platform teams operate under a **base-image mandate**: every
container *must* derive from a sanctioned Amazon Linux 2023, Red Hat UBI, or
Ubuntu Pro image — usually because that base carries a required monitoring
agent, an endpoint-security daemon, or a centrally-tracked CVE baseline.

This example shows the two ways to adopt ClearCutt under that constraint.

---

## Path A — Graft the runtime onto your mandated base (no migration)

A ClearCutt runtime is a self-contained, `RPATH`/`RUNPATH`-bound `/nix/store`
closure. The graft is declared in [`flake.nix`](./flake.nix), which passes the
mandated base image into `clearcutt.lib.graftOntoBase`:

```nix
overlayImage = clearcutt.lib.graftOntoBase {
  inherit system;
  fromImage = mandatedBase;
  runtime = "java21";
  tier = "distroless";
  name = "acme-java21-ubi";
  tag = "latest";
};
```

Before building, replace the placeholder base digest and Nix fetch hash in
`flake.nix`. Then build the grafted image archive:

```bash
nix build .#packages.x86_64-linux.overlayImage
```

Generate the offline closure-equivalence predicate before promotion:

```bash
clearcutt-verify overlay verify \
  --runtime-archive clearcutt-runtime.tar \
  --grafted-archive result \
  --runtime-ref ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless@sha256:<runtime-digest> \
  --grafted-ref ghcr.io/acme/java21-ubi:latest@sha256:<grafted-digest> \
  --target java21-distroless \
  --output-predicate > closure-equivalence.intoto.json
```

The predicate type is
`https://clearcutt.dev/attestations/closure-equivalence/v1`. It proves the
materialized `/nix/store` runtime bytes in the grafted image match the source
ClearCutt runtime archive. It does not prove anything about the inherited base
OS layer.

> [!IMPORTANT]
> **Honest trade-off.** Path A keeps your mandated base, so you also keep that
> base's attack surface: its shell, coreutils, package manager, and whatever
> CVEs ride along with them. You get ClearCutt's reproducible, RPATH-isolated
> runtime, but **not** the distroless zero-utility guarantee. Use the catalog
> site to compare the resulting CVE posture against the from-scratch images.

> [!NOTE]
> **Updating runtimes independently of the OS.** Because the runtime is declared
> as a ClearCutt runtime line, you bump the language version by changing
> `runtime` or `tier` in `flake.nix` and rebuilding. The mandated base layer
> and its agents can remain fixed.

---

## Path B — Migrate to the from-scratch ClearCutt images

If the mandate is negotiable, deriving directly from a ClearCutt image gives
you the full hardening story (shell-less distroless, minimal closure, signed +
attested provenance). This is the same pattern as
[`examples/clearcutt-template-java`](../clearcutt-template-java):

```dockerfile
FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:dev AS builder
WORKDIR /workspace
COPY . .
RUN mvn clean package

FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless@sha256:<pin>
COPY --from=builder /workspace/target/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
```

---

## Which should I use?

| | Path A — overlay on mandated base | Path B — migrate to from-scratch |
| :--- | :--- | :--- |
| Base OS mandate | **Satisfied** (keeps sanctioned base) | Requires exception / waiver |
| Monitoring/security agents in base | Preserved | Re-attach separately |
| Attack surface | Base OS + runtime | Runtime only (smallest) |
| Distroless zero-utility guarantee | No, inherits base shell/utils | Yes |
| Runtime updates without OS change | Yes, rebuild grafted runtime closure | Yes, use a new tag |
| Recommended when | You can't change the base today | You want maximum hardening |

Path A is the low-friction on-ramp; Path B is the destination. Many teams start
with A to prove the runtime works under their controls, then graduate to B
tier-by-tier as base mandates are relaxed.

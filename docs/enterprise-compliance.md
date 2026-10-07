# Enterprise Compliance Layering

> **Status note.** The `clearcutt-verify overlay generate` and `clearcutt-verify overlay
> verify` CLI commands were removed along with the CVE remediation subsystem.
> The Nix mechanism this page describes is unchanged and still exported as
> `clearcutt.lib.graftOntoBase` from `core/flake.nix`, so the grafting pattern
> works. What no longer ships is the CLI wrapper and the generated
> closure-equivalence in-toto predicate; comparing the two `/nix/store` closures
> is now something you script yourself.


Some enterprises require every workload image to inherit from a certified
operating-system baseline such as Red Hat UBI, Ubuntu Pro, SLES, or Amazon Linux
2023. ClearCutt supports that adoption path without pretending the resulting
image is native ClearCutt distroless.

The trade-off is explicit: the final image inherits the mandated base image's
shell, package manager, libraries, and CVE footprint. The ClearCutt claim is
narrower and stronger: the language runtime closure under `/nix/store` can be
compiled through the same Nix path as the native image and verified offline
against that native runtime closure.

## First-Class Graft Function

Use `clearcutt.lib.graftOntoBase` instead of copying `/nix` with a Dockerfile.
The helper wraps `dockerTools.buildLayeredImage` with `fromImage`, so the runtime
closure stays under the ClearCutt compiler path while the base comes from your
mandated source.

```nix
{
  description = "ClearCutt Java 21 graft on mandated UBI 9";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    clearcutt.url = "github:northcutted/clearcutt-verify?dir=core";
  };

  outputs = { self, nixpkgs, clearcutt }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          mandatedBase = pkgs.dockerTools.pullImage {
            imageName = "registry.access.redhat.com/ubi9/ubi-minimal";
            imageDigest = "sha256:73922c2a93268c12bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74";
            sha256 = "sha256-REPLACE_WITH_NIX_PREFETCH_DOCKER_HASH";
          };
        in {
          overlayImage = clearcutt.lib.graftOntoBase {
            inherit system;
            fromImage = mandatedBase;
            runtime = "java21";
            tier = "slim";
            name = "clearcutt-java21-ubi";
            tag = "v1";
          };
        });
    };
}
```

For Ubuntu, Amazon Linux, SLES, or another baseline, change only the
`dockerTools.pullImage` input and output name. The runtime selection stays on
the ClearCutt runtime line, for example `runtime = "node22"`,
`runtime = "python3.14"`, or `runtime = "go1.26"`.

## Closure-Equivalence Predicate

After building a native ClearCutt runtime archive and the grafted archive, emit
an offline in-toto predicate proving the `/nix/store` closure bytes match:

```bash
# REMOVED COMMAND - kept to document the closure-equivalence check it performed.
clearcutt-verify overlay verify \
  --runtime-archive clearcutt-java21-slim.tar \
  --grafted-archive result \
  --runtime-ref ghcr.io/acme/clearcutt/clearcutt-java21:v1-slim@sha256:... \
  --grafted-ref ghcr.io/acme/clearcutt-java21-ubi:v1@sha256:... \
  --target java21-slim \
  --output-predicate > closure-equivalence.intoto.json
```

The predicate type is
`https://clearcutt.dev/attestations/closure-equivalence/v1`. It does not claim
the corporate base is distroless or CVE-free. It claims one falsifiable thing:
the ClearCutt runtime closure inside the grafted image is byte-for-byte
equivalent to the source runtime closure. The in-toto subjects are the
digest-pinned source runtime image and final grafted image.

## Admission Use

Treat the closure-equivalence predicate as one input to admission policy:

- Verify the grafted image signature against the platform workflow identity.
- Verify the closure-equivalence predicate for the grafted image digest.
- Keep normal vulnerability scanning and patch governance on the mandated base.
- Do not apply native ClearCutt distroless guarantees to BYO-base overlays.

# Fixture: ghcr.io/northcutted/images

A real estate report: the [clearcutt-factory](https://github.com/northcutted/clearcutt-factory)
example fleet (`platform-tools`, `debian-tools`, `amazonlinux-tools`,
`hello-app`) and the bases it builds on, from Chainguard and Docker Hub.

Generated with [`policy.yaml`](policy.yaml) and [`refs.txt`](refs.txt):

```bash
clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name northcutted-images \
  --platforms linux/amd64,linux/arm64 --reproduce --out .
```

What it shows:

- The four factory images are `verified`. Their signature, SBOM,
  vulnerability scan, SLSA provenance, and recipe are all verified against
  the factory's signer, which is bound to runs in the clearcutt-factory
  repository. Each image also rebuilt from its recipe to the same digest.
- Every base is proven by layer digest. `debian-tools` is 17 days behind
  `debian:trixie-slim` and `platform-tools` 3 days behind `wolfi-base`.
- The Chainguard images verify against Chainguard's signer, but are
  `unverified` because they carry no vulnerability attestation the policy can
  read.
- The Docker Hub images are `failed`: they carry no signature, SBOM, or
  provenance.

Regenerating it changes digests, dates, and findings as the fleet moves.

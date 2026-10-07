# Trust-Preserving Registry Mirroring

Enterprise platform teams often consume base images from behind a private registry proxy. 

This document explains how to mirror ClearCutt images into internal registries while preserving supply-chain trust evidence (signatures, SBOMs, and SLSA provenance).

---

## 1. Preserving referrers
OCI signatures and SBOMs are stored alongside container images as OCI referrers (e.g., using `org.cncf.oras.artifact` or Cosign tag mappings). 

Simple tag copies (e.g. `docker pull` followed by `docker push`) **do not** transfer these referrers. A standard tag copy discards the signature referrers and breaks downstream admission control gates.

---

## 2. Multi-Arch Mirror Workflow
To preserve referrers and signatures during replication:
1. **Skopeo Copy**: Use `skopeo copy --all` to duplicate the multi-architecture manifest list. This ensures every platform layer remains intact.
2. **Cosign Copy**: Use `cosign copy` to duplicate the cryptographic signatures and SBOM referrers.

---

## 3. CLI Mirror Script Generation
Generate operational mirror scripts dynamically:
```bash
clearcutt-verify mirror java25-distroless \
  --target artifactory.acme.internal/docker-mirror \
  --output mirror-script.sh
```

### Verification in Private Registries
After mirroring, generate a verification script that compares the source and the
mirrored target. `mirror verify` performs no network calls itself — it emits a
script you run where you have registry access:
```bash
clearcutt-verify mirror verify \
  --source ghcr.io/northcutted/clearcutt/clearcutt-java25@sha256:... \
  --target artifactory.acme.internal/docker-mirror/clearcutt-java25@sha256:... \
  --output verify-mirror.sh
bash verify-mirror.sh   # requires cosign, oras, crane, jq
```
The generated script checks that the digests match, that referrer counts
(signatures, SBOMs, provenance) were preserved, and that the target signature
still verifies. Pin the `--certificate-identity`/`--certificate-oidc-issuer`
values in the script to your build workflow before using it as a gate.

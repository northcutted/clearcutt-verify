# ClearCutt Verify Mental Model

ClearCutt Verify has one loop, and it does not require anyone to have built
the images with ClearCutt tools:

1. Enumerate a registry namespace into an inventory (`registry scan`), or list
   references by hand (`import images`).
2. Read each image's manifest, config, layers, and labels (`import observe`).
3. Derive which images are built on which and how stale each is (`graph build`),
   what the estate has in common (`graph layers`), and which images ship a
   package (`graph packages`).
4. Verify each image's signatures and attestations against a trust policy, and
   write the estate report (`estate verify`).
5. Act on it: gate CI on the verdicts (`estate verify --fail-on`), and wake the
   images built on a base that changed (`estate dependents`).
6. Keep the report and its history next to the images (`estate push`), for a
   portal to publish ([clearcutt-portal](https://github.com/northcutted/clearcutt-portal)).

## Where it sits in ClearCutt

| Tool | Job |
| --- | --- |
| [clearcutt-factory](https://github.com/northcutted/clearcutt-factory) | Builds images reproducibly from YAML, signs and attests them, and rebases apps onto patched bases. |
| clearcutt-verify | Checks an estate, whatever built it, and writes the estate report. |
| [clearcutt-portal](https://github.com/northcutted/clearcutt-portal) | Publishes the report as a website. |

The tools share data formats, not code: OCI annotations, Sigstore attestations,
the estate report ([contract](../../contract/README.md)), and one trust policy
(`kind: TrustPolicy`) that says whose signatures the organization accepts.

## Proof, claims, and unknowns

- A base relationship found by comparing layer digests is **proof**; one read
  from an `org.opencontainers.image.base.*` annotation is a **claim** its author
  made, and is checked against the layers before it counts.
- Evidence is **verified** only when cosign verified it against a trusted
  signer. Evidence found but not verified is **present**; evidence signed by
  someone else is **failed**.
- What couldn't be read is **unknown**, never zero and never a pass. An image
  whose requirements can't all be decided is **unverified**.

## Evidence channels

Signature, SBOM, vulnerability scan, provenance, recipe, rebase record, and test
results are reported independently. Do not treat one green signal as proof that
every channel is complete.

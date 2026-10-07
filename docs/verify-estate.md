# Verifying an estate

`clearcutt-verify estate verify` checks every image in an estate and writes the
**estate report**: what was found, what was proven, and what couldn't be
decided, per image and in total. It is the document
[clearcutt-portal](https://github.com/northcutted/clearcutt-portal) turns into
a website; the format is the contract in [`contract/`](../contract/README.md).

It works on images ClearCutt didn't build. Images built by
[clearcutt-factory](https://github.com/northcutted/clearcutt-factory) get more:
their recipes and rebase records are verified and read too.

```bash
clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out dist/estate
```

`refs.txt` lists image references, one per line. To reuse a scan, pass
`--observations dist/scan/observations.json` from `clearcutt-verify import observe`
instead.

## What it checks, per image

1. **Evidence in the registry.** Signatures and attestations stored by cosign
   v3 (Sigstore bundles as OCI referrers, including GitHub artifact
   attestations pushed to the registry), by cosign v2 (`sha256-<digest>.sig`
   and `.att` tags), and unsigned SBOMs attached as referrers. Bundles are
   decoded to learn what each one actually holds; cosign labels its own
   bundles as plain signatures.
2. **Verification.** Each piece of evidence is verified with cosign against
   the policy's trusted signers. Anything not signed by one of them is
   `failed`, never quietly accepted.
3. **Contents.** Vulnerability findings come from vulnerability attestations
   (deduplicated across platforms; VEX-suppressed findings are kept but not
   counted), packages from SBOM attestations, the source commit from verified
   SLSA provenance, and clearcutt-factory details from recipes and rebase
   records. A rebased image is named after the recipe of the image it was
   rebased from, found by following its verified rebase records back.
4. **Base.** Where the image's layers start with an observed image's layers,
   that is proof. For images whose base tag has moved on since they were
   built, the base the image names (its `org.opencontainers.image.base.*`
   annotations, or the base pinned in a verified clearcutt-factory recipe) is
   fetched and compared layer by layer, so the claim becomes proof or is
   rejected, and drift is measured against the base's current tag.
5. **Verdict.** `verified` when every requirement is met, `failed` when one
   isn't, `unverified` when one can't be decided (evidence that couldn't be
   read, or that no trusted signer could vouch for).

## The policy

```yaml
apiVersion: clearcutt.dev/v1
kind: VerificationPolicy
# Evidence an image needs, verified: signature, sbom, vulnerabilityScan,
# provenance, recipe (clearcutt-factory), tests.
required: [signature, sbom, provenance]
# Whose signatures count. Wildcard identities are refused.
trustedSigners:
  - identityRegexp: ^https://github\.com/acme/images/
    issuer: https://token.actions.githubusercontent.com
  - identityRegexp: ^https://github\.com/chainguard-images/images/
    issuer: https://token.actions.githubusercontent.com
failOn: critical      # vulnerabilities at or above this fail the image
onlyFixed: true       # ...counting only those with a fix
maxDaysBehind: 30     # a base more than 30 days behind its newest version fails
```

### Reusable workflows

A signature made in a reusable GitHub workflow (clearcutt-factory's
`images.yml` and `fleet.yml`, for instance) carries the identity of the called
workflow, which any repository can call. So trust in it should also say which
calling repositories count:

```yaml
trustedSigners:
  - identityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v0\.
    issuer: https://token.actions.githubusercontent.com
    sourceRepositoryOwner: https://github.com/acme   # runs in acme's repositories
    sourceMatchesImage: true    # ...in the repository the image names as its source
    sourceRef: refs/heads/main  # ...on main
```

`sourceRepository` names one repository exactly. Each constraint resolves to the
one repository the run must have been in, and cosign checks the certificate's
GitHub workflow repository against it (`--certificate-github-workflow-repository`).
Evidence signed by a reusable workflow with no caller constraint is reported
as `present`, not `verified`, with the repository it was called from. The
report records each signer's repository and ref (`signer.sourceRepository`,
`signer.sourceRef`).

With `maxDaysBehind`, an image whose base couldn't be placed is `unverified`:
it might be behind. Roots (images others are built on, with no base of their
own) are exempt.

Without a file, the same policy can be given with `--require`,
`--trusted-identity-regexp`, `--trusted-issuer`, `--vulnerabilities-fail-on`,
and `--only-fixed`.

## Output

`--out DIR` receives a bundle: `estate-report.json` and `estate-history.json`.
The history gains an entry per run; pass `--history` to extend a history kept
elsewhere. The command prints a summary table, and `--fail-on failed` (or
`unverified`) makes it exit 2 when any image falls short, for CI.

### Keeping reports in the registry

The registry that holds the images can hold their reports too, as an OCI
artifact (`clearcutt-verify estate push`). A scheduled job pulls the last bundle, so
the new run extends its history, verifies, and pushes the result:

```bash
clearcutt-verify estate pull ghcr.io/acme/estate:latest --output dist/estate || true  # nothing yet on the first run
clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out dist/estate
clearcutt-verify estate push ghcr.io/acme/estate:latest --dir dist/estate \
  --file estate-report.json --file estate-history.json \
  --generated-at "$(jq -r .metadata.generatedAt dist/estate/estate-report.json)"
```

A portal build pulls the same reference. The push prints the artifact's
digest; sign it (`cosign sign ghcr.io/acme/estate@sha256:…`) so readers can
tell the report came from your job.

## Reproducibility

`--reproduce` rebuilds every clearcutt-factory image from its verified recipe
(or repeats its verified rebase) with `clearcutt-factory verify --image`, and
records whether the digest matched. It needs `clearcutt-factory` on `PATH` (or
`--factory-path`) and a container runtime, and takes as long as the builds do.
Each rebuild works in its own directory under the user cache directory (on
macOS, `~/Library/Caches/clearcutt-verify/reproduce/`), which is kept with its
build log when the image doesn't reproduce.

A different digest is `not-reproduced` and fails the image. A rebuild that
couldn't finish (a registry or the container runtime failing) is
`not-checked`, with the reason, and leaves the image `unverified`: whether it
reproduces is still undecided. Without `--reproduce`, images with recipes are
`not-checked`.

## Limits

- **Registry rate limits.** Docker Hub limits anonymous manifest reads (100 an
  hour). A run reads each manifest once, but bases published for many
  architectures cost a read per platform image; `--platforms
  linux/amd64,linux/arm64` reads only those. Lookups the registry refuses are
  reported as `unknown`, not `missing`. Logging in (`docker login`) raises the
  limit; `clearcutt-verify` reads the same credentials.
- **Tests.** Test evidence counts only as a test-result attestation
  (`https://in-toto.io/attestation/test-result/…`).
- **Speed.** Each piece of evidence is one cosign verification; `--concurrency`
  bounds how many images are checked at once.

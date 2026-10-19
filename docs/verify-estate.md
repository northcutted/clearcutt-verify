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
   `failed`, never quietly accepted. Evidence cosign couldn't check (it
   couldn't reach the registry or the transparency log, the registry refused
   it, or cosign couldn't run) is `unknown`, not `failed`, and its `detail`
   says what went wrong; whether a trusted signer signed it is undecided.
   Before reading anything, the run checks that cosign is there and is cosign
   v3 (the version whose bundles and output it reads), and stops with exit 1
   if not. cosign is asked for exactly the signer
   the evidence's certificate names (its identity and issuer, and for GitHub
   Actions the repository and ref of the run), once a trusted signer accepts
   that signer, so the signer the report shows on verified evidence is the
   one cosign checked.
3. **Contents.** Only what cosign verified is read: vulnerability findings
   from verified vulnerability attestations (deduplicated across platforms;
   VEX-suppressed findings are kept but not counted; grype output only, for
   now, see Limits), packages from verified
   SBOM attestations, the source commit from verified SLSA provenance, and
   clearcutt-factory details from verified recipes and rebase records.
   Evidence that is `present` or `failed` is reported, but nothing in it is
   read or counted. Anyone who can push to a repository can attach more
   copies of a kind of evidence. Every copy whose certificate names a signer
   the policy accepts is verified, so a copy that doesn't verify never
   replaces or crowds out one that does, however new it claims to be or
   however many there are; copies holding content no trusted identity signed
   cost no cosign run. Among verified copies, the newest counts (for
   vulnerability scans, by the scan time inside the signed attestation), and
   the item's `detail` says how many others were ignored.
   A rebased image is named after the recipe of the image it was rebased
   from, found by following its verified rebase records back, and keeps that
   recipe's stack (the stack version its layers were built with).
4. **Base.** Where the image's layers start with an observed image's layers,
   that is proof. For images whose base tag has moved on since they were
   built, the base the image names (its `org.opencontainers.image.base.*`
   annotations, or the base pinned in a verified clearcutt-factory recipe) is
   fetched and compared layer by layer, so the claim becomes proof or is
   rejected, and drift is measured against the base's current tag.
5. **Verdict.** `verified` when every requirement is met, `failed` when one
   isn't, `unverified` when one can't be decided (evidence that couldn't be
   read, or that no trusted signer could vouch for). A `verified` verdict
   rests on evidence a trusted signer vouched for: with no trusted signers
   every image is `unverified`, and so is an image none of whose evidence
   verified, whatever else the policy checks. Checks that read no evidence
   (`maxDaysBehind`, `--reproduce`) can't verify an image on their own.
   Only `verified` evidence meets a requirement. A rebased image needs no
   recipe of its own (`recipe: not-applicable`) only when its rebase record
   is `verified`; a missing recipe beside a rebase record that is `present`
   or `unknown` leaves the image `unverified`, and beside one that `failed`,
   `failed`.

## The policy

```yaml
apiVersion: clearcutt.dev/v1
kind: VerificationPolicy
# Evidence an image needs, verified: signature, sbom, vulnerabilityScan,
# provenance, recipe (clearcutt-factory), tests.
required: [signature, sbom, provenance]
# Whose signatures count. Name each owner exactly and end it with / (write
# ^https://github\.com/acme/, not ^https://github\.com/acme, which matches
# acme-evil too). See "Identity checks" below for what is refused.
trustedSigners:
  - identityRegexp: ^https://github\.com/acme/images/
    issuer: https://token.actions.githubusercontent.com
  - identityRegexp: ^https://github\.com/chainguard-images/images/
    issuer: https://token.actions.githubusercontent.com
failOn: critical      # vulnerabilities at or above this fail the image
onlyFixed: true       # ...counting only those with a fix
maxDaysBehind: 30     # a base more than 30 days behind its newest version fails
maxScanAgeDays: 7     # a vulnerability scan older than 7 days leaves the image unverified
```

`failOn` counts only verified vulnerability scans. An image whose scan isn't
verified on every platform is `unverified` even when the scan says it is
clean: its vulnerabilities are unknown. `maxScanAgeDays` measures the oldest
platform's scan, so every platform must have been scanned recently, and an
image with no verified scan of every platform is `unverified` under it: there
is no age to measure.

### Identity checks

An `identityRegexp` must start with `^`. It is also refused when it matches an
identity it surely shouldn't: workflows of made-up owners on GitHub and
GitLab, and, for identities the expression itself matches, the same identity
with its owner (the first path segment, on any forge) swapped for a made-up
one, for one with something before or after it (`acme-evil`), or for one a
character off (an unescaped `.`), and email identities with their domain
extended. These probes catch the usual mistakes, not every over-broad
expression: write the narrowest one that works.

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
as `present`, not `verified`, with the repository it was called from; so is
GitHub Actions evidence whose certificate doesn't name the repository whose
run signed it. The
report records each signer's repository and ref (`signer.sourceRepository`,
`signer.sourceRef`).

### One trust policy for the organization

The trusted signers can live in their own file, a `TrustPolicy`
([schema](../contract/trust-policy.v1.schema.json)), which clearcutt-factory
reads too (`signing.trustPolicy`), so the organization says once whose
signatures count. Signers have roles: `image` (the default) signs images and
their attestations, `stack` signs clearcutt-factory stacks.

```yaml
apiVersion: clearcutt.dev/v1
kind: TrustPolicy
signers:
  - name: factory-builds
    identityRegexp: ^https://github\.com/northcutted/clearcutt-factory/\.github/workflows/(images|fleet)\.yml@refs/tags/v
    issuer: https://token.actions.githubusercontent.com
    sourceRepositoryOwner: https://github.com/acme
    sourceMatchesImage: true
  - name: platform-stacks
    roles: [stack]
    identity: https://github.com/acme/platform/.github/workflows/stacks.yml@refs/heads/main
    issuer: https://token.actions.githubusercontent.com
```

Name it from a verification policy (`trustPolicy: trust.yaml`, relative to the
policy) or pass `--trust-policy trust.yaml`; its image signers join the
policy's `trustedSigners`.

A signer's `key:` file is relative to the file that names it (the trust
policy, or the verification policy), as clearcutt-factory reads it, so cosign
and `--reproduce` find it wherever they run, and the report names the file
that was used. A cosign KMS URI (`awskms://…`, `pkcs11:…`) is used as written.

A key that signs without a transparency log (a private or offline Sigstore
setup, `--tlog-upload=false`) needs `tlog: false` on its signer:

```yaml
  - name: offline-key
    key: keys/images.pub
    tlog: false   # cosign --insecure-ignore-tlog, for this key only
```

Without it, its evidence is `failed`, and the detail says the transparency
log inclusion couldn't be verified (not that someone else signed it). With
it, cosign checks the signature but not the log for that key, so nothing shows
when the evidence was signed; verified evidence records `signer.tlog: false`.
Keyless signers can't set it: a certificate is valid only when the log shows
it was used in time. clearcutt-factory reads trust policies strictly, so a
shared one can use `tlog` once clearcutt-factory accepts the field too.
`--reproduce` passes `--insecure-ignore-tlog=true` to `clearcutt-factory
verify` for such a key, which needs a clearcutt-factory that accepts it.

With `maxDaysBehind`, an image whose base couldn't be placed is `unverified`:
it might be behind. So is one whose base is behind its newest version by an
unknown number of days (`base.daysBehindUnknown`: a creation time is missing,
or zeroed by a reproducible build). Roots (images others are built on, with no
base of their own) are exempt; an image that names a base in its annotations
or its recipe's lock is no root, and stays unresolved when that base can't be
shown.

Without a file, the same policy can be given with `--require`,
`--trusted-identity-regexp`, `--trusted-issuer`, `--vulnerabilities-fail-on`,
`--only-fixed`, and `--max-scan-age-days`.

## Output

`--out DIR` receives a bundle: `estate-report.json` and `estate-history.json`.
The history gains an entry per run; pass `--history` to extend a history kept
elsewhere. The command prints a summary table, and `--fail-on failed` (or
`unverified`) makes it exit 2 when any image falls short, for CI.

### Stacks

Apps that clearcutt-factory built on a registry stack (`stack:
ghcr.io/acme/stacks/go:1`) record the stack version their lock pins. The
report's `stacks` lists each such stack: the version its tag names now, every
version apps are pinned to, each version's signature verified against the
policy's stack signers (a trust policy's `stack` signers, or `stackSigners:`
in a VerificationPolicy), and how many apps are on an older version. Each app's
`factory.stackRef` and `factory.stackDigest` say which. A rebased app (the
fleet's steady state) is on the stack its original was built on: the verified
recipe of the image it was rebased from says which, reached through its
verified rebase record. A stack is a repository and a tag: apps on
`stacks/go:1` and `stacks/go:2` are on two stacks, each compared with its own
tag.

### Who is built on a base

`estate dependents` reads a report and lists the images built on a base
repository: the version each is on, how far behind it is, and the repository
each image was built from (from verified provenance where there was any, else
its label). A platform team's workflow uses it to wake exactly the repositories
a newly published base affects, for clearcutt-factory's `rebase` to move them.

```bash
clearcutt-verify estate dependents --report dist/estate/estate-report.json \
  --base ghcr.io/acme/platform/run-python --format json
```

Only relationships proven by layer digest count unless `--min-strength` says
otherwise; `--transitive` adds the images built on those images.

### Keeping reports in the registry

The registry that holds the images can hold their reports too, as an OCI
artifact (`clearcutt-verify estate push`). A scheduled job pulls the last bundle, so
the new run extends its history, verifies, and pushes the result:

```bash
clearcutt-verify estate pull ghcr.io/acme/estate:latest --output dist/estate --allow-missing  # nothing yet on the first run
clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out dist/estate
clearcutt-verify estate push ghcr.io/acme/estate:latest --dir dist/estate \
  --file estate-report.json --file estate-history.json \
  --generated-at "$(jq -r .metadata.generatedAt dist/estate/estate-report.json)"
```

`--allow-missing` succeeds only when the registry has no manifest at the
reference; any other failure fails, including a stored bundle whose files
can't be read, so a run never starts a fresh history and pushes it over one it
couldn't read. A portal build pulls the same reference. The push prints the
artifact's digest; sign it (`cosign sign ghcr.io/acme/estate@sha256:…`) so readers can
tell the report came from your job.

## Other fields readers use

- `base.platform` says which platform image `base.digest` names when it isn't
  the index the tag points at (a base an image claims is checked on one
  platform image), and `base.provenOn` which platform's layers were compared.
- `packagesSource` says where an image's packages were read from: its SBOM
  evidence, which platforms' verified SBOMs were read, and the SBOM evidence's
  status (anything but `verified` means some platform's packages are missing).
- `base.daysBehindUnknown` marks a stale base whose `daysBehind` couldn't be
  measured.
- Provenance from GitHub's `actions/attest-build-provenance`, pushed to the
  registry, is `source: github-attestation`, told by its verified content
  (SLSA provenance of GitHub's workflow build type); an unverified copy isn't
  read, so it shows as `cosign-attestation`. Verified evidence a GitHub
  Actions workflow signed records `signerWorkflow`, so a reader can offer
  `gh attestation verify oci://REPOSITORY@DIGEST --bundle-from-oci --repo
  OWNER/REPO --signer-workflow SIGNER_WORKFLOW`, with `--repo` from
  `signer.sourceRepository`.
- `tests` is `present` (source `recipe`) for clearcutt-factory images whose
  verified recipe declares a smoke test: factory runs it on every platform
  before pushing, but doesn't attest the result. A rebased image's stays
  `missing`: its rebase record doesn't say whether a smoke test ran
  (`rebase -f app.yaml` runs the app's; `rebase --image` and `--no-test`
  don't), and its `detail` names the test the original's recipe declares.
- Each history entry has a row per image (`images`): its digest, verdict, base,
  rebase, and vulnerability counts in that run, for per-image history. Rows
  also list the IDs of the image's fixable high and critical findings
  (`fixableFindings`) and a digest of its package set (`packagesDigest`), both
  from verified evidence, so a reader can show which findings were fixed or
  introduced and whether packages changed between runs.

## Reproducibility

clearcutt-factory's reusable workflows rebuild each image they publish on a
second runner (and repeat each fleet rebase), and attest each match on the
image (`clearcutt-factory verify --image --attest`, predicate
`https://github.com/northcutted/clearcutt-factory/reproduction/v1`). Such an
attestation makes an image `reproduced` without rebuilding it, with
`reproducibility.source: attestation`, when:

- cosign verified it against the policy's image signers, bound like the
  recipe (`sourceMatchesImage` and the other constraints apply);
- its subject, and the `digest` it says the reproduction gave, are the image's
  digest;
- it was made (`from.digest.sha256`, the sha256 of the signed DSSE payload)
  from a recipe or rebase record cosign verified on the same image, of the
  kind its method rebuilds from (`recipe-rebuild` from a recipe,
  `rebase-repeat` from a rebase record).

The report then gives the method, `checkedAt` (the attestation's
`reproducedAt`), the digest, who signed it (`signer`), where it is (`ref`),
and the run and machine that reproduced it (`builder`, as the attestation
says). It shows the image rebuilt on a fresh machine of the publisher's, not
that anyone else can rebuild it; `--reproduce` rebuilds the others yourself.
An attestation that isn't verified, or doesn't meet these conditions, is not
read or counted, and `reproducibility.detail` says why.

`--reproduce` rebuilds every other clearcutt-factory image from its verified recipe
(or repeats its verified rebase) with `clearcutt-factory verify --image`, bound
to exactly the signer that verified the recipe or rebase record the report
shows (its identity, issuer, and the repository of the run that signed; or
the trusted key), and records whether the digest matched. It needs `clearcutt-factory` on `PATH` (or
`--factory-path`) and a container runtime, and takes as long as the builds do.
Each rebuild works in its own directory under the user cache directory (on
macOS, `~/Library/Caches/clearcutt-verify/reproduce/`), which is kept with its
build log when the image doesn't reproduce.

A different digest is `not-reproduced` and fails the image. A rebuild that
couldn't finish (a registry or the container runtime failing) is
`not-checked`, with the reason, and leaves the image `unverified`: whether it
reproduces is still undecided. The digest is read only from the result
clearcutt-factory reports last (its final output line on success, its error
on a mismatch), never from build output, and a rebuild that exits with an
error is never `reproduced`; its `reproducibility.source` is `rebuild`.
Without `--reproduce`, images with recipes and no verified reproduction
attestation are `not-checked`.

## Limits

- **Registry rate limits.** Docker Hub limits anonymous manifest reads (100 an
  hour). A run reads each manifest once, but bases published for many
  architectures cost a read per platform image; `--platforms
  linux/amd64,linux/arm64` reads only those, and the report records the
  selection (`metadata.platforms`): SBOMs, scans, findings, and packages then
  describe those platforms only. An image none of whose platform images is
  selected, or whose platform images couldn't all be read, has its SBOM and
  vulnerability scan `unknown`, not judged on the platforms that happened to
  be read. Lookups the registry refuses are reported as `unknown`, not
  `missing`. Logging in (`docker login`) raises the
  limit; `clearcutt-verify` reads the same credentials.
- **Scanners: grype only, for now.** Vulnerability findings are read from
  cosign vulnerability attestations (`https://cosign.sigstore.dev/attestation/vuln/v1`)
  holding grype's JSON output: the predicate's `scanner.uri` (or the result's
  `descriptor.name`) names grype, and the result has grype's `matches` list.
  Another scanner's attestation (Trivy's `--format cosign-vuln`, for one) is
  still verified, but its findings aren't read: the image's vulnerabilities
  are unknown (no `vulnerabilities`, a warning, and the scan's `detail` says
  why), never zero, so `failOn` and `maxScanAgeDays` leave it `unverified`.
- **Tests.** Test evidence counts only as a test-result attestation
  (`https://in-toto.io/attestation/test-result/…`).
- **Speed.** Each signer of each kind of evidence on an image is one cosign
  verification; when copies name more than one signer, one more per trusted
  signer finds which hold content a trusted identity signed, and only their
  signers are verified. `--concurrency` bounds how many images are checked at
  once.

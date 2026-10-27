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

## Prepare a starter policy

```bash
clearcutt-verify policy init --refs refs.txt --out policy
```

Use `--images images.yaml` instead of `--refs` to start from an inventory.
Only its image references are used: declarations of evidence, platforms or
trust do not count. The command resolves the references and discovers their
attachments afresh, without invoking cosign or claiming verification.

It writes `policy.yaml` and `trust-policy.yaml` into a **new directory**.
`required` is the evidence found for every inspected image reference. SBOMs
and scans must cover each platform image; an attachment on a multi-platform
index alone does not establish that coverage. Comments show availability
counts for the other kinds and formats that remain present-only. Discovered
content may still be malformed or unusable; availability is not validation.
An unreadable image, platform or evidence listing stops initialization
without publishing a starter, rather than silently reducing requirements.

The active trust list is `signers: []`. Discovered certificate identities,
issuers and caller repository/refs appear only as commented **UNVERIFIED**
candidates. Confirm them out of band before adding active signer rows;
key-signed evidence requires a separately trusted public key. Notation
certificate claims are labelled separately from Cosign trust entries.
Choose vulnerability and freshness gates for your estate; the starter does
not infer thresholds. An untouched starter cannot verify an image.

`--platforms linux/amd64,linux/arm64` limits the inspected scope; use the same
selection for verification. `--concurrency` defaults to four references.
`--verbose` writes progress to stderr; `--quiet` suppresses progress and the
normal summary. `--format json` or `--format yaml` prints a summary containing
`images`, `required`, per-kind `available` counts, `unverifiedSigners`, the
output path and any platform/format scope; these formats still print with
`--quiet`. The YAML policy files are written separately.

Existing output files, directories (including empty ones) and symlinks are
refused. Both documents are parsed and validated in staging, then published
together by a directory rename. Use a new output directory to discover
again; initialization does not overwrite a policy you have reviewed.

## What it checks, per image

1. **Evidence in the registry.** Signatures and attestations stored by cosign
   v3 (Sigstore bundles as OCI referrers, including GitHub artifact
   attestations pushed to the registry), by cosign v2 (`sha256-<digest>.sig`
   and `.att` tags), and unsigned SBOMs attached as referrers. Bundles are
   decoded to learn what each one actually holds; cosign labels its own
   bundles as plain signatures. Evidence other tools leave is found too, and
   reported `present`, never `verified`, with nothing in it read:
   - **Notation signatures** (`notation sign`, as ACR, Harbor, and ECR
     setups use): referrers of artifact type
     `application/vnd.cncf.notary.signature` (`source: notation-signature`).
     clearcutt-verify doesn't verify them (no ClearCutt trust policy names a
     Notation signer, and cosign doesn't check them); the `signer` it shows
     is the claim in the envelope's certificate, `identity: "x509.subject:
     <subject>"` (JWS envelopes; a COSE envelope's isn't read). `notation
     verify` checks them against a Notation trust policy.
   - **BuildKit attestations** (`docker buildx build --sbom --provenance`):
     the SPDX SBOM and SLSA provenance BuildKit stores in the image index, in
     an attestation manifest beside each platform image
     (`vnd.docker.reference.type: attestation-manifest`; `source:
     buildx-attestation`). They are unsigned in-toto statements.
   - **cosign's `.sbom` tag** (`cosign attach sbom`): an unsigned SBOM in the
     `sha256-<digest>.sbom` tag (`source: cosign-sbom-tag`).

   SBOMs and vulnerability reports belong to platform images. A platform
   image with none of its own is judged by any attached to the image index
   (what `cosign attach sbom` or `cosign attest` on a multi-platform tag
   writes): `present`, signed or not, since such a copy doesn't say which
   platform it describes, and never read. When the index's evidence can't be
   read, the platform image's is `unknown`, not `missing`.
2. **Verification.** Each piece of evidence is verified with cosign against
   the policy's trusted signers. Anything not signed by one of them is
   `failed`, never quietly accepted. Evidence cosign couldn't check (it
   couldn't reach the registry or the transparency log, the registry refused
   it, or cosign couldn't run) is `unknown`, not `failed`, and its `detail`
   says what went wrong (for the trusted root, what TUF said too); whether a
   trusted signer signed it is undecided.
   Before reading anything, the run checks that cosign is there and is cosign
   v3 (the version whose bundles and output it reads), and stops with exit 1
   if not. When the policy trusts a keyless signer, or a key signer whose
   evidence must be in the transparency log (no `tlog: false`), it then
   fetches Sigstore's trusted root once (`cosign initialize`) and hands the
   cached `trusted_root.json` (the one from the mirror `cosign initialize`
   used: `TUF_MIRROR`, else the default) to every verification that needs it
   (`cosign --trusted-root`), so no verification fetches it from the TUF
   repository itself: each cosign run
   otherwise refreshes TUF metadata over the network into the shared cache
   (`~/.sigstore/root`), and with verifications running concurrently one
   could find the repository unreachable, or a sibling's half-written file,
   and fail the evidence as if its signature were bad (cosign v3.0.x reports
   that as "trusted root is required when using new bundle format"). A fetch
   that fails stops the run (exit 1). Should the file not be in the cache
   where it is looked for (a cosign that caches elsewhere), the run warns on
   standard error (a GitHub Actions `::warning` too) and in the report's
   `warnings`, and each verification fetches the root itself, as before. An
   air-gapped setup passes its own file
   with `--trusted-root`, and one that sets `SIGSTORE_ROOT_FILE` and the
   other individual-target variables is left to cosign. cosign is asked for
   exactly the signer
   the evidence's certificate names (its identity and issuer, and for GitHub
   Actions the repository and ref of the run), once a trusted signer accepts
   that signer, so the signer the report shows on verified evidence is the
   one cosign checked.
3. **Contents.** Only what cosign verified is read: vulnerability findings
   from verified vulnerability attestations (deduplicated across platforms;
   VEX-suppressed findings are kept but not counted; grype's and Trivy's
   output only, for now, see Limits), packages from verified
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
is no age to measure. The publisher's scan is as old as the image: what was
published since is unknown until the image is rescanned (below).

### Rescanning: today's findings beside the publisher's

```bash
clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --out dist/estate --rescan
```

`--rescan` scans each image's **verified** SBOMs itself, with grype (on
`PATH`, or `--grype-path`; the run checks it is there first and exits 1 if
not), against a vulnerability database of today, and reports the result
beside the attested scan: `vulnerabilities` stays what the publisher's
verified scan found, on its day; `rescan` is what the same packages look like
now (`rescan.vulnerabilities`, with `scanner`, `scannedAt`, and
`database.built`, the database's build time). Only SBOMs a trusted signer
verified are scanned, one per platform image: an image with no verified SBOM
on some platform, or not all of whose platform images could be read, or that
grype couldn't scan, has `rescan.status: unknown` with the reason, and its
current vulnerabilities are unknown, never clean. The database is grype's
own, where grype's settings put it (`GRYPE_DB_CACHE_DIR`,
`GRYPE_DB_UPDATE_URL`, and the rest of grype's `GRYPE_DB_*` environment).
Before reading anything, the run updates it once (`grype db update`), and
every scan then uses it as it is (`GRYPE_DB_AUTO_UPDATE=false`), so
concurrent scans don't each check for, and on a fresh runner download, the
database at once; an update that fails stops the run (exit 1), as a missing
grype does. With `GRYPE_DB_AUTO_UPDATE=false` already set (a database
imported with `grype db import`, for an air-gapped run), nothing is
downloaded: the run only checks that grype has a database (`grype db
status`) and stops (exit 1) if it hasn't. When grype
couldn't scan any image at all, the report is written (every rescan
`unknown`) and the run exits 1: a run that found out nothing isn't a result.

With `--rescan`, the policy's `scanSource` says which scan `failOn` gates
on:

```yaml
scanSource: worst   # attestation, rescan, or worst (the default with --rescan)
```

`attestation` gates on the publisher's scan, as without `--rescan`; `rescan`
on this run's; `worst` on both: an image fails when either finds enough, and
is `unverified` when either is unknown. `scanSource: rescan` or `worst`
without `--rescan` is an error: there is nothing to gate on. With a
`scanned` rescan, `maxScanAgeDays` measures the rescan by its database's
build time (findings know nothing published after it), so a stale local
database leaves the image `unverified` as a stale attestation would. The
flag form is `--scan-source`.

#### VEX

```yaml
vex: [vex/openssl.openvex.json, vex/estate.openvex.json]   # relative to the policy file
```

OpenVEX documents the policy names are applied to the rescans. Every finding
they suppress is still listed in `rescan.vulnerabilities.findings`, marked
`suppressed: true`, not counted, and attributed in `suppressedBy` to the
statement that did it (the document's `file` as the policy named it, its
`@id`, the statement's `product` as written, `status`, and
`justification`); a finding grype's own rules suppressed says `source:
scanner`. Nothing is dropped silently. The report's `policy.vex` lists the
documents, and a statement about an image that isn't in the estate is
warned about. The flag form is `--vex FILE` (relative to the working
directory).

grype applies VEX itself, but it scans an SBOM here, not an image, so a
statement whose product is the image wouldn't be applied and one whose
product is a package would apply to every image. So `clearcutt-verify` scopes
the statements before grype sees them, by this rule (clearcutt-factory
applies the same one to its build-time scans):

- A product that is an **image purl** (`pkg:oci/…` or `pkg:docker/…`) names
  the image when its version (percent-decoded) is the image's digest or one of
  its platform images' digests (then it applies to that platform only), or,
  with no version, when its `repository_url` qualifier is the image's
  repository (and its `tag` qualifier, if any, one of the image's tags).
  `pkg:oci/app?repository_url=ghcr.io/acme/app` and
  `pkg:oci/app@sha256%3A…` both work; a bare `pkg:oci/app` names no image
  and is applied nowhere (the run warns).
- A product that **isn't a purl** names the image when it is the image's
  repository, `repository:tag`, `repository@digest`, or a bare digest the
  image or one of its platform images has.
- A product that is any **other purl** is a package: it applies to every
  image, to the packages grype matches it to (grype matches a purl by type,
  namespace, and name; by version when the product has one; and by each
  qualifier the product has, so `pkg:apk/wolfi/openssl@3.0.1-r0` matches
  `pkg:apk/wolfi/openssl@3.0.1-r0?arch=x86_64`).
- A statement about an image applies to the packages its `subcomponents`
  name; with no subcomponents, to every package in the image's SBOM, for that
  vulnerability (subcomponents none of which can be read leave it applying
  to none). A statement's `vulnerability.name` and `aliases` both count
  (grype's GHSA and the CVE it tracks are the same finding).

OpenVEX v0.2.0 documents are read, and OpenVEX 0.0.1 documents are read the
way clearcutt-factory reads them, so one document means the same to both
tools: a `vulnerability` given as a string is its name, products given as
strings are their `@id`, and the `subcomponents` a 0.0.1 statement names
beside its products are those of each product that names none of its own.

For each scan, the statements about the image are rewritten as
package-scoped statements (each subcomponent, or each package of the SBOM,
as the product) and handed to grype with the package-scoped statements as
they are; statements about other images aren't. What grype then reports as
ignored is matched back to the statement that caused it.

### Observe-only images

```yaml
observe: ["cgr.dev/chainguard/*", "ghcr.io/acme/app:canary"]
```

Images matching an `observe` pattern (a path glob over the repository, or
over `repository:tag`) are in the report with a verdict like any other, but
don't gate: they are counted in `summary.verdicts.observeOnly` instead of
`verified`, `failed`, or `unverified`, and `--fail-on` ignores them. The
report marks each with `observeOnly: true`. Use it for an upstream base you
watch but don't own, so its findings are visible without failing the
estate. The flag form is `--observe PATTERN`.

### Provenance: what is and isn't checked

A `verified` `provenance` means cosign verified the attestation's signature
against a trusted signer and that the statement is about the image, and the
source repository and commit were read from it (`source`, `basis:
provenance`). The builder ID, build type, and materials are **read, not
evaluated**: the report shows the builder and build type in `provenance`,
and `evidence.provenance.detail` says so. To check the builder, name the
ones you trust:

```yaml
provenanceBuilders: ["https://github.com/northcutted/clearcutt-factory/.github/workflows/images.yml@refs/tags/v0.3.0"]
```

Verified provenance naming another builder (`runDetails.builder.id`, or
`builder.id` in SLSA v0.2), or naming none, is then `failed`, and nothing is
read from it: no `source` from it, no `provenance`. One naming a listed
builder records `provenance.builderChecked: true`. Each entry must be a
builder ID; an empty one is refused when the policy is read. Build type and
materials still aren't evaluated.

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
policy's `trustedSigners`. A third role, `estate`, names who may sign the
estate's own artifacts in the registry (the report bundle `estate push`
stores and the history index it appends to): `estate pull --trust-policy
trust.yaml` (or `--policy policy.yaml`, through its `trustPolicy`) verifies
against those signers instead of cosign's flags, and so does `estate
history`. clearcutt-factory accepts the role and ignores it.

```yaml
  - name: estate-job
    roles: [estate]
    identity: https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main
    issuer: https://token.actions.githubusercontent.com
```

`sourceRepositoryOwner: https://github.com/OWNER` accepts a keyless signer's
runs in any repository of that owner: the certificate's Source Repository
URI (`1.3.6.1.4.1.57264.1.12`, or the v1 workflow repository extension) must
be `https://github.com/OWNER/<repo>`, i.e. its owner segment must be
`OWNER` exactly (`acme-evil` is not `acme`), and that repository is then
required of cosign exactly (`--certificate-github-workflow-repository
OWNER/<repo>`), so the report shows the repository that signed. With
`sourceRepository` or `sourceMatchesImage` as well, the repository they
resolve to must be the owner's. The value must be exactly
`https://github.com/OWNER` (a trailing slash is allowed); anything else is
refused when the policy is read, and the constraint needs the GitHub Actions
issuer. Evidence signed by a reusable workflow under a signer that names
none of `sourceRepository`, `sourceRepositoryOwner`, or `sourceMatchesImage`
stays `present`, never `verified`: the identity alone would trust every
caller.

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

With `maxDaysBehind`, only drift from a base **proven** by layer digests
(`base.strength: proof`) fails an image. An image whose claimed base
(`declared`, `assisted`, `weak`) is more than the limit behind is
`unverified`, with the reason saying the drift rests on a claim: a label can't
fail an image any more than it can pass one. Edges from `base.name` or build
history (`oci-base-name`, `history`) identify no version, so their drift is
`unknown`. An image whose base couldn't be placed is `unverified`:
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
elsewhere. Both are checked against the contract's schemas before anything is
written; a report or history that doesn't match (a bug, or a history file that
isn't one) writes nothing and exits 1. Each image's `id` comes from its whole
reference (`ghcr.io/acme/billing:1.2` is `ghcr-io-acme-billing-1-2`; see
[the contract](../contract/README.md)), so it is the same in every run and
never depends on the order of `refs.txt`. A reference listed twice is one
image. History rows written before v0.17.0, under the old short IDs
(`billing-1-2`), are renamed to the image's current ID when exactly one image
had that old ID, so its history carries on. The command prints a summary table (`--verbose` adds why each
image that isn't verified isn't; `--quiet` prints nothing but errors and the
`--fail-on` result; `--format json` or `yaml` prints the report itself
instead), and `--fail-on failed` (or `unverified`) makes it exit 2 when any
image falls short, for CI. A run that could check nothing (every piece of
evidence of every image `unknown`: cosign, the registries, or the images
unreachable) writes its report, which says so, and exits 1: it isn't a
result, and shouldn't pass a gate that only looks at the exit code.

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
clearcutt-verify estate pull ghcr.io/acme/estate:latest --output dist/estate --allow-missing \
  --certificate-identity https://github.com/acme/estate/.github/workflows/estate.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
clearcutt-verify estate verify --refs refs.txt --policy policy.yaml --name acme --out dist/estate
clearcutt-verify estate push ghcr.io/acme/estate:latest --dir dist/estate \
  --file estate-report.json --file estate-history.json \
  --generated-at "$(jq -r .metadata.generatedAt dist/estate/estate-report.json)"
cosign sign --yes ghcr.io/acme/estate@sha256:…   # the digest push printed
```

`--allow-missing` succeeds only when the registry has no manifest at the
reference (nothing yet on the first run); any other failure fails, including a
stored bundle whose files can't be read, so a run never starts a fresh
history and pushes it over one it couldn't read. The push prints the
artifact's digest; the job signs it, and the next run's pull writes nothing
until cosign has verified that signature against the trust policy's `estate`
signers (`--trust-policy trust.yaml`, or `--policy policy.yaml` through its
`trustPolicy`), or against the job's identity given as cosign's flags
(`--certificate-identity` or `--certificate-identity-regexp` with
`--certificate-oidc-issuer`, or `--key`, as `cosign verify` takes them).
Without it, anyone who can push to the repository could hand the next run a
history of their making. `--allow-unverified` writes an unverified bundle
anyway, and warns. `estate push --history REF` appends the snapshot to a
history index and prints the index's digest too; a job signs that digest the
same way (`cosign sign --yes REPOSITORY@INDEX_DIGEST`), and `estate history
REF` reads the index only once cosign has verified it against the same
signers (the same flags), refusing it otherwise unless `--allow-unverified`.

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
  before pushing, but doesn't attest the result. A rebased image's comes from
  its verified rebase record, which (clearcutt-factory v0.2.0 and later)
  names the smoke test the rebase ran and each platform's result: `verified`
  when it passed on every platform the rebase built and every platform image
  read, `failed` when the record says it didn't pass on one, `present` when
  it says nothing about one. The item points at the rebase record
  (`predicateType`, `ref`, `signer`), so checking the record checks it. A
  record that names no test (`rebase --image`, `--no-test`, or an earlier
  clearcutt-factory) leaves it `missing`, and its `detail` names the test the
  original's recipe declares.
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
attestation are `not-checked`. With it, an image whose recipe or rebase
record is `unknown` (couldn't be read) is `not-checked` too, and `unverified`:
whether there was anything to rebuild is undecided, so it is never skipped as
if it had no recipe.

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
- **Scanners: grype and Trivy, for now.** Vulnerability findings are read
  from cosign vulnerability attestations (`https://cosign.sigstore.dev/attestation/vuln/v1`)
  holding grype's JSON output (the predicate's `scanner.uri`, or the result's
  `descriptor.name`, names grype, and the result has grype's `matches` list)
  or Trivy's report (`trivy image --format cosign-vuln`: the `scanner.uri`
  names Trivy, and the result is Trivy's JSON report, schema version 2, with
  its `Results` list; every finding counts, whatever its `Status`, and a
  report without `Results`, which Trivy writes when it found nothing it could
  scan, isn't read). Another scanner's attestation is still verified, but its
  findings aren't read: the image's vulnerabilities are unknown (no
  `vulnerabilities`, a warning, and the scan's `detail` says why), never
  zero, so `failOn` and `maxScanAgeDays` leave it `unverified`. `--rescan`
  scans with grype.
- **Tests.** Test evidence counts as a test-result attestation, or as the
  smoke test a verified clearcutt-factory rebase record says passed (a
  recipe's declared test is only `present`): a test-result attestation
  (`https://in-toto.io/attestation/test-result/…`).
- **Speed.** Each signer of each kind of evidence on an image is one cosign
  verification; when copies name more than one signer, one more per trusted
  signer finds which hold content a trusted identity signed, and only their
  signers are verified. `--concurrency` bounds how many images are checked at
  once.

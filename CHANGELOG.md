# Changelog

ClearCutt is pre-1.0: minor releases may include breaking changes, and only
the latest release is supported (see [SECURITY.md](SECURITY.md)).

Each release on
[GitHub Releases](https://github.com/northcutted/clearcutt-verify/releases)
carries the CLI binaries, a Sigstore signature bundle for each, and a
`SHA256SUMS.txt` manifest; releases after v0.15.0 also attest each binary's
build provenance (`gh attestation verify`). Its notes are generated from the
merged pull requests; this file is the curated summary.

## Unreleased

<!--
Add an entry here in the same PR as any user-visible behavior change (CLI
commands and flags, the estate report contract, the action, release assets).
When a release is cut, move these entries under a heading for its version.
-->

### Breaking

- **Image IDs come from the whole reference.** An image's `id` was its
  repository's last path segment and tag (`billing-1-2`), with `-2`, `-3`
  added to repeats in the order references were listed, so two registries'
  `static` images could swap IDs between runs. It is now the registry,
  repository path, and tag (or a digest's first 12 hex digits), lower-cased,
  with other characters made dashes and the tag `latest` left out:
  `ghcr-io-acme-billing-1-2`, `cgr-dev-chainguard-static`. References that
  spell the same ID each get the first 8 hex digits of the sha256 of the
  reference appended, so IDs no longer depend on input order. This applies to
  `import images`, `registry scan`, and `estate verify --refs`; `estate
  verify` also gives any observation whose ID is missing, repeated, or not a
  URL path segment the ID its reference gives. A reference listed twice is
  imported once. Readers that kept IDs (links, compare-runs) see each image
  under a new ID once; `estate verify` renames the rows of earlier runs in
  the history it extends when exactly one current image had the old ID,
  computed from the reference as it was written (a reference without a tag
  had the repository's ID, a digest reference the digest's, tag or not). The
  fixture and example bundles use the new IDs.
- **`estate history` verifies the history index's signature.** It read the
  index on nobody's word. Like `estate pull`, it now needs who signed it: a
  trust policy's signers with role `estate` (`--trust-policy FILE`, or
  `--policy FILE` through its `trustPolicy`), or cosign's flags
  (`--certificate-identity`/`-regexp` with `--certificate-oidc-issuer`, or
  `--key` with `--insecure-ignore-tlog`); an index nobody trusted signed is
  refused (exit 1), and `--allow-unverified` reads it anyway with a warning.
  A job that appends to a history (`estate push --history`) signs the index
  digest the push prints, as it signs the bundle's. `estate pull` takes the
  same `--trust-policy`/`--policy` flags. A new trust-policy signer role,
  `estate`, names those signers; clearcutt-factory accepts and ignores it.
- **`estate pull` verifies the signature of what it pulls.** It checked only
  the artifact's media type, so anyone who could push to the repository could
  hand the next scheduled run a history of their making. It now writes
  nothing until cosign v3 has verified the artifact's signature against the
  signer named on the command line, as `cosign verify` takes it:
  `--certificate-identity` (or `--certificate-identity-regexp`, anchored, as a
  trust policy's) with `--certificate-oidc-issuer`, optionally
  `--certificate-github-workflow-repository OWNER/REPO`; or `--key` (with
  `--insecure-ignore-tlog` for a key that signs without a transparency log).
  One of those is required. A bundle that is unsigned, signed by someone else,
  or whose signature cosign couldn't check is refused (exit 1).
  `--allow-unverified` writes it anyway and prints a warning (a GitHub Actions
  `::warning` annotation too); without a signer it checks nothing. Callers
  must add the signer flags: for a job that signs with `cosign sign --yes`,
  its workflow identity, e.g. `--certificate-identity
  https://github.com/OWNER/REPO/.github/workflows/estate.yml@refs/heads/main
  --certificate-oidc-issuer https://token.actions.githubusercontent.com`. A
  bundle pushed before the job signed them needs signing once (or one run with
  `--allow-unverified`).

### Added

- **`sourceRepositoryOwner` is validated and described.** A trusted signer's
  `sourceRepositoryOwner` must be exactly `https://github.com/OWNER`; the
  policy is refused otherwise (before, a wrong value silently matched nothing
  and every signature came out failed). The trust-policy schema now describes
  every signer field, and docs/verify-estate.md states the exact rule: the
  certificate's Source Repository URI must be `https://github.com/OWNER/<repo>`
  (its owner segment exactly `OWNER`), and that repository is then required
  of cosign (`--certificate-github-workflow-repository`).
- **`estate verify --rescan`: today's findings beside the publisher's.** The
  run scans each image's *verified* SBOMs itself with grype (on `PATH`, or
  `--grype-path`; checked before the run, exit 1 without it) and reports the
  result as `images[].rescan` beside `vulnerabilities`: the attested scan,
  on its day, and the same packages against a vulnerability database of
  today (`rescan.vulnerabilities`, with `scanner`, `scannedAt`, and
  `database.built`). Only SBOMs a trusted signer verified are scanned, per
  platform image; an image with no verified SBOM on a platform, not all of
  whose platform images could be read, or that grype couldn't scan is
  `rescan.status: unknown` with the reason, never clean. `summary.rescan`
  totals them; history rows carry `rescanVulnerabilities`. The policy's
  `scanSource` (`attestation`, `rescan`, or `worst`; `--scan-source`) says
  which scan `failOn` gates on, `worst` by default with `--rescan`: an image
  fails when either finds enough and is `unverified` when either is unknown.
  With a scanned rescan, `maxScanAgeDays` measures the rescan by its
  database's build time. grype's database settings (`GRYPE_DB_*`) are left
  to grype. When grype couldn't scan any image, the report is written and the
  run exits 1.
- **VEX for rescans.** A policy's `vex:` list of OpenVEX documents (relative
  to the policy file; `--vex FILE`) is applied to the rescans, scoped per
  image before grype sees it: statements whose product is the image
  (`pkg:oci/…` by digest or `repository_url`, or a plain reference) are
  rewritten to their subcomponents (or every package of the SBOM), and
  package-scoped statements apply estate-wide. Every suppressed finding is
  listed with `suppressed: true` and `suppressedBy` (the document's file and
  `@id`, the statement's product, status, and justification; or `source:
  scanner` for grype's own rules), never dropped. `policy.vex` lists the
  documents; a statement about an image that isn't in the estate is warned
  about. The scoping rule is documented in docs/verify-estate.md.
- **Observe-only images.** A policy's `observe:` patterns (path globs over
  the repository, or `repository:tag`; `--observe PATTERN`) mark images that
  are reported with a verdict but don't gate: `images[].observeOnly: true`,
  counted in `summary.verdicts.observeOnly` (so `verified + failed +
  unverified + observeOnly` is `images`), ignored by `--fail-on`, and marked
  in the history rows.
- **Provenance: read, not evaluated, and said so.** Verified SLSA provenance
  now records what it says about the build in `images[].provenance`
  (`builderId`, `buildType`), and `evidence.provenance.detail` states what
  was checked (the signature, that the statement is about the image; the
  source read from it) and what wasn't (builder, build type, materials). A
  policy's `provenanceBuilders:` list makes the builder a check: provenance
  naming another builder, or none, is `failed`, and neither its source nor
  its builder is read from it (no `source` with `basis: provenance`, no
  `images[].provenance`); one naming a listed builder records
  `provenance.builderChecked: true`. An empty entry in the list is refused
  when the policy is read.

### Fixed

- **Keyless evidence no longer fails when cosign loses Sigstore's trusted
  root.** Each cosign run refreshes TUF metadata over the network into the
  shared `~/.sigstore/root` cache, so with verifications running
  concurrently one could find the TUF repository unreachable, or a sibling's
  half-written file, and come out `failed` ("not signed by a trusted signer:
  … trusted root is required when using new bundle format"; cosign v3.0.x
  only warns what TUF said). This made a verified image's vulnerability scan
  read as failed on the showcase estate on some days. `estate verify` and
  `estate pull` now fetch the trusted root once (`cosign initialize`) before
  verifying anything, when the policy trusts a keyless signer, and pass the
  cached `trusted_root.json` to every verification (`--trusted-root`); a
  fetch that fails is an operational error (exit 1). `--trusted-root FILE`
  supplies one instead (air-gapped setups), and `SIGSTORE_ROOT_FILE` and the
  other individual-target variables are left to cosign. Should cosign still
  lose the root, the evidence is `unknown`, with TUF's own message in its
  detail, never `failed`. The action installs cosign v3.1.4 (the installer's
  default was v3.0.6).

### Changed

- **A run that could check nothing exits 1, not 0.** When every piece of
  evidence of every image is `unknown` (cosign, the registries, or the
  images couldn't be reached), `estate verify` writes the report, which says
  so, and exits with the operational code: a report in which nothing could be
  checked is not a pass, whatever `--fail-on` says.
- **Every report and history is checked against the contract before it is
  written.** `estate verify` validates both documents against the schemas in
  `contract/` (compiled into the binary from the same types) and writes
  nothing, exiting 1, when either doesn't match, so a bug can't publish a
  bundle a portal would reject. A previous `estate-history.json` that isn't a
  valid history now stops the run instead of being extended.
- **Staleness is never manufactured from a claim.** `maxDaysBehind` fails an
  image only when its base is proven by layer digests (`base.strength:
  proof`); an image more than the limit behind a base it only claims
  (`declared`, `assisted`, `weak`) is `unverified`, with the reason saying
  so. Graph edges from `org.opencontainers.image.base.name` or build history
  (`oci-base-name`, `history`) no longer pick the oldest observed version of
  the repository and call the image stale: they name the repository the image
  claims, carry no `baseDigest` (and the report's `base.imageId` is empty:
  no observed image is identified as the version), have `drift: unknown`,
  and aren't counted as stale consumers (`graph build --fail-on-stale`
  included). Under
  `--reproduce`, an image whose recipe or rebase record is `unknown` is
  `not-checked` and `unverified`, not skipped as if it had no recipe.
- **`reproducibility.checkedAt` is the report's time** for images this run
  rebuilt (`--reproduce`), not the wall clock, so `--generated-at` makes the
  whole report reproducible.
- **An untrusted rebase record no longer satisfies a required `recipe`.** Any
  rebase record that wasn't `missing` (one signed by someone else, `failed`;
  one no trusted signer applied to, `present`) made the recipe
  `not-applicable`, and `not-applicable` met `required: [recipe]`, so an image
  could be `verified` on evidence nobody trusted. The recipe is now
  `not-applicable` only when the rebase record is `verified` and names the
  image it was rebased from; otherwise it stays `missing`, and its `detail`
  says why the record doesn't count. The verdict accepts `not-applicable`
  only for that recipe: a missing recipe beside a `present` or `unknown`
  rebase record is `unverified`, beside a `failed` one `failed`.
- **Only grype's output is read as a vulnerability scan, for now.** Any JSON
  in a cosign vulnerability attestation that unmarshalled into grype's shape
  was read, so another scanner's report (Trivy's `cosign-vuln` format, for
  one) read as grype output with no matches: a clean scan that passed
  `failOn`. A scan is now read only when its predicate says it is grype's
  (`scanner.uri` or the result's `descriptor.name`) and has grype's `matches`
  list; otherwise it verifies but its findings are unknown (no
  `vulnerabilities`, a warning, and the scan's `detail` says why), so
  `failOn` and `maxScanAgeDays` leave the image `unverified`.
- **"Couldn't check" is no longer reported as "failed".**
  - `estate verify` checks its tools before reading anything: cosign must be
    on `PATH` (or `--cosign-path`) and be cosign v3 whenever the policy trusts
    a signer, and `--reproduce` needs `clearcutt-factory`. A missing tool, or
    a cosign v2 (which reports cosign v3's bundles as unsigned) or v4, exits 1
    (operational error) and writes no report. Before, every piece of evidence
    came out `failed`, "not signed by a trusted signer", and `--fail-on
    failed` exited 2 as if the estate had failed its policy.
  - Evidence cosign couldn't check (a registry or the transparency log
    unreachable, refusing, or throttling; cosign not running; its output
    unreadable) is `unknown`, with a `detail` saying so, not `failed`. With
    several trusted keys, evidence is `unknown` when any key couldn't be
    checked and none verified. An `unknown` copy outranks `failed` ones anyone
    could attach.
  - An image whose platform images couldn't all be read, or none of whose
    platform images is among `--platforms`, has its SBOM and vulnerability
    scan `unknown` (no findings, no packages), not judged on the platform
    images that were read. `platforms` is `[]`, never `null`, when the image's
    platform list can't be read.
  - New, optional, additive: `metadata.platforms` records the `--platforms`
    selection, so a reader knows which platforms per-platform evidence
    describes.
- **Credentials reach only their registry.** `estate push`, `pull`, and
  `history` and the `evidence` commands sent whichever environment pair was
  set (`REGISTRY_*`, `CLEARCUTT_REGISTRY_*`, or `GITHUB_ACTOR` and
  `GITHUB_TOKEN`) as basic auth to any registry they were pointed at, so a
  job's `GITHUB_TOKEN` reached a third-party registry as soon as one was
  named, contradicting the docs. `GITHUB_TOKEN` now goes to `ghcr.io` only, as
  everywhere else in the CLI; `REGISTRY_*` (or `CLEARCUTT_REGISTRY_*`) only to
  the registries of the references the command was given; the Docker
  keychain, each entry to its own registry. On `ghcr.io`, a `docker login`
  now takes precedence over `GITHUB_TOKEN`, as it already did for `estate
  verify`.
- **Rebased images read their smoke test from the rebase record.**
  clearcutt-factory v0.2.0 and later record in the signed rebase record the
  smoke test a rebase ran (`test`: the app's `spec.test` and each platform's
  result), but rebased images still showed `tests: missing`. A verified
  rebase record whose test passed on every platform the rebase built and
  every platform image read now makes `tests` `verified`, pointing at the
  record (`predicateType`, `ref`, `signer`); one that says it didn't pass on
  a platform makes it `failed`, and one silent about a platform `present`.
  Records without `test`, and records that aren't verified, leave it
  `missing`.
- `estate verify` honours the global output flags it ignored: `--verbose`
  lists why each image that isn't verified isn't, `--quiet` prints nothing
  but errors and the `--fail-on` result, and `--format json|yaml` prints the
  report itself instead of the table.
- CI runs the real cosign: a new required job (`cosign-e2e`, in the PR Gate
  Summary) signs and attests two-platform images with cosign v3 key pairs in
  `registry:2` (no Referrers API: the referrers tag) and `registry:3` (the
  Referrers API), and checks the verdicts `estate verify` reaches (a
  verified image, one signed by another key, a Trivy scan, an unsigned one)
  and that `estate pull` reads a signed bundle back only for the key that
  signed it. Every other test fakes cosign.
- **`estate push --history` no longer resets the history on a read error.**
  Any error reading the history index (401, 429, 5xx included) started an
  empty index, which the push then wrote over the series. A new series now
  starts only when the registry says nothing is there (404,
  `MANIFEST_UNKNOWN`, `NAME_UNKNOWN`); any other error stops the push before
  the index is written (the snapshot is stored, and the error names it). A
  tag that holds an image, or an index that isn't an estate history, is
  refused, not overwritten.

## v0.16.0

Released 2026-10-16.

- Release binaries carry a SLSA build provenance attestation, signed by the
  release workflow and verifiable with `gh attestation verify`. The release
  workflow signs with cosign v3.1.3, accepts only stable `X.Y.Z` versions,
  and refuses to publish under a tag that names a different commit than the
  one it built.
- The Markdown reports of `graph build` and `graph layers` name the
  `clearcutt-verify` binary in their reproduce commands; they still said
  `clearcutt`.
- Removed `verify release-evidence`, and with it the `verify` command group.
  It checked the release evidence of images built by the removed image
  factory (an SPDX SBOM, a test-results attestation, and slsa-verifier
  provenance), and its help named a `--core-dir` flag that did not exist.
  `estate verify` verifies images, one or many, against a trust policy.
- Removed `.github/actions/install-clearcutt-verify`. Install with the
  repository's action, `uses: northcutted/clearcutt-verify@vX.Y.Z`, which
  checks the release's checksum and Sigstore bundle the same way.
- **`estate verify` reads only what cosign verified.** Vulnerabilities,
  packages, the provenance source, and clearcutt-factory details come only from
  attestations cosign verified against a trusted signer; `present` and
  `failed` evidence is reported but nothing in it is read. Before, the newest
  attached copy of each kind was read by its unverified timestamp, so anyone
  who could push to a repository could attach a newer copy that hid findings,
  faked a scan time or provenance source, or (with a forged certificate) turned
  a reusable workflow's `present` signature into `verified`. cosign is now asked
  for exactly the signer each copy's certificate names, so the signer shown on
  verified evidence is the one cosign checked. Every copy naming a signer the
  policy accepts is verified, so copies attached under made-up certificates,
  however many and however new, can't replace or crowd out a verified one
  (copies holding content no trusted identity signed cost no cosign run). A
  signature counts only when cosign verified a signature over the image's
  digest, not a bundle of another type.
- Verdicts are stricter: a `verified` verdict needs at least one piece of the
  image's evidence verified against a trusted signer, so with no trusted
  signer every image is `unverified` (it was `verified`), and checks that read
  no evidence (`maxDaysBehind`, `--reproduce`) no longer verify an unsigned
  image; `failOn` needs a verified scan on every platform (an unverified clean
  scan no longer passes); `maxScanAgeDays` measures the oldest platform's
  scan, and leaves an image with no verified scan of every platform
  `unverified`; with `maxDaysBehind`, a
  stale base whose age couldn't be measured is `unverified` (new, additive
  `base.daysBehindUnknown` in the contract); and an image that names a base it
  can't be shown to be built on stays unresolved instead of becoming a root.
- Trusted signers' `identityRegexp` must be anchored (`^`), and is refused
  when it matches probe identities of other owners on any forge: made up,
  prefixed or suffixed (`acme-evil` for `^https://github\.com/acme`), or a
  character off (an unescaped `.`), or an email domain extended past yours.
  The probes catch the usual mistakes, not every over-broad expression.
- `stacks` has one entry per stack repository and tag, so apps on another
  major tag no longer count as stale.
- `--reproduce` reads the rebuilt digest only from clearcutt-factory's final
  result, a rebuild that exits with an error is never `reproduced`, and the
  rebuild is bound to exactly the signer (identity, issuer, run repository)
  that verified the recipe the report shows, not to the first policy regexp
  that matches.
- New `estate pull --allow-missing` succeeds only when the registry has no
  manifest at the reference yet; any other failure fails, including a stored
  bundle whose files can't be read. The documented scheduled job uses it
  instead of `|| true`, which let a failed pull start a new history that the
  push then wrote over the old one.
- The GitHub Action pinned by commit SHA installs the release tagged at that
  commit (it installed the latest release), and fails for a commit no release
  tag points at.
- A trust policy's or verification policy's `key:` file is relative to the
  file that names it, as clearcutt-factory reads it (it was passed to cosign
  as written, and cosign, and `--reproduce`, run elsewhere); KMS URIs are
  used as written. `--reproduce` now rebuilds images whose recipe a trusted
  key verified, with `--key` (they were always `not-checked`, leaving every
  such image `unverified`).
- `registry scan` skips `sha256-<digest>` tags, where registries without the
  OCI Referrers API keep an image's referrers. They sort above `latest`, so
  with few tags kept per repository the scan could pick one as the image.
- An image whose layers start with several observed images' layers is built
  on the nearest one, the longest prefix. With an upstream base such as
  `cgr.dev/chainguard/wolfi-base` in the inventory, every app was attributed
  to it instead of to its run image (the first match by repository name won),
  so `estate dependents --base <run image>` found nothing and stale run images
  went unreported. Equally long prefixes (a mirrored base) go to the one the
  image's base annotation names, else the first repository by name.
- Rebased apps keep their stack. After a fleet rebase, the report had
  `stacks: null` and apps' `factory` lacked `stackRef` and `stackDigest`, so
  stack versions and stack signatures went unreported and unchecked. They now
  come from the verified recipe of the image the app was rebased from, reached
  through its verified rebase record (as `kind` and `name` already did). A
  rebased image's `tests` stays `missing`, since its rebase record doesn't say
  whether a smoke test ran; its detail now names the test the original's
  recipe declares and says why it isn't counted.
- Evidence a key signed without a transparency log can be verified: `tlog:
  false` on a key signer (in a trust policy or a VerificationPolicy; new,
  optional, additive in both schemas) passes `--insecure-ignore-tlog=true` to
  cosign for that key only, and verified evidence records `signer.tlog:
  false`. Keyless signers can't set it. Before, such evidence always failed,
  and said it was "not signed by a trusted signer"; a failure on the
  transparency log now says the log inclusion couldn't be verified (and, for
  keys, how to accept it). clearcutt-factory reads the shared trust policy
  strictly, so it has to accept `tlog` before a shared file uses it.
- `estate verify` reads clearcutt-factory's reproduction attestations
  (`https://github.com/northcutted/clearcutt-factory/reproduction/v1`, from
  `clearcutt-factory verify --image --attest`, which its reusable workflows
  run after each publish and rebase). One that cosign verified against the
  image signers (bound like the recipe), whose subject and `digest` are the
  image's, and that was made from a recipe or rebase record verified on the
  same image (`from.digest.sha256` is that statement's sha256, of the kind its
  method rebuilds from) makes the image `reproduced` without rebuilding it.
  `--reproduce` rebuilds only the images without one. New, additive contract
  fields on `reproducibility`: `source` (`attestation` or `rebuild`),
  `builder` (the run and machine, as the attestation says, and the
  clearcutt-factory and BuildKit versions), `signer`, and `ref`. An
  attestation that isn't verified or bound is never read or counted, and the
  detail says why.
- History rows (`estate-history.json`, `entries[].images[]`) list
  `fixableFindings`, the IDs of each image's fixable high and critical
  findings, and `packagesDigest`, a digest of its package set, both from
  verified evidence only (new, additive), so readers can show which findings
  were fixed or introduced, and whether packages changed, between runs. Lower
  severities and findings without a fix are only counted, to keep the history
  small. The `northcutted-images` fixture's newest rows are regenerated from
  its report.
- Provenance from GitHub's `actions/attest-build-provenance` pushed to the
  registry is labeled `github-attestation` (it was `cosign-attestation`: the
  label looked for `/attest-build-provenance` in the signer's identity, which
  is the calling workflow). It is told by its verified content, SLSA
  provenance of GitHub's workflow build type, so only verified evidence is
  labeled so. Verified evidence a GitHub Actions workflow signed records
  `signerWorkflow` (new, additive), the workflow without its ref, so readers
  can offer `gh attestation verify --signer-workflow`. The committed
  `northcutted-images` fixture predates both; regenerating it adds them.

## v0.15.0

Released 2026-10-10.

- For estate report readers (clearcutt-portal's requests, #56–#59), all
  additive: `base.platform` and `base.provenOn` (and `bases[].currentPlatform`)
  say which platform image a base digest names and where the proof was made;
  `packagesSource` says where an image's packages came from; history entries
  carry a row per image; and clearcutt-factory images whose verified recipe
  declares a smoke test show `tests: present` (source `recipe`). The
  `northcutted-images` fixture is regenerated.
- Estate reports list the clearcutt-factory registry stacks the estate's apps
  are built on (`stacks`): each version in use with its signature verified
  against the policy's stack signers (a trust policy's `stack` signers, or
  `stackSigners:`), and how many apps are pinned to an older version than the
  stack's tag names now. Apps record `factory.stackRef` and
  `factory.stackDigest`.
- New `registry scan --github-org ORG` enumerates an organization's (or
  user's) ghcr.io container packages through the GitHub Packages API, with
  `--package-prefix` to keep some of them. GHCR has no `_catalog` endpoint.
- New GitHub Action (`uses: northcutted/clearcutt-verify@vX.Y.Z`) installs
  cosign and a signature-verified release (`version: source` builds the
  action's checkout), and `docs/github-actions.md` shows a scheduled estate job
  that keeps its history in the registry.
- Registry reads fall back to `GITHUB_TOKEN` for ghcr.io only (never another
  registry), and `estate verify` retries throttled and failed registry
  requests with backoff before reporting them as unknown.
- `estate verify` policies can limit how old a vulnerability scan may be
  (`maxScanAgeDays`, `--max-scan-age-days`). An older scan, or one with no
  scan time, leaves the image unverified: what was found since is unknown.
- New `TrustPolicy` contract (`contract/trust-policy.v1.schema.json`): one file
  that says whose signatures an organization accepts, with roles for images and
  clearcutt-factory stacks. `estate verify --trust-policy`, or `trustPolicy:` in
  a VerificationPolicy, trusts its image signers; clearcutt-factory reads the
  same file (`signing.trustPolicy`). `--reproduce` binds the rebuild to the
  repository the evidence was verified against.
- **ClearCutt Verify now does one job: verify estates and write the estate
  report.** Removed, with the hardened-image catalog they served (whose images
  stopped being built in #39): `catalog`, `list`, `inspect`, `diff`,
  `release`, `verify image`/`catalog`/`rebuild`/`closure-purity`/`runtime-cve`/
  `boundaries`, `certify`, `policy`, `mirror`, `vex`, `exceptions`, `scan`,
  `conformance`, `import apply-evidence`, the global `--catalog` and `--strict`
  flags, the Astro catalog site and its embedded template (the website is
  [clearcutt-portal](https://github.com/northcutted/clearcutt-portal)'s job),
  the `clearcutt.yaml` fleet config, and the `certify-app` action. `app build`
  and `app rebase` are retired in favor of
  [clearcutt-factory](https://github.com/northcutted/clearcutt-factory)'s
  `build` and `rebase`, and `rebase discover`/`plan` in favor of:
- New `clearcutt-verify estate dependents` lists the images an estate report
  records as built on a base, with their drift and source repositories, so
  automation can wake exactly the repositories a new base affects.
- **Renamed to ClearCutt Verify.** The repository is
  `northcutted/clearcutt-verify`, the Go module
  `github.com/northcutted/clearcutt-verify`, and the binary `clearcutt-verify`
  (release assets `clearcutt-verify-<os>-<arch>`). Commands are unchanged
  except that estate verification is `clearcutt-verify estate verify`, next to
  `estate push`, `pull`, and `history`. The install action is
  `.github/actions/install-clearcutt-verify`, and it still installs releases
  published under the old names. Data formats keep their `clearcutt` names
  (`clearcutt.dev/v1`, `application/vnd.clearcutt.*`, `clearcutt.yaml`,
  `CLEARCUTT_*`): they belong to the ClearCutt family.
- `estate verify` trusted signers can say which workflow runs count:
  `sourceRepository`, `sourceRepositoryOwner`, `sourceRef`, and
  `sourceMatchesImage` (the run must be in the repository the image names as
  its source), enforced by cosign. This matters for reusable workflows, whose
  certificate identity is the called workflow, which any repository can call:
  evidence they sign is now `present`, not `verified`, unless the signer
  constrains the caller. Evidence signers in the report gain
  `sourceRepository` and `sourceRef`.
- New `clearcutt-verify estate verify` verifies every image in an estate and writes the
  estate report bundle (`estate-report.json`, `estate-history.json`). It finds
  evidence in the registry (cosign v3 Sigstore bundles, cosign v2 tags, unsigned
  SBOM referrers), verifies it with cosign against a policy's trusted signers,
  reads vulnerabilities, packages, SLSA source, and clearcutt-factory recipes
  and rebase records, proves bases by layer digest (including bases an image
  names whose tag has since moved), and decides a verdict per image.
  `--reproduce` rebuilds clearcutt-factory images to compare digests. See
  `docs/verify-estate.md`.
- `import observe` now reads registry credentials from the Docker keychain
  (`docker login`), so private images and Docker Hub's higher authenticated
  rate limit work.
- New estate report contract (`apiVersion: clearcutt.dev/v1`, `kind:
  EstateReport` and `EstateHistory`) in `contract/`: JSON Schemas generated
  from the Go types in `cli/internal/report`, a README defining every status,
  a synthetic example bundle, and a fixture generated from a real estate. It is
  the interface clearcutt-portal reads.
- **ClearCutt no longer builds images (#39).** The Nix image factory, its
  reference fleet, and the `platform`, `fleet`, `matrix`, `dev`, `service`,
  `overlay`, `runtime`, and `remediation` command groups that served it were
  removed. Building images is
  [clearcutt-factory](https://github.com/northcutted/clearcutt-factory)'s job.

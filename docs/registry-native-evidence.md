# Registry-Native Evidence

ClearCutt stores governance data — release evidence, estate snapshots, and the
history series — in an OCI registry, next to the images it describes.

This page covers what that buys, the two operational constraints it introduces,
and what to do about them. Both constraints are real. Neither is a reason not to
do it, but both will bite an operator who does not know about them.

## Why the registry

- **One storage plane.** Evidence lives where the images live, under one
  credential and one retention policy, instead of in a second system with its
  own auth model.
- **One answer on every platform.** Registries implementing the OCI 1.1
  Referrers API index attachments themselves; the referrers tag fallback covers
  those that do not. There is no code path per vendor and no per-platform
  bootstrap.
- **Digests, not URLs.** Evidence pins the image digest it describes, so it
  cannot drift onto different bytes when a tag moves.
- **It mirrors.** A mirrored registry carries its own evidence into an air gap.

The practical consequence is that GitHub becomes *one* control plane rather than
*the* control plane. Anything that can run a container and reach a registry can
run the whole governance loop.

## Writing and reading the plane

Evidence is written by the publish path and read by the catalog. Both halves
are needed: reading a plane nothing writes to finds nothing.

```bash
# Write. Off by default; opt in.
clearcutt-verify evidence attach ghcr.io/acme/app:v1.4.0 --dir ./evidence \
  --release v1.4.0
  --system x86_64-linux --attach-evidence

# Read. Defaults to github; opt in.
clearcutt-verify catalog gather --evidence-source=registry
```

Both sides are opt-in, and in that order. Defaulting the write on would make
every existing publish newly depend on a registry write it did not need before —
a credential that can push an image but not a referrer would turn an upgrade
into a failed release. Defaulting the read on would point a fork at a plane its
evidence is not in yet.

**The migration is: turn attachment on for a release cycle so the evidence
exists, then flip the read side.**

`evidence attach` stores the SBOM, scan and test results for a release against
the image digest they describe — pinned to the digest, not the staging tag, so a later
push to the same tag does not inherit this build's evidence.

The bundle uses stable, target-independent file names (`sbom.json`, `scan.json`,
`test-results.json`), so a consumer reads the same names whatever image produced
them.

## Constraint 1: garbage collection

**Attached evidence is a manifest like any other, and registry lifecycle rules
can delete it.**

A policy that prunes untagged manifests, or deletes everything in a repository
older than N days, or caps a repository at N artifacts, will take evidence with
it — and depending on the rule, possibly before it takes the image. GitHub
release assets do not behave this way. Moving evidence into the registry trades
vendor lock-in for a retention concern you now own.

What protects you, in order of how much you should rely on it:

**1. The referrers tag fallback tags each attachment.** On registries without
the Referrers API, ClearCutt's attachments are reachable through a real tag
(`sha256-<subject-digest>`), which defeats untagged-manifest pruning — the most
common rule by far. This is automatic and costs nothing.

It does **not** protect against age-based or count-based rules, and on registries
that *do* implement the Referrers API there may be no tag at all.

**2. Export the evidence.** This is the answer that does not depend on a
registry's policy:

```bash
clearcutt-verify evidence export ghcr.io/acme/app:v1.4.0 --output ./evidence-export
```

The export contains two representations of the same evidence, because two
audiences want different things:

| directory | what it is | who it is for |
|---|---|---|
| `oci/` | a standard OCI image layout, digest-preserving | restore it to any registry; signatures over the evidence still verify |
| `files/` | the same evidence as plain files | an auditor with a zip and no container tooling |

`export.json` records what the bundle holds and why it exists, so a copy sitting
in object storage two years from now explains itself without the tool that wrote
it.

Put the export wherever your retention guarantees actually live — object storage
with a lifecycle hold, a compliance archive, a backup system. Restore with:

```bash
clearcutt-verify evidence import ./evidence-export ghcr.io/acme/app
```

Restoration preserves the original digests, which is what keeps any signature
made over the evidence valid.

**3. Do not configure a policy that deletes it.** Obvious, but worth stating:
if evidence retention matters for compliance, the registry's lifecycle rules are
now a compliance control. Treat them as one.

## Constraint 2: some tags must stay mutable

Two things ClearCutt writes are **rewritten in place** and therefore require
mutable tags. If your registry enforces tag immutability on the repository, they
will fail.

| what | tag | why it is rewritten |
|---|---|---|
| estate history index | `:history` | each new snapshot appends an entry to the index |
| referrers tag fallback | `sha256-<digest>` | each new attachment appends to that subject's referrer list |

Everything else ClearCutt writes is write-once and safe to make immutable:

| what | tag | safe to freeze |
|---|---|---|
| dated estate snapshot | `:2026-09-01` | yes — written once, never rewritten |
| evidence bundle | addressed by digest | yes — content-addressed, no tag |
| release images | `:v1.4.0` | yes, if that is your policy |

**The recommendation:** enable tag immutability if you want it, but exempt the
`history` tag and the `sha256-*` referrer tags. Most registries express this as
a pattern-based rule.

If your registry cannot express an exemption, the fallback is to keep the
history index in a **separate repository** from the images, so an immutability
policy on the image repository does not reach it:

```bash
clearcutt-verify estate push ghcr.io/acme/app:2026-09-01 \
  --history ghcr.io/acme/estate-history:history
```

Note the asymmetry worth understanding: **immutability and the history index
want opposite things.** The index is valuable precisely because it is a single
moving pointer to a growing series; every snapshot it names is itself immutable
and digest-addressed. Freezing the pointer would freeze the series at one entry.

## What is stored where

| artifact | mechanism | addressed by |
|---|---|---|
| estate snapshot | OCI artifact, config media type `application/vnd.clearcutt.estate.v1+json` | tag and digest |
| estate history | OCI image index, entries annotated with each run's metrics | mutable tag |
| release evidence | OCI artifact with `subject`, discovered via referrers | digest |

Reading a history trend costs one manifest fetch regardless of series length,
because the metrics live in the index annotations rather than in the snapshots.

## Running it anywhere

The governance path — `registry scan`, `import observe`, `graph`, `estate`,
`evidence`, `certify`, `scan` — is pure Go and needs no Nix. The published
container image carries only a static binary on a distroless base:

```bash
docker run --rm ghcr.io/northcutted/clearcutt:latest \
  evidence list ghcr.io/acme/app:v1.4.0
```

Two operational notes:

- The image runs as **nonroot** (uid 65532). A mounted output directory must be
  writable by that user, or `evidence export` fails with a permission error.
  Either `chmod` the directory or run with `--user "$(id -u):$(id -g)"`.
- There is **no shell** in the image. Anything that expects to `sh -c` inside it
  will not work; invoke the binary directly.

Only the image *factory* needs Nix, which is a different job with a different
image. Nothing in the governance loop requires it.

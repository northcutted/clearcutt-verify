# Swapping the Container Registry

ClearCutt defaults to **GHCR** (`ghcr.io`) authenticated with the workflow's
built-in `GITHUB_TOKEN`. Treat GHCR as the fully supported reference path for
the current release. Other OCI registries are configurable, but they still need
registry-specific validation for authentication, OCI referrers, GitHub
attestations, and SLSA verification before a fork should rely on them.

## The configuration source

Image naming, release login host, and catalog enrichment login host are sourced
from `clearcutt.yaml`:

```yaml
registry:
  host: ghcr.io
  owner: your-org
  repository: your-fleet
  imagePrefix: yourbrand
```

The release and catalog workflows call:

```bash
# The publish-pages workflow resolves the host from clearcutt.yaml directly.
```

That command emits non-secret values such as `host`, `registry_base`, and
`username` from the fleet config and runner environment. Passwords are never
emitted by the CLI.

## The credential knobs

Set these as GitHub Actions **repository (or organization) variables/secrets**
when the defaults are not enough (`Settings → Secrets and variables → Actions`):

| Setting | Kind | Default when unset | Purpose |
| --- | --- | --- | --- |
| `CLEARCUTT_REGISTRY_USER` | Variable | `github.actor` | Login username / robot account. |
| `CLEARCUTT_REGISTRY_TOKEN` | Secret | `GITHUB_TOKEN` | Login password / token. |

The rebase pipeline additionally honors `CLEARCUTT_REBASE_REGISTRY_USER` /
`CLEARCUTT_REBASE_REGISTRY_TOKEN` when app images live in a different registry
than the platform fleet; it falls back to the three knobs above, then to the
GitHub defaults.

Because these default to the GitHub built-ins, **the canonical GHCR setup keeps
working with nothing set.**

## Registry support tiers

- **Tier 1: GHCR reference path.** Default and release-tested path. Uses
  `GITHUB_TOKEN`, GitHub Packages, GitHub Releases, GitHub Pages, GitHub-native
  attestations, Cosign referrers, and SLSA verification together.
- **Tier 2: generic token OCI registries.** Harbor, Artifactory, Quay, Nexus,
  GitLab Container Registry, and Docker Hub can use robot/service credentials
  through `registry.host`, `CLEARCUTT_REGISTRY_USER`, and
  `CLEARCUTT_REGISTRY_TOKEN`. Before relying on the path, prove that Cosign v3
  referrers, SBOM attestations, SLSA verification, and catalog enrichment work
  against the target registry.
- **Tier 3: cloud registries with short-lived auth.** AWS ECR and Google
  Artifact Registry need an auth bootstrap step today. ECR can use
  `aws-actions/amazon-ecr-login` or set `CLEARCUTT_REGISTRY_TOKEN` from
  `aws ecr get-login-password`; GAR should use `google-github-actions/auth`
  with Workload Identity Federation and `oauth2accesstoken` as the username.
  These should be treated as integration work until an explicit `authMode`
  selector lands.

## Known limitations

- **SLSA provenance generator.** The release workflow's provenance job uses
  `slsa-framework/slsa-github-generator` with `private-repository: true`; its
  registry credentials are parameterized from the same knobs, but confirm the
  reusable workflow supports your target registry before relying on it.
- **ECR/GAR short-lived auth** needs an extra auth step today (no `authMode`
  selector yet).

After changing `registry.host`, re-run `clearcutt-verify registry scan` against the new host to confirm credentials and reachability.

## Verify the swap

After configuring the knobs, run a release and confirm evidence resolves against
the new host:

```bash
clearcutt-verify registry scan --registry "$NEW_HOST" --namespace YOUR_ORG --repository YOUR_IMAGE --output /tmp/images.yaml
# or, for a consumer of a published image:
clearcutt-verify certify <your-host>/<org>/<repo>/<image>:<tag> --require-signature --require-provenance
```

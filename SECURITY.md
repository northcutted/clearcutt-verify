# Security Policy

## Supported Versions

ClearCutt is pre-1.0. There are no long-term support branches: security fixes
land on `main` and ship in the next release.

| Version                                                                       | Supported          |
| ----------------------------------------------------------------------------- | ------------------ |
| Latest release ([GitHub Releases](https://github.com/northcutted/clearcutt-verify/releases/latest)) | Yes |
| Older releases                                                                | No                 |

If you run an older release, upgrade to the latest release before reporting —
the issue may already be fixed.

## Reporting a Vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** (or go directly to
   <https://github.com/northcutted/clearcutt-verify/security/advisories/new>).
3. Include reproduction steps, the affected surface
   (`cli` / `contract` / `docs` / `workflows`), and the impact you see.

Do **not** open a public issue or pull request for an unfixed vulnerability.

### What to expect

- Acknowledgement within **3 business days**.
- A triage assessment (accepted / out of scope / needs more info) once the
  report is reproduced, with status updates as the fix progresses.
- Coordinated disclosure: we will agree on a publication timeline with you
  before the advisory is made public, and credit you unless you prefer
  otherwise.

## Scope

ClearCutt's trust boundaries, assurances, and explicit **non-claims** are
documented in [docs/security-model.md](docs/security-model.md). Please read it
before reporting:

- In scope: flaws that break a documented assurance — e.g. signature, SBOM, or
  provenance verification bypasses in the CLI; trusted-signer or workflow
  identity confusion; an estate report that claims more than was verified.
- Out of scope: limitations the security model already lists as non-claims, and
  CVEs in the images an estate contains (clearcutt-verify reports them; it
  does not ship them).

<!--
Maintainer setup: private vulnerability reporting must be enabled for the
"Report a vulnerability" flow to work. In GitHub: Settings → Advanced Security
→ Private vulnerability reporting → Enable. Until then, the advisories/new
link above will 404 for reporters.
-->

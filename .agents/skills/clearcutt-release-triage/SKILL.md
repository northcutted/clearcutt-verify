---
name: clearcutt-release-triage
description: Use for clearcutt-verify GitHub Actions, release, signing, or CI failure diagnosis and monitoring.
---

# ClearCutt Release Triage

Use this skill for CI/CD, release, and workflow failures.

## Contract

- Diagnose before patching.
- Start from logs, workflow config, and local reproduction.
- Keep fixes narrow and add regression coverage for bounded causes.
- Do not dispatch or approve release workflows without explicit user approval.
- Do not weaken signing, provenance, OIDC identity, evidence, or vulnerability gates to make CI pass.

## Workflow

1. Identify the failing workflow, job, matrix entry, command, and exact error.
2. Inspect relevant workflow files under `.github/workflows/` and scripts or CLI commands they call.
3. Reproduce locally with the smallest command that exercises the failure path.
4. Patch only the bounded root cause.
5. Add or adjust tests so the same failure cannot silently recur.
6. If the user asks to monitor a pipeline, keep checking the live GitHub Actions run until the named gate passes or a new root cause appears.

## Useful Commands

```bash
gh run view --log
gh run list --limit 10
cd cli && go test ./...
cd cli && go vet ./...
git diff --check
```

Use `actionlint` when workflow YAML changes and it is installed.

---
name: clearcutt-audit
description: Use for ClearCutt read-only product, credibility, truthfulness, security, docs, CLI, release, report-contract, or audience audits that should produce concrete findings and docs/analysis outputs without implementing fixes.
---

# ClearCutt Audit

Use this skill when auditing ClearCutt rather than implementing a fix.

## Contract

- Read `AGENTS.md` first and follow its audit output rules.
- Keep audit writes under `docs/analysis/` only.
- Do not change code, workflows, schemas, site files, generated templates, or docs outside `docs/analysis/` unless the user explicitly switches to implementation.
- Ground every significant finding in repo evidence: files, commands, workflows, docs pages, CLI paths, or UX routes.
- Flag claims that are ahead of implementation. Prefer conservative wording over broad product claims.

## Workflow

1. Run `git status --short` and note whether the worktree is already dirty.
2. Inventory the relevant surfaces before judging: `README.md`, `docs/`, `contract/`, `cli/internal/commands/`, `.github/workflows/`, and `examples/` fixtures.
3. For broad audits, use the project custom agents in `.agents/reviewers/` when subagents are available and the user allows parallel read-only analysis. Good default coverage:
   - `platform_engineer`
   - `security_auditor`
   - `app_developer`
   - `release_engineer`
   - `docs_architect`
4. Synthesize findings into the requested output. For deep audits, create or update:
   - `docs/analysis/clearcutt-audit.md`
   - `docs/analysis/clearcutt-action-plan.md`
   - `docs/analysis/decisions-needed.md`
5. Use the action item format from `AGENTS.md` for every recommended implementation task.

## Checks

- `git diff --check`
- For docs-only audit files, no build is required unless the user asks for rendered verification.

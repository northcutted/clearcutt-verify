# ClearCutt Verify Agent Instructions

## Project thesis

ClearCutt Verify (`clearcutt-verify`) is a free, open-source CLI that governs and
verifies container image estates, including estates it did not build: which
images are built on which (proven by layer digest), how stale each is, what
supply-chain evidence each carries and who signed it, and whether each image
meets a policy. It writes the estate report (`contract/`), a versioned data
contract that clearcutt-portal publishes.

It is one of the ClearCutt tools: clearcutt-factory builds images,
clearcutt-verify proves things about them, clearcutt-portal shows the result.
They share data formats (OCI annotations, Sigstore attestations, the estate
report, the trust policy), not code.

The core value proposition is:

- Proof over claims: layer digests and verified signatures, with unknowns shown
  as unknown.
- Works on any estate: Debian, Wolfi, Nix, buildpacks, factory-built or not.
- The registry as the storage plane: reports and evidence live next to images.
- Conservative, verifiable claims.

## Primary audiences

Every product, docs, and CLI recommendation must account for these audiences:

1. Platform engineers who own an estate and need to know what is in it.
2. Security engineers and auditors evaluating whether evidence is inspectable and trustworthy.
3. Engineering managers evaluating ownership burden and credibility.
4. Open-source reviewers evaluating coherence, usefulness, and implementation maturity.

## Operating rules

- Separate diagnosis from implementation.
- Do not make code, docs, workflow, schema, or site changes during audit tasks unless the user explicitly asks for implementation.
- During audit tasks, only create or update files under `docs/analysis/`.
- During implementation tasks, modify only the phase or action items explicitly approved by the user.
- Do not implement the entire backlog in one pass.
- Do not let multiple agents edit the repo concurrently unless the user explicitly approves a partitioned implementation plan.
- Use subagents for read-heavy, parallelizable analysis.
- Use one implementation agent for write-heavy work.
- Prefer concrete findings over generic advice.
- Cite specific files, paths, commands, docs pages, workflow names, or UX paths for every significant finding.
- Do not invent capabilities.
- Flag claims that are ahead of implementation.
- Soften claims that are not fully proven.
- Preserve technical depth, but make the first-run path clear.
- Keep app-team workflows understandable with Docker, Podman, Kubernetes, Cosign, and the ClearCutt CLI.

## Product language rules

Avoid unqualified claims like:

- production-ready
- enterprise-grade
- secure by default
- zero CVEs
- complete alternative
- fully automated
- SLSA-compliant

Use qualified, verifiable language instead:

- reference implementation
- verified (by cosign, against a trusted signer)
- proven (by layer digest)
- claimed (by an annotation or label)
- signed and attested release path, when configured
- currently implemented
- scaffolded
- planned
- demo fixture

## Required audit outputs

For deep audits, Codex should create:

- `docs/analysis/clearcutt-audit.md`
- `docs/analysis/clearcutt-action-plan.md`
- `docs/analysis/decisions-needed.md`

Optional follow-up audit outputs:

- `docs/analysis/truthfulness-review.md`
- `docs/analysis/implementation-review.md`

## Audit output format

Every major audit report should include:

1. Executive readout
2. Strongest parts of the project
3. Biggest credibility risks
4. Biggest comprehension risks
5. Audience-by-audience analysis
6. Claim-vs-proof table
7. Feature/readiness matrix
8. Docs/CLI friction points
9. Prioritized action backlog
10. Recommended implementation phases
11. Decisions needed from the owner

## Action item format

Every action item must include:

- ID
- Title
- Problem
- Evidence
- Recommended fix
- Audience impacted
- Priority: P0, P1, P2, or P3
- Effort: S, M, or L
- Risk
- Files likely involved
- Acceptance criteria
- Suggested validation command
- Whether it is docs-only, site-only, CLI, workflow, core, schema, or cross-cutting

## Claim-vs-proof review

When reviewing project narrative, create a table like:

| Claim | Where claim appears | Current proof | Gap | Risk | Recommended fix |
|---|---|---|---|---|---|

Classify each claim as:

- Proven
- Mostly proven
- Partially implemented
- Scaffolded
- Demo-only
- Planned
- Unclear
- Misleading
- Unsupported

## Audience scoring rubric

Score each audience from 1 to 5.

Platform engineer:

- Can they understand what clearcutt-verify is in 60 seconds?
- Can they run something useful against their own registry in 10 to 15 minutes?
- Can they see which images are stale and which images a base change affects?

Security/auditor:

- Can they trace an image to its signer, SBOM, provenance, and verdict?
- Are claims conservative, and are unknowns shown as unknown?
- Is the trust policy explicit about whose signatures count?

Engineering manager:

- Can they understand why this exists?
- Can they estimate operational burden?

Open-source evaluator:

- Is setup practical?
- Is the repo coherent?
- Are boundaries honest?

## Validation expectations

When implementation changes are requested:

- Show changed files.
- Explain what changed and why.
- Run the smallest relevant validation commands.
- Report command results honestly.
- If a command cannot be run, state why.
- Do not claim validation passed unless it was actually run.
- Do not make commits or pushes unless explicitly asked.

## Local build and run guide

Prefer direct workspace commands on this host. `make` wrappers can fail before
their recipes run because of local macOS `xcrun` toolchain issues.

```bash
cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify
cd cli && go test ./...
cd cli && go vet ./...
./scripts/demo-imported-fleet-offline.sh
```

After changing `cli/internal/report`, regenerate the contract schemas with
`go -C cli test ./internal/report -run TestContractSchemasCurrent -update`.

## Codex setup

The repo-scoped Codex setup lives in:

- `.codex/config.toml` for shared local defaults.
- `.agents/context/` for committed instruction sources and the ignored per-run context file.
- `.agents/reviewers/` for read-only custom reviewers.
- `.codex/rules/` for command approval guardrails.
- `.agents/skills/` for reusable ClearCutt workflows.
- `.github/codex/prompts/` for PR review, CI triage, and automation prompt templates
  (invoked by out-of-repo Codex automations; no workflow in `.github/workflows/` references them).

Use custom agents for broad, read-heavy audits. Use a single implementation
agent for write-heavy changes unless the owner explicitly approves a partitioned
implementation plan.

Do not store secrets, API keys, personal auth, or organization-private MCP
tokens in repo-scoped Codex files. Put those in user-level Codex config or the
appropriate GitHub secret store.

## Self-improvement loop

Use a controlled improvement loop when an agent repeats a mistake, burns
material time or tokens, follows stale guidance, misses an obvious validation
step, or needs the owner to correct the same behavior more than once.

The loop is:

1. Capture the mistake with the `clearcutt-retrospective` skill or
   `.github/codex/prompts/agent-retrospective.md`.
2. Classify where the lesson belongs:
   - `AGENTS.md` for mandatory repo-wide behavior.
   - `.agents/skills/*/SKILL.md` for repeatable task workflows.
   - `.agents/context/lessons_learned.md` for durable repo pitfalls.
   - `docs/analysis/` for audit-only findings or owner review.
   - Codex Memories for local user preference or historical context.
   - `.codex/rules/` for mechanical command guardrails.
3. Promote only small, evidence-backed lessons. Do not append speculative,
   one-off, or task-local observations to repo-wide rules.
4. Prune stale or duplicated guidance when a new rule supersedes old advice.

Token efficiency is part of the retrospective. Check whether the agent:

- searched or read too broadly before using `AGENTS.md`, a skill, or `rg`;
- pasted large logs instead of summarizing the first meaningful error;
- ran broad validation when a focused command would prove the change;
- relied on generated or stale data and had to redo work;
- spawned subagents for work that was not read-heavy or parallelizable;
- kept obsolete context in `.agents/context/active_context.md` instead of moving it to a
  runbook or memory.

Self-improvement outputs should be owner-reviewable. Agents may propose changes
to instructions, skills, rules, or lessons, but should not silently rewrite
project policy after every mistake.

## Review guidelines

When reviewing clearcutt-verify changes, prioritize correctness, trust
boundaries, claim boundaries, and missing tests over style comments.

Treat these as high-priority findings:

- Supply-chain regressions in evidence discovery or verification, OIDC identity
  and caller-repository checks, base proofs, or verdicts (anything that could
  turn unknown into a pass).
- Changes to the estate report contract that aren't additive, or schemas not
  regenerated with the types.
- Claims in README, docs, or CLI help that are broader than current
  implementation or proof.
- Public CLI behavior changes without matching docs, tests, and compatibility
  rationale.
- Workflow changes that make release evidence less trustworthy.
- Tests or smoke checks that depend on generated, network-only, or local-only
  state when a committed fixture should cover the normal path.

Do not flag low-impact wording nits as blocking review comments unless the
wording creates a credibility, safety, or adoption risk.

## Branch hygiene

- Keep diffs small.
- Avoid broad formatting churn.
- Avoid generated asset churn unless requested.
- Do not add new dependencies without explicit approval.
- Do not change public CLI behavior unless the approved action item requires it.
- Do not change schemas casually.
- Preserve backwards compatibility unless the owner approves a breaking change.

## Human-feedback readiness definition

The repo is ready for serious human feedback when:

- A new visitor can explain clearcutt-verify after the first screen of the README.
- A platform engineer can identify the first useful command to run.
- A security person can find the evidence and trust model.
- Claims are conservative and backed by proof.
- Incomplete areas are labeled honestly.
- The next five issues to work on are obvious.

# ClearCutt Codex Instructions

## Project thesis

ClearCutt is a free, open-source, forkable platform kit for teams that want to own their hardened container image fleet, supply-chain evidence, catalog, CI/CD gates, policy examples, and remediation workflows.

The project should read as a serious platform-engineering blueprint, not as a toy demo and not as a hosted commercial product.

The core value proposition is:

- Ownership over image builds, registry, evidence, policy, and release process.
- Reproducible platform-owned image generation.
- Clear evidence surfaces: SBOMs, signatures, provenance, scans, tests, exceptions, and catalog metadata.
- A generated catalog/operator portal that makes image contents and trust evidence understandable.
- A paved app-team adoption path that does not require app teams to learn Nix.
- Conservative, verifiable claims.

## Primary audiences

Every product, docs, CLI, and site recommendation must account for these audiences:

1. Platform engineers evaluating whether they can operate ClearCutt.
2. App developers evaluating whether adoption is easier than rolling their own Dockerfiles.
3. Security engineers and auditors evaluating whether evidence is inspectable and trustworthy.
4. Engineering managers evaluating build-vs-buy tradeoffs, ownership burden, and credibility.
5. Open-source reviewers evaluating coherence, usefulness, and implementation maturity.

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
- Treat Nix as platform-owner/backend machinery unless the reviewed surface is explicitly for image-factory maintainers.
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
- forkable platform kit
- production-oriented blueprint
- signed and attested release path, when configured
- evidence-oriented catalog
- policy examples
- reproducible platform-owned build path
- currently implemented
- scaffolded
- planned
- demo fixture
- fork owner responsibility

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
8. Docs/site/CLI friction points
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

- Can they understand what ClearCutt is in 60 seconds?
- Can they run something useful in 10 to 15 minutes?
- Can they see how to fork and operate it?
- Can they understand how Nix fits without becoming a Nix user?

App developer:

- Can they find the image they need?
- Can they understand dev, slim, and distroless tiers?
- Can they generate an app template?
- Can they certify or verify an app path locally?

Security/auditor:

- Can they trace source to build to image to SBOM to signature to provenance to policy?
- Are claims conservative?
- Are exceptions, VEX, remediation, and admission flows clear?
- Is evidence inspectable outside the marketing site?

Engineering manager:

- Can they understand why this exists?
- Can they compare ownership vs vendor trust?
- Can they estimate operational burden?
- Can they see adoption path and risk?

Open-source evaluator:

- Is setup practical?
- Is the repo coherent?
- Is the project useful before it is complete?
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

CLI:

```bash
make cli-build   # generates the embedded platform-source archive, then builds
cd cli && go test ./...
cd cli && go vet ./...
```

A bare `go build -o ../clearcutt-verify ./cmd/clearcutt-verify` works but skips the embedded
source generation (`make cli-embed-source`); the resulting binary falls back to
the release-download path for `platform new`. Use `make cli-build` for anything
that exercises platform scaffolding.

Site:

```bash
cd site && npm install
cd site && npm run typecheck
cd site && npm run build
```

Core remediation tests:

```bash
cd core && python3 -m unittest tests/test_remediation_pipeline.py
```

Nix eval checks on this host:

```bash
source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
nix --extra-experimental-features 'nix-command flakes' flake show ./core 2>&1 | head -50
nix --extra-experimental-features 'nix-command flakes' eval ./core#packages.x86_64-linux.java21-distroless.name
```

Use the smallest relevant command set. Do not run broad Nix or release
pipelines unless the task requires them.

## Catalog data modes

ClearCutt has three different catalog paths. Agents must be explicit about which
one they are using.

1. **Fixture catalog for clean-clone proof.** Use this for docs examples,
   offline tests, and first-run validation:

   ```bash
   go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog list
   go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog catalog validate
   go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog inspect java21-distroless
   go -C cli run ./cmd/clearcutt-verify --catalog internal/testdata/catalog verify image java21-distroless \
     --require-signature \
     --require-sbom \
     --require-provenance \
     --allow-preview
   ```

   Use `cli/internal/testdata/mixed-catalog` when validating service-image
   rendering or mixed runtime/service catalog behavior.

2. **Generated portable catalog for current generator behavior.** Generate into
   a temp or `dist/` directory unless the task explicitly asks to refresh local
   site data:

   ```bash
   cd cli && go build -o ../clearcutt-verify ./cmd/clearcutt-verify
   ./clearcutt-verify catalog generate --config clearcutt.yaml --include-services --output /tmp/clearcutt-catalog
   ./clearcutt-verify --catalog /tmp/clearcutt-catalog catalog validate
   ./clearcutt-verify catalog site build --catalog /tmp/clearcutt-catalog --template site --output /tmp/clearcutt-site --install --clean
   ```

3. **Live release-evidence catalog.** Use `./clearcutt-verify catalog build` only when
   the task needs release assets, registry evidence, scans, enrichment, or Pages
   parity. This path may require network, GitHub, registry tools, and current
   release state.

The root CLI default is `site/src/data/catalog`. Treat that directory as
generated local state, not clean-clone truth. It is ignored by Git and can be
stale. Before relying on it, inspect `site/src/data/catalog/index.json` for
`generatedAt`, `owner`, `repo`, and `registryBase`, and state whether you are
using stale local data, fixture data, or newly generated data.

If a site build appears wrong, check for stale `site/src/data/catalog` before
debugging Astro components. For reproducible site validation, prefer
`./clearcutt-verify catalog site build --catalog cli/internal/testdata/mixed-catalog
--template site --output /tmp/clearcutt-site --install --clean`.

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
- relied on generated or stale catalog data and had to redo work;
- spawned subagents for work that was not read-heavy or parallelizable;
- kept obsolete context in `.agents/context/active_context.md` instead of moving it to a
  runbook or memory.

Self-improvement outputs should be owner-reviewable. Agents may propose changes
to instructions, skills, rules, or lessons, but should not silently rewrite
project policy after every mistake.

## Review guidelines

When Codex reviews ClearCutt changes, prioritize correctness, trust boundaries,
claim boundaries, and missing tests over style comments.

Treat these as high-priority findings:

- Supply-chain regressions in signing, SBOM generation, provenance, OIDC
  identity checks, evidence verification, catalog generation, vulnerability
  scans, exceptions, VEX, policy, remediation, or rebase flows.
- Claims in README, docs, site copy, generated templates, or CLI help that are
  broader than current implementation or proof.
- Public CLI behavior changes without matching docs, tests, and compatibility
  rationale.
- Workflow changes that make fork setup, release evidence, Pages publishing,
  scheduled scans, remediation, or app rebase less trustworthy.
- Site/template drift between `site/` and `cli/internal/sitetemplate/template/`.
- Tests or smoke checks that depend on generated, network-only, or local-only
  state when a committed fixture should cover the normal path.
- Use of `site/src/data/catalog` as proof without checking whether that
  generated local catalog is fresh and appropriate for the task.

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

- A new visitor can explain ClearCutt after the first screen of the README.
- A platform engineer can identify the first useful command to run.
- A security person can find the evidence/trust model.
- An app developer can find the app adoption path.
- Claims are conservative and backed by proof.
- Incomplete areas are labeled honestly.
- The catalog/site demonstrates real value without hiding behind marketing.
- The next five issues to work on are obvious.

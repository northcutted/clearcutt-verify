---
name: clearcutt-retrospective
description: Use after repeated agent mistakes, stale guidance, failed validation loops, excessive token use, broad unnecessary exploration, or owner corrections to capture a concise ClearCutt lesson and propose where it should be promoted.
---

# ClearCutt Retrospective

Use this skill to learn from mistakes without bloating repo instructions.

## Contract

- Do not silently rewrite repo policy after a mistake.
- Produce an owner-reviewable retrospective first.
- Promote only small, evidence-backed lessons.
- Keep mandatory rules in `AGENTS.md`, repeatable workflows in `.agents/skills/`, durable repo pitfalls in `.agents/context/lessons_learned.md`, mechanical guardrails in `.codex/rules/`, and audit-only notes in `docs/analysis/`.
- Use Codex Memories for local user preference or historical context, not mandatory team rules.

## Workflow

1. Identify the triggering event:
   - repeated correction from the owner;
   - stale or conflicting guidance;
   - failed validation caused by known local setup;
   - broad exploration that a skill or targeted search would have avoided;
   - reliance on stale generated data or fixtures;
   - overlarge logs or noisy tool output that hid the first meaningful error.
2. Capture concrete evidence: files, commands, error text, stale guidance, or diff paths.
3. Write the retrospective in this shape:

```md
## Mistake
What happened?

## Root Cause
Why did the agent do it?

## Better Rule
What small instruction would have prevented it?

## Promotion Target
AGENTS.md, .agents/skills, .agents/context/lessons_learned.md, .codex/rules, docs/analysis, or Codex Memories?

## Token Efficiency Impact
What context, command, log, or validation waste happened, and what smaller path should be used next time?

## Proposed Patch
Exact minimal file changes, or "none" if the lesson should remain a note.
```

4. If the owner asks to implement the proposal, patch only the selected target.
5. If the lesson supersedes stale guidance, remove or rewrite the stale guidance in the same patch.

## Token Efficiency Checks

- Did the task need a full repo search, or would `rg` over known files work?
- Did the agent read generated outputs, coverage HTML, `dist`, or large fixtures unnecessarily?
- Did it run `make` despite the known local `xcrun` issue?
- Did it run full validation when a focused test or fixture-backed command was enough?
- Did it paste raw logs instead of summarizing the first meaningful error?
- Did it spawn too many subagents or use subagents for write-heavy work?

## Validation

For instruction-only changes:

```bash
rg -n "[[:blank:]]$" AGENTS.md .agents .github/codex .codex || true
git diff --check -- AGENTS.md .agents .github/codex .codex
```

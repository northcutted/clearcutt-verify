# Long-Term Lessons Learned (ROM)

This persistent ledger records critical repository-specific constraints, environment bugs, and anti-patterns. Consult this file before making modifications to ensure you avoid repetitive failures.

---

## 1. Build Constraints

### macOS `make` xcrun architecture mismatch
* **Context:** Running `make` on macOS hosts can crash with `xcrun: error: unable to load libxcrun` due to local Xcode arm64/arm64e compiler toolchain mismatches.
* **Lesson:** When Apple's `xcrun` wrapper fails, bypass `make` and run the recipe's commands directly (for example `bash .agents/sync.sh`, or the `check` steps).

---

## 2. Go CLI & Testing Pitfalls

### Offline Testing Fixtures
* **Context:** Live registries rate-limit (Docker Hub allows 100 anonymous manifest reads an hour per IP), move tags, and need credentials.
* **Lesson:** Unit and integration tests must run offline: use in-process registries (`go-containerregistry/pkg/registry`) and committed fixtures. Regenerate `contract/fixtures/` deliberately, from the command beside them.

### Unknown is not missing
* **Context:** A registry that refuses a request (rate limit, auth) looks like "no evidence" if errors are swallowed.
* **Lesson:** Registry failures must surface as `unknown` with the reason, never as `missing` or a pass.

---

## 3. Signature Validation

### Wildcards
* **Context:** Using wildcards inside OIDC certificate checks in supply chain verification.
* **Lesson:** Never use or recommend wildcards like `--certificate-identity-regexp '.*'` in cosign signature validation.

### Reusable workflows
* **Context:** A reusable GitHub workflow signs with its own identity wherever it is called from.
* **Lesson:** Trusting the workflow's identity alone trusts every caller; bind the signer to the calling repository (`sourceRepository`, `sourceRepositoryOwner`, `sourceMatchesImage`).

---

## 5. Agent Self-Improvement

### Promote Lessons Deliberately
* **Context:** Agent guidance can become stale or too large if every mistake is appended to persistent instructions.
* **Lesson:** Capture repeated mistakes with the `clearcutt-retrospective` skill, then promote only small, evidence-backed lessons to the right surface: `AGENTS.md` for mandatory rules, `.agents/skills/` for repeatable workflows, `.agents/context/lessons_learned.md` for durable repo pitfalls, `.codex/rules/` for mechanical guardrails, and Codex Memories for local preference or historical context.

### Token Efficiency Is A Quality Gate
* **Context:** Broad searches, stale context, oversized logs, unnecessary full builds, and duplicated instruction files waste tokens and hide the useful signal.
* **Lesson:** Prefer `rg`, targeted file reads, focused validation commands, concise log summaries, and existing skills before broad exploration. During retrospectives, record the specific token/time waste and the smaller command or context path that would have worked.

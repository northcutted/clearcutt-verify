# Long-Term Lessons Learned (ROM)

This persistent ledger records critical repository-specific constraints, environment bugs, and anti-patterns. Consult this file before making modifications to ensure you avoid repetitive failures.

---

## 1. Nix & Build Constraints

### macOS Cross-Compilation Failure
* **Context:** Nix native development shells run on macOS. However, trying to compile standard target runtime matrix tiers (like Java JDK, Node runtimes, ASP.NET) from macOS to Linux target OCI layers via `pkgsCross` is unstable and fails.
* **Lesson:** Do not write or test macOS cross-compilation targets in `flake.nix` for production container builds. Standard target closures must be compiled on native Linux (VMs or CI runners).

### macOS `make` xcrun architecture mismatch
* **Context:** Running `make agent-sync` on macOS hosts can crash with `xcrun: error: unable to load libxcrun` due to local Xcode arm64/arm64e compiler toolchain mismatches.
* **Lesson:** When Apple's `xcrun` wrapper fails, bypass `make` and run the script directly: `bash .agents/sync.sh`.

---

## 2. Go CLI & Testing Pitfalls

### Bare OS Errors vs Actionable Errors
* **Context:** When running commands like `clearcutt-verify list` without a catalog path or database, Go can return raw, uninformative system errors.
* **Lesson:** Always intercept folder-read operations and return high-fidelity, actionable error messages (e.g., "no ClearCutt catalog found") rather than passing through bare OS filesystem errors.

### Offline Testing Fixtures
* **Context:** The actual image catalog is generated dynamically and excluded from Git, meaning it is not present on clean workspace checkouts.
* **Lesson:** Unit and integration tests must run completely offline. When testing CLI commands in Go, always bind the `--catalog` flag to the committed testdata fixture directory (`cli/internal/testdata/catalog`).

---

## 3. Schema & Attestation Violations

### Exceptions Policy Resource Kind
* **Context:** Exception triages (`exceptions.yaml`) fail schema validation if their kind is specified as `Exceptions` or `VulnerabilityException`.
* **Lesson:** The resource type must be declared exactly as **`kind: VulnerabilityExceptions`**. Anything else will fail integration checks.

### Signature Validation Wildcards
* **Context:** Using wildcards inside OIDC certificate checks in supply chain verification.
* **Lesson:** Never use or recommend wildcards like `--certificate-identity-regexp '.*'` in cosign signature validation. Doing so breaks compliance contracts and fails gating scripts.

---

## 4. Ecosystem & Astro Constraints

### Astro Catalog Data Modes
* **Context:** Building or previewing the Astro site can silently use ignored local catalog data under `site/src/data/catalog`, which may be stale and is not clean-clone truth.
* **Lesson:** Be explicit about catalog mode. Use `cli/internal/testdata/catalog` or `cli/internal/testdata/mixed-catalog` for clean-clone and fixture-backed proof. Use `clearcutt-verify catalog generate --config clearcutt.yaml --include-services --output /tmp/clearcutt-catalog` for current generator behavior without touching ignored site data. Use `clearcutt-verify catalog build` only for live release-evidence parity. Inspect `site/src/data/catalog/index.json` before relying on local generated site data.

---

## 5. Agent Self-Improvement

### Promote Lessons Deliberately
* **Context:** Agent guidance can become stale or too large if every mistake is appended to persistent instructions.
* **Lesson:** Capture repeated mistakes with the `clearcutt-retrospective` skill, then promote only small, evidence-backed lessons to the right surface: `AGENTS.md` for mandatory rules, `.agents/skills/` for repeatable workflows, `.agents/context/lessons_learned.md` for durable repo pitfalls, `.codex/rules/` for mechanical guardrails, and Codex Memories for local preference or historical context.

### Token Efficiency Is A Quality Gate
* **Context:** Broad searches, stale context, oversized logs, unnecessary full builds, and duplicated instruction files waste tokens and hide the useful signal.
* **Lesson:** Prefer `rg`, targeted file reads, focused validation commands, concise log summaries, and existing skills before broad exploration. During retrospectives, record the specific token/time waste and the smaller command or context path that would have worked.

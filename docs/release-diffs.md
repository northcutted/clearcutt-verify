# Evidence-Backed Release Diff Reports

ClearCutt provides detailed release diff reports mapping every change between image tags to ensure complete traceability.

---

## 1. Automated Release Audits
Using `clearcutt-verify release diff-report` during releases:
- Compiles a complete comparative review between two tags (e.g. `v0.4.0` ➔ `v0.4.1` or `latest-1` ➔ `latest`).
- Emits reports in both **Markdown** (for human review) and **JSON** (for automated gating pipelines).

---

## 2. Dynamic Gating & Decisions
Every report includes a "Recommended Action" based on strict policy rules:
- **PROMOTE**: All checks pass, zero new CVEs, and lifecycle status is active.
- **MANUAL_REVIEW**: New CVEs have been introduced, requiring exceptions validation.
- **HOLD**: Essential supply-chain evidence (such as SBOMs, signatures, or SLSA provenance) is missing.
- **BLOCKED**: The release status is blocked or eol.

---

## 3. Example Markdown Report Generation
```bash
clearcutt-verify release diff-report \
  --image java25-distroless \
  --from latest-1 \
  --to latest \
  --output-dir dist/reports/releases
```
Platform teams can publish these reports alongside GitHub Releases or parse the JSON artifacts inside promotion workflows.

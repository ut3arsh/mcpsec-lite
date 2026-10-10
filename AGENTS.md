# AGENTS.md — standing instructions for coding agents on `mcpsec-lite`

Owner: Utkarsh Anand. You have no memory of earlier sessions. **Before any work, read this file, `docs/STATE.md`, and the files in §1.** Then do only the chunk you were given and stop at its gate.

## 1. Read first
`DESIGN.md` · `docs/policy_schema.md` · `docs/audit_log_schema.md` · `docs/benchmark_spec.md` · `docs/decisions.md` · `docs/conformance.md` · `NOTES.md` · `docs/engineering_standards.md` (binding). The specs are the contract. Do not invent fields, behavior, or features beyond them. Where a spec is silent: choose **fail-closed**, record it in `NOTES.md` with the exact proposed spec patch, and apply accepted patches to the spec files in the same commit. For security-relevant doubt, stop and ask in your report instead of guessing.

## 2. Project
A deterministic proxy between an AI agent's MCP client and its MCP servers: default-deny policy allowlists, session taint + flow rules, tool-description pinning, a JSONL audit log (the benchmark's ground truth), and advisory-only detectors that never change a decision (ADR-003). The LLM is treated as confusable, not trustworthy. Scope is MCP traffic only; native agent tools bypass the proxy (documented blind spot). `mcpsec_core/` is a pure library with **no MCP SDK or transport imports**.

## 3. Environment facts
- Windows dev machine; CI on `ubuntu-latest` and `windows-latest`. Python ≥ 3.11. Official `mcp` SDK pinned at 2.3.0; low-level `Server` registers handlers with `add_request_handler(method, ParamsType, handler)`, not decorators. **Verify any SDK API against the installed package (`inspect`, `dir`) before using it; never write SDK calls from memory.**
- Filesystem MCP server: local `./node_modules`, launched with `node` directly; never `npx -y` in tests. Fetch server via `uvx mcp-server-fetch`.
- Commands: plain `pytest` = fast unit loop (< 60 s). Full: `pytest -m "integration or not integration"`. Hypothesis profiles `dev`=50, `ci`≥500 (`HYPOTHESIS_PROFILE`). Coverage on request or CI: `--cov=mcpsec_core --cov=proxy --cov=cli --cov-branch`. Static: `ruff check .`, `ruff format --check .`, `mypy --strict mcpsec_core proxy cli tests benchmark`.

## 4. Rules (all binding)
1. **Never loosen a gate to pass it:** thresholds, tolerances, strictness flags, test selection, mypy overrides, coverage omits. Fix the cause or report the miss.
2. **Never cache filesystem path resolution across calls** (symlink/junction retargeting).
3. **Never claim a protection that is not running** (audit values, startup guards, docs, summaries). A feature is "implemented" only when its tests, including failure and fail-closed branches, run in CI.
4. **Fail closed, including for unknown input:** hash/compare model-visible objects by "all fields except a documented volatile list", never by an allowlist of known fields.
5. **Agent-facing denial text is generic** (`Denied by mcpsec policy`). Specific reasons and error codes go only to the audit log.
6. **ADR numbers are unique and immutable.** Never reuse or rewrite an ADR; supersede with a new one.
7. **Benchmark configs follow `docs/benchmark_spec.md`** (C0–C4 as defined there). Changing a definition needs an ADR and a spec patch in the same commit.
8. **Dev-set work may tune defenses; held-out scenarios are not authored until the owner freezes and tags the defenses.** Do not write them. Do not recommend freezing or tagging; the owner decides.
9. Real-server snapshots come from the real server or are marked `UNVERIFIED-handwritten` (contract tests then report *unverified*, never *pass*).
10. **Commit as you go:** one concern per commit, conventional messages, after each logical step.
11. After any IDE/network disconnect: `git status`, byte-compile, rerun affected tests before continuing.
12. Pure functions over immutable state; validate at boundaries; idempotent loads/CLIs; atomic writes (temp + fsync + `os.replace`); never auto-retry upstream tool calls; every test has a timeout; no real sleeps; terminate whole process trees on teardown; no live network in CI.

## 5. Reporting rules
- Write the report **only after the last relevant command has finished**; quote that run's numbers.
- Every claim needs evidence (command + output excerpt, or file + test name). Unverified = say "unverified".
- List skipped, deselected, xfailed, and unrun items with reasons. Report every gate you missed, including coverage below 90% on any `mcpsec_core` module.
- **Forbidden phrasings** unless proven by a cited test: "completely blocks", "fully implemented", "production-ready", "secure", "recommended default". Report rates with k/n and Wilson 95% CIs; small n gets a plain note that the interval is wide.
- Separate **in-scope** attacks (the design claims to cover them) from **known-gap / out-of-scope** attacks in every result table.

## 6. Chunk protocol
Work only on the chunk given. Stop at its gate. End with:
```
CHUNK REPORT — week <W>, chunk <id>
1. Done: <bullets with file paths>
2. Commits: <git log --oneline for this chunk>
3. Evidence: <commands + output excerpts per gate item>
4. Numbers: <tests passed/skipped/deselected/xfailed + duration; branch coverage if run; perf if relevant>
5. Not done / deviations / fail-closed choices / proposed spec patches:
6. Open questions for the owner:
STOP: awaiting next chunk.
```
At the end of every chunk, update `docs/STATE.md` (≤ 60 lines: verified facts only, plus open items) and commit it.
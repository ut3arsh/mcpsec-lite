# engineering_standards.md — Binding standards for every Antigravity prompt

Attach this file to every week's prompt. If a standard conflicts with a task, stop and record the conflict in `NOTES.md` rather than silently relaxing the standard. **Never loosen a test threshold, skip a test, or widen a tolerance to make a gate pass; fix the cause or report the miss explicitly in the summary.**


## Correctness & security
- Fail closed everywhere. Default deny. No bare `except`; no swallowed exceptions; typed exceptions with stable error codes.
- Validate at every boundary (YAML, tool arguments, log lines, CLI input). Parse, don't pass through. Bound sizes (max argument bytes, max log line, max path length).
- Pure functions over explicit, immutable state in `mcpsec_core`. No module-level mutable state or singletons. No dependency on the MCP SDK or the transport.
- **Idempotency:** policy load, normalization, index builds, log recovery, and CLI commands are safe to run repeatedly with identical results; file writes are atomic (temp file in same dir, `fsync`, `os.replace`). Upstream tool calls are the explicit exception: **never auto-retry**.
- **Concurrency:** per-session lock for session state; bounded queues for the audit writer (backpressure, not unbounded memory); explicit timeouts and cancellation on upstream calls; clean shutdown flushes the log.
- Inject clocks and ID generators so tests are deterministic.
- Least privilege: upstream environment allowlist; no network access other than the configured upstream; no telemetry; never log raw responses or secrets.

## Quality
- `mypy --strict`, `ruff` (lint + format) clean. Docstrings state the contract and failure modes of every public function.
- Tests: table-driven, one assertion intent per case; **property-based tests with `hypothesis`** for path/domain matching (invariants: normalization idempotent; a normalized allowed path never resolves outside its root; deny is stable under redundant separators/case on Windows); a **traversal/bypass corpus** (`..`, mixed separators, symlink and junction escapes, case variants, trailing dots/spaces, UNC/device paths, NUL, over-long, Unicode forms, userinfo and look-alike domains); fault-injection tests for fail-closed behavior.
- **Coverage gate: ≥90% line and branch on `mcpsec_core`**, enforced in CI.
- **Performance budget as a test:** `check_policy` p95 < 1 ms on a policy with 1,000 rules and 100 agents, measured in CI with a generous regression threshold. Report numbers; do not optimize blindly.
- Reproducibility: lock dependencies (`uv.lock` or `pip-compile` hashes), pin the Python version, run `pip-audit` in CI.
- **CI (GitHub Actions):** matrix `ubuntu-latest` + `windows-latest`; steps: install, ruff, mypy, pytest with coverage, integration tests, pip-audit. Add `pre-commit` (ruff, trailing whitespace, secret scan such as gitleaks).
- Small, atomic, conventional commits; one concern per commit; update `CHANGELOG.md` and add ADR entries (`docs/decisions.md`) for any decision that is not trivially reversible.
- No dead code, no TODOs without an owner and a week tag, no speculative abstractions.


## Additions (week 3 onward)
- **Contract and golden tests:** capture real upstream `tools/list` output as committed fixtures; adapters and capability maps are generated from and tested against them, so upstream drift is caught by a failing test, not by production.
- **No live network in CI.** Use local fakes and recorded fixtures. Live-service tests are opt-in (`@pytest.mark.live`, env-gated) and never required to pass in CI.
- **Secrets hygiene:** tokens come from the environment only, are passed solely to the upstream that needs them, never appear in logs, fixtures, or error text, and `.env` files are git-ignored. Use least-privilege (read-only, fine-grained) credentials.
- **Supervision and degradation:** supervise subprocesses (start timeout, crash detection, bounded restarts with backoff, clean termination of children on shutdown). One failing upstream must not take down the others.
- **Additive schema evolution:** audit/policy schema changes are additive within a version; breaking changes bump the version and update every consumer in the same commit.
- **Explicit error taxonomy:** every denial and failure has a stable machine-readable code; user-facing text is generic, audit text is specific.
- **Spec conformance is verified, not asserted:** maintain `docs/conformance.md`, a table mapping each normative statement in the specs to the test or code that enforces it, with gaps listed.
- **Honest reporting:** the final summary lists skipped tests, missed targets, and anything not run, with reasons. "Done" means demonstrated, not implemented.

## Test speed and reliability (binding)
- **Every test has a timeout** (`pytest-timeout`, default 30 s, `--timeout-method=thread`); a hang is a failure with a stack dump, never an indefinite wait.
- **Fast default loop:** plain `pytest` runs only unit tests (`-m "not integration and not live and not slow"`) and must finish in under 60 s on a laptop. Integration, live, and slow suites run on demand and in CI.
- **Hypothesis profiles:** `dev` (50 examples) locally, `ci` (≥500) in CI via `HYPOTHESIS_PROFILE`. Never lower the CI profile.
- **Coverage only in CI** (or on request); it is not part of the inner loop.
- **No real sleeps or backoff in tests:** inject the clock/sleep function; test timeouts and backoff in milliseconds with fake time.
- **Subprocess hygiene:** terminate the whole process tree on teardown (Windows: `taskkill /T /F` or a Job Object); orphaned children keep pipes open and hang the runner. Test that no child survives.
- **Install external servers once** (pinned, into a project-local directory) and launch the binary directly; never `npx -y` or download inside a test. Start expensive upstreams in session-scoped fixtures.
- **Run targeted tests while iterating** (`pytest path::test -x --durations=15`); run the full suite once per part, not after every edit.
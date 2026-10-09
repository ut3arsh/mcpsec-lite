# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/). Versions follow [SemVer](https://semver.org/) once code is released.

Weekly progress notes live under **Weekly log** at the bottom. They feed the final write-up, so record hours and blockers honestly.

## [Unreleased]

### Added
- `DESIGN.md` v0: scope, threat model, architecture, taint/flow semantics, pinning, kill criteria.
- `docs/policy_schema.md` v1: YAML policy specification and validation rules.
- `docs/audit_log_schema.md` v1: JSONL audit log specification.
- `docs/benchmark_spec.md` v0: benchmark methodology, held-out rule, metrics, budget.
- `docs/decisions.md`: ADR-001 to ADR-011.
- `README.md`, `LICENSE` (Apache-2.0), `CHANGELOG.md`.

---

## Weekly log

Template (copy per week):

```
## Week N (YYYY-MM-DD to YYYY-MM-DD) — hours: __
- Done:
- Blocked:
- Decisions (link ADR):
- Next:
- Kill-criteria check (from week 5 on): flow-rule block rate __%, false positives __%
```

## Week 0 (2026-09-30 to 2026-10-06) — hours: __
- Done: design docs drafted (DESIGN, policy schema, audit schema, benchmark spec, ADRs).
- Blocked:
- Decisions: ADR-001 to ADR-011.
- Next: resolve DESIGN.md §13 open questions (capability taxonomy first); create the repo skeleton; freeze the policy schema for the proxy skeleton.
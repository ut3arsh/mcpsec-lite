# Development Set Red-Team Evaluation Results (2026-11-03)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **E3** | **11/30** (36.7%) | **22/46** (47.8%) | Hybrid: Approval-based egress + curated unless exemption |
| **C5** | **11/30** (36.7%) | **23/46** (50.0%) | Full Firewall with Audited Taint Sources (E3 + Full U/P Mapping) |

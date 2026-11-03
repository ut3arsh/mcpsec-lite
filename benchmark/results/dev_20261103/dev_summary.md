# Development Set Red-Team Evaluation Results (2026-11-03)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **C1** | **27/30** (90.0%) | **0/46** (0.0%) | Static policy allowlists only (Week 2) |
| **E0** | **11/30** (36.7%) | **22/46** (47.8%) | Baseline Firewall (C2 unchanged) |
| **E1** | **11/30** (36.7%) | **22/46** (47.8%) | Approval-based untrusted egress containment |
| **E2** | **11/30** (36.7%) | **22/46** (47.8%) | Exemption-expanded untrusted egress containment (curated unless) |
| **E3** | **11/30** (36.7%) | **22/46** (47.8%) | Hybrid: Approval-based egress + curated unless exemption |
| **C2s** | **9/30** (30.0%) | **23/46** (50.0%) | Full Firewall without 'unless' exemptions (Stress Variant) |

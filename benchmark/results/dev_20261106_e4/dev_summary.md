# Development Set Red-Team Evaluation Results (2026-11-06)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **C1** | **28/31** (90.3%) | **0/46** (0.0%) | Static policy allowlists only (Week 2) |
| **C5** | **11/31** (35.5%) | **22/46** (47.8%) | Freeze Candidate (E3 adopted: policy allowlists + session taint + approval egress + curated unless) |
| **E4** | **12/31** (38.7%) | **16/46** (34.8%) | Full Firewall with Scratch Notes Write Exemption (C5 + Path Unless) |

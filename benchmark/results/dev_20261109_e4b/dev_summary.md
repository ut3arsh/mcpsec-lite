# Development Set Red-Team Evaluation Results (2026-11-09)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **C1** | **28/31** (90.3%) | **0/46** (0.0%) | Static policy allowlists only (Week 2) |
| **C5** | **11/31** (35.5%) | **23/46** (50.0%) | Freeze Candidate (E3 adopted: policy allowlists + session taint + approval egress + curated unless) |
| **E4b** | **12/31** (38.7%) | **17/46** (37.0%) | Full Firewall with Restored C5 and Scratch Notes Write Exemption (Path Unless) |

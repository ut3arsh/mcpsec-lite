# Development Set Red-Team Evaluation Results (2026-11-10)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **C0** | **33/33** (100.0%) | **0/50** (0.0%) | Baseline without proxy (pass-through) |
| **C1** | **30/33** (90.9%) | **0/50** (0.0%) | Static policy allowlists only (Week 2) |
| **C2** | **12/33** (36.4%) | **23/50** (46.0%) | Full Firewall (Policy + Flow Rules + Taint Tracking) |
| **C5** | **12/33** (36.4%) | **24/50** (48.0%) | Freeze Candidate (E3 adopted: policy allowlists + session taint + approval egress + curated unless) |
| **C6** | **11/33** (33.3%) | **18/50** (36.0%) | Frozen Default Profile (E5 + Strict Tool-Description Pinning) |

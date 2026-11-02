# Development Set Red-Team Evaluation Results (2026-11-02)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **C0** | **27/27** (100.0%) | **0/44** (0.0%) | Baseline without proxy (pass-through) |
| **C1** | **24/27** (88.9%) | **0/44** (0.0%) | Static policy allowlists only (Week 2) |
| **C2** | **11/27** (40.7%) | **20/44** (45.5%) | Full Firewall (Policy + Flow Rules + Taint Tracking) |
| **C2s** | **9/27** (33.3%) | **21/44** (47.7%) | Full Firewall without 'unless' exemptions (Stress Variant) |
| **C3** | **11/27** (40.7%) | **20/44** (45.5%) | Full Firewall + Detectors (Advisory, ADR-003) |
| **C4** | **10/27** (37.0%) | **20/44** (45.5%) | Full Firewall + Strict Tool-Description Pinning |

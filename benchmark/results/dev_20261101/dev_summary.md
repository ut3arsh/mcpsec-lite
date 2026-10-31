# Development Set Red-Team Evaluation Results (2026-10-31)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **C0** | **24/24** (100.0%) | **0/32** (0.0%) | Baseline without proxy (pass-through) |
| **C1** | **21/24** (87.5%) | **0/32** (0.0%) | Static policy allowlists only (Week 2) |
| **C2** | **11/24** (45.8%) | **9/32** (28.1%) | Full Firewall (Policy + Flow Rules + Taint Tracking) |
| **C2s** | **9/24** (37.5%) | **10/32** (31.2%) | Full Firewall without 'unless' exemptions (Stress Variant) |
| **C3** | **11/24** (45.8%) | **9/32** (28.1%) | Full Firewall + Detectors (Advisory, ADR-003) |
| **C4** | **10/24** (41.7%) | **9/32** (28.1%) | Full Firewall + Strict Tool-Description Pinning |

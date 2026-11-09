# Development Set Red-Team Evaluation Results (2026-11-09)

> **Note:** Labeled Development Set. Defenses were tuned during initial development; results reflect scripted tests and explicit red-team stress chains.

## Summary Matrix Across Configurations

| Configuration | Attacks Succeeded (ASR) | Benign Blocked (FPR) | Description |
|---|---|---|---|
| **C5** | **12/33** (36.4%) | **24/50** (48.0%) | Freeze Candidate (E3 adopted: policy allowlists + session taint + approval egress + curated unless) |
| **E4b** | **14/33** (42.4%) | **17/50** (34.0%) | Full Firewall with Restored C5 and Scratch Notes Write Exemption (Path Unless) |
| **E5** | **12/33** (36.4%) | **18/50** (36.0%) | Full Firewall with Restored C5, Scratch Notes Write Exemption, and File-Origin Taint |

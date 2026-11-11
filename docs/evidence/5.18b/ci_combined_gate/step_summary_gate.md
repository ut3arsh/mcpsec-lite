## 🛡️ Combined Cross-Platform Coverage Gate (`mcpsec_core`)

- **Combined Statement Coverage:** **`97.01%`** (1816/1872) — Target: $\ge 90.00\%$
- **Combined Branch Coverage:** **`94.83%`** (715/754) — Target: $\ge 90.00\%$
- **Combined Total Coverage:** **`96.38%`** (2531/2626)
- **Per-Module Floor (>= 85.00% stmts & branches):** ✅ **PASSED** (all 8 core modules: audit, pinning, flow, matching, policy, taint, approvals, detectors)

| Module | Statements | Statement (%) | Branches | Branch (%) |
|---|---|---|---|---|
| `mcpsec_core/__init__.py` | 1/1 | 100.00% | 0/0 | 100.00% |
| `mcpsec_core/adapters.py` | 87/92 | 94.57% | 47/52 | 90.38% |
| `mcpsec_core/approvals.py` | 235/241 | 97.51% | 59/64 | 92.19% |
| `mcpsec_core/audit.py` | 222/223 | 99.55% | 77/80 | 96.25% |
| `mcpsec_core/detectors.py` | 108/110 | 98.18% | 59/64 | 92.19% |
| `mcpsec_core/flow.py` | 100/102 | 98.04% | 62/68 | 91.18% |
| `mcpsec_core/matching.py` | 151/158 | 95.57% | 85/86 | 98.84% |
| `mcpsec_core/models.py` | 157/159 | 98.74% | 14/14 | 100.00% |
| `mcpsec_core/pinning.py` | 317/331 | 95.77% | 97/102 | 95.10% |
| `mcpsec_core/policy.py` | 380/397 | 95.72% | 177/186 | 95.16% |
| `mcpsec_core/taint.py` | 58/58 | 100.00% | 38/38 | 100.00% |

✅ **GATE STATUS: PASSED** — Both statement and branch coverage meet or exceed 90.00%, and all 8 core modules meet or exceed the 85.00% floor.

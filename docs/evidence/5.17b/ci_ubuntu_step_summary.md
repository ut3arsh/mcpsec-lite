### 📊 Core Test Suite Coverage (`mcpsec_core`)
- **Total Branch-Aware Coverage:** **`93.30%`** (Gate: $\ge 90.00\%$)
- **Branch Coverage:** **`92.57%`**
- **Statement Coverage:** **`93.59%`**

| Module | Stmts | Cover (%) | Branches | Branch Cover (%) |
|---|---|---|---|---|
| `mcpsec_core/__init__.py` | 1/1 | 100.00% | 0/0 | 100.00% |
| `mcpsec_core/adapters.py` | 87/92 | 93.06% | 47/52 | 90.38% |
| `mcpsec_core/approvals.py` | 206/241 | 84.92% | 53/64 | 82.81% |
| `mcpsec_core/audit.py` | 222/223 | 98.68% | 77/80 | 96.25% |
| `mcpsec_core/detectors.py` | 108/110 | 95.98% | 59/64 | 92.19% |
| `mcpsec_core/flow.py` | 100/102 | 95.29% | 62/68 | 91.18% |
| `mcpsec_core/matching.py` | 145/158 | 92.21% | 80/86 | 93.02% |
| `mcpsec_core/models.py` | 157/159 | 98.84% | 14/14 | 100.00% |
| `mcpsec_core/pinning.py` | 288/331 | 87.53% | 91/102 | 89.22% |
| `mcpsec_core/policy.py` | 380/397 | 95.54% | 177/186 | 95.16% |
| `mcpsec_core/taint.py` | 58/58 | 100.00% | 38/38 | 100.00% |

### ⏭️ Skipped Tests (`pytest -rs`)
**Total Skipped:** 7

| Test Case | Class / File | Skip Reason |
|---|---|---|
| `test_github_adapter_conformance_with_snapshot` | `tests.test_contract` | UNVERIFIED-handwritten fixture: handwritten schema fixture based on official GitHub MCP specification (Docker / remote runtime unavailable locally on Windows host) |
| `test_live_filesystem_contract_vs_snapshot` | `tests.test_contract` | Opt-in live contract test (set RUN_LIVE_CONTRACT_TESTS=1) |
| `test_live_fetch_contract_vs_snapshot` | `tests.test_contract` | Opt-in live contract test (set RUN_LIVE_CONTRACT_TESTS=1) |
| `test_flow_path_unless_windows_case_insensitive` | `tests.test_flow_path_unless` | Windows case-insensitivity test applies to Windows only |
| `test_known_gap_http_redirect_ssrf_bypass` | `tests.test_known_gaps` | Known Gap: HTTP redirect bypass. Policy evaluates initial URL domain; upstream HTTP client follows redirects to non-allowlisted internal IPs (addressed in egress filtering / Week 6). |
| `test_known_gap_filesystem_symlink_toctou` | `tests.test_known_gaps` | Known Gap: Path TOCTOU. Symlink or directory swap between policy validation and upstream server filesystem read (addressed via file descriptor pinning / kernel namespace isolation). |
| `test_path_junction_escape_resolution_windows` | `tests.test_matching` | Windows directory junctions are Windows-specific |

### 🛡️ Proxy Session Coverage (`proxy/session.py`)
- **Total Coverage:** **`97.76%`**
- **Branch Coverage:** **`93.22%`** (110/118)
- **Statement Coverage:** **`99.65%`** (282/283)


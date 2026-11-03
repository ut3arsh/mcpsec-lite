# Diff Table: Chunk 5.16 (2026-11-03) vs Chunk 5.17a Rerun (2026-11-04)

Generated pursuant to Chunk 5.17a Task 4.
Comparison between `benchmark/results/dev_analysis_20261103.md` and `benchmark/results/dev_analysis_20261104_rerun.md`.

| Section / Metric | Old Value (5.16) | New Value (5.17a Rerun) | Mathematical & Policy Cause |
|---|---|---|---|
| **Bar (d) Approvals / Task (E1)** | 0.46 | 0.59 (27/46) | In 5.16, approvals/task was evaluated on `deny_all`, which halted tasks at the 1st denied approval. In 5.17a, it is evaluated on `approve_all` (approvals actually requested before completion). 6 tasks (BENIGN-33, 34, 36, 39, 40, 46) require 2 approvals each under E1. (+6 approvals across 46 tasks = +0.1304) |
| **Bar (d) Approvals / Task (E3)** | 0.48 | 0.54 (25/46) | Evaluated on `approve_all`. In E3, 3 tasks (BENIGN-36, 40, 46) require 2 approvals each. Under `deny_all`, they halted at 1 approval. (+3 approvals across 46 tasks = +0.0652) |
| **Combined Benign Approvals / Task (E1)** | 0.46 | 0.59 | Metric recomputed on `approve_all` trials (27 total approvals requested across 46 tasks). |
| **Combined Benign Approvals / Task (E3)** | 0.48 | 0.54 | Metric recomputed on `approve_all` trials (25 total approvals requested across 46 tasks). |
| **v2 Manifest Approvals / Task (E1)** | 0.83 | 1.25 (15/12) | Evaluated on `approve_all`. In v2, 5 tasks (BENIGN-33, 34, 36, 39, 40) require 2 approvals each under E1 (15 total approvals / 12 tasks). |
| **v2 Manifest Approvals / Task (E3)** | 0.92 | 1.08 (13/12) | Evaluated on `approve_all`. In v2, 2 tasks (BENIGN-36, 40) require 2 approvals each under E3 (13 total approvals / 12 tasks). |
| **v3 Manifest Approvals / Task (E1)** | 1.00 | 1.50 (3/2) | Evaluated on `approve_all`. BENIGN-46 requires 2 approvals (1 untrusted fetch + 1 untrusted write). Total 3 approvals / 2 tasks. |
| **v3 Manifest Approvals / Task (E3)** | 1.00 | 1.50 (3/2) | Evaluated on `approve_all`. BENIGN-46 requires 2 approvals (1 untrusted fetch + 1 untrusted write). Total 3 approvals / 2 tasks. |
| **Section 3: C1 Tainted Subset (n)** | n = 31 | n = 0 | In 5.16, partition was by static `taint_expected`. In 5.17a, partition is strictly by taint ACQUIRED in trials. C1 has no taint tracking engine, so zero tasks acquire taint (n = 0). |
| **Section 3: C1 Clean Subset (n)** | n = 15 | n = 46 | Since C1 does not track taint, all 46 tasks remain in the clean partition (46/46 clean, 0 approvals needed, 100.0% completion). |
| **Section 3: C1 Tainted Approval-Needed** | 0/31 (0.00%) | 0/0 (0.00%) | n changed from 31 to 0 due to acquired taint partitioning. |
| **Section 3: C1 Tainted Completion (deny)** | 31/31 (100.0%) | 0/0 (0.00%) | n changed from 31 to 0 due to acquired taint partitioning. |
| **Section 3: C1 Tainted Completion (appr)** | 31/31 (100.0%) | 0/0 (0.00%) | n changed from 31 to 0 due to acquired taint partitioning. |
| **Section 3: C1 Clean Approval-Needed** | 0/15 (0.00%) | 0/46 (0.00%) | n changed from 15 to 46 due to acquired taint partitioning. |
| **Section 3: C1 Clean Completion (deny)** | 15/15 (100.0%) | 46/46 (100.0%) | n changed from 15 to 46 due to acquired taint partitioning. |
| **Section 3: C1 Clean Completion (appr)** | 15/15 (100.0%) | 46/46 (100.0%) | n changed from 15 to 46 due to acquired taint partitioning. |

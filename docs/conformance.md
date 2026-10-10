# Specification Conformance Matrix

This document maps normative requirements (`MUST`, `MUST NOT`, `SHOULD`, `REQUIRED`) from [`docs/policy_schema.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/policy_schema.md) and [`docs/audit_log_schema.md`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/docs/audit_log_schema.md) to concrete automated test cases in the test suite.

---

## 1. Policy Schema (`docs/policy_schema.md`)

| Spec Section | Normative Requirement | Implementation / Validator | Automated Test Case |
|---|---|---|---|
| **§1.1 Overview** | Policy must be valid YAML mapping with deterministic SHA-256 hash | `compute_policy_hash`, `load_policy` in `mcpsec_core/policy.py` | [`tests/test_policy.py::test_valid_minimal_policy_loads_cleanly`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py), [`tests/test_policy.py::test_policy_load_idempotent`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 1: Version** | `version: 1` required; unknown versions rejected with `ERR_VERSION` | `validate_and_compile_policy` | [`tests/test_policy.py::test_rule1_invalid_or_missing_version`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 2: Closed Schema** | Unknown root and nested keys rejected with `ERR_UNKNOWN_KEY` | Pydantic model validation (`extra="forbid"`) | [`tests/test_policy.py::test_rule2_unknown_key_rejected`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 3: Capability Tags** | Capability tags must belong to closed set `{read, write, network_read, egress, exec}` | `ALLOWED_CAPABILITY_TAGS` validation | [`tests/test_policy.py::test_rule3_capabilities_tag_outside_closed_set`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 4: Taint Labels** | Taint source labels and flow rules must reference recognized labels | `ALLOWED_TAINT_LABELS` validation | [`tests/test_policy.py::test_rule4_unknown_taint_label_or_tag`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 5: Unique Flow IDs** | Flow rule IDs must be unique across the policy document | `seen_flow_ids` uniqueness check | [`tests/test_policy.py::test_rule5_duplicate_flow_rule_id`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 6: Flow Actions** | Flow rules must define exactly one of `deny_capabilities` or `require_approval_capabilities` | Flow rule validation | [`tests/test_policy.py::test_rule6_flow_rule_invalid_capabilities`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 6b: Flow 'unless'** | Flow rule `unless` must carry `domain_allowlist` and require `egress` capability on rule | `validate_and_compile_policy` in `mcpsec_core/policy.py` | [`tests/test_policy.py::test_unless_exemption_validation_rules`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 7: Tool Capabilities** | Tools in `policies` must have corresponding entry in `capabilities` | Capabilities presence check | [`tests/test_policy.py::test_rule7_tool_in_policies_has_no_capabilities`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.1 Rule 8: Argument Adapters** | Tool constraints (`path_allowlist`, `domain_allowlist`) require recognized argument adapters | `validate_tool_adapter_for_constraints` in `mcpsec_core/adapters.py` | [`tests/test_policy.py::test_rule8_constraint_on_tool_with_no_adapter`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py), [`tests/test_adapters.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_adapters.py) |
| **§3.1 Rule 9: Glob Compilation** | Path and domain patterns must be pre-compiled at load time | `compile_path_glob`, `compile_domain_pattern` | [`tests/test_policy.py::test_rule9_invalid_glob_syntax`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_policy.py) |
| **§3.2 Unicode Normalization** | Arguments and paths normalized to Unicode NFC before validation | `unicodedata.normalize("NFC", ...)` | [`tests/test_matching.py::test_unicode_nfc_normalization`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_matching.py) |
| **§3.3 Path Resolution & Traversal** | Canonical path resolution resolving symlinks, junctions, `..`, relative paths | `resolve_and_match_path` | [`tests/test_matching.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_matching.py) |
| **§3.4 Strict Unexpected Arguments** | Unrecognized tool arguments rejected with `ERR_UNEXPECTED_ARGUMENT` | `validate_unexpected_arguments` in `mcpsec_core/adapters.py` | [`tests/test_adapters.py::test_unexpected_argument_rejection`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_adapters.py) |
| **§3.5 Tool Name Mapping** | Bidirectional translation `<server>__<tool>` <-> `<server>.<tool>` | `encode_tool_name`, `decode_tool_name` | [`tests/test_adapters.py::test_tool_name_roundtrip_property`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_adapters.py) |
| **§4 Taint Tracking** | Labels applied post-success; pure immutable update; fail-closed missing private args | `update_taint` in `mcpsec_core/taint.py` | [`tests/test_flow_truth_table.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_flow_truth_table.py), [`tests/test_flow_properties.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_flow_properties.py) |
| **§5 Flow Engine** | Flow rules evaluate `deny > require_approval > allow` with `unless` domain exemption | `check_flow` in `mcpsec_core/flow.py` | [`tests/test_flow_truth_table.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_flow_truth_table.py), [`tests/test_flow_proxy_e2e.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_flow_proxy_e2e.py) |
| **§5.1 Network Egress Semantics** | Any tool transmitting caller data outside trust boundary carries `egress` (fetch carries `[network_read, egress]`) | `mcpsec_core/adapters.py` & Policy capabilities | [`tests/test_flow_proxy_e2e.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_flow_proxy_e2e.py) |
| **§6 Generic Error Responses** | Enforce denials return generic `"Denied by mcpsec policy"` to agent | `ProxySession.call_tool` | [`tests/test_proxy_policy.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_proxy_policy.py), [`tests/test_flow_proxy_e2e.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_flow_proxy_e2e.py) |
| **§7 Tool-Description Pinning** | Pin store hashing with strict mode masking from `tools/list` and call rejection | `PinStore`, `ProxySession` | [`tests/test_pinning.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_pinning.py) |

---

## 2. Audit Log Schema (`docs/audit_log_schema.md`)

| Spec Section | Normative Requirement | Implementation | Automated Test Case |
|---|---|---|---|
| **§2 Event Types** | Valid JSONL events: `policy_loaded`, `session_start`, `tool_call`, `session_end` | `AuditLogger` in `mcpsec_core/audit.py` | [`tests/test_audit.py::test_all_audit_event_types_schema_conformance`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_audit.py) |
| **§3.1 Pin Status Enum** | `pin_status` enum must be one of `pinned \| unpinned \| changed \| unchecked` | `ToolCallEvent.pin_status` in `mcpsec_core/models.py` | [`tests/test_audit.py::test_pin_status_enum_matches_schema_doc`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_audit.py), [`tests/test_pinning.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_pinning.py) |
| **§3.2 Redaction Modes** | Arguments redacted per policy (`redacted`, `full`, `hash_only`) | `redact_args` in `mcpsec_core/redaction.py` | [`tests/test_redaction.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_redaction.py) |
| **§3.3 Latency Breakdown** | Tool calls record `latency_ms.proxy` and `latency_ms.upstream` | `ProxySession.call_tool` | [`tests/test_proxy.py::test_proxy_filesystem_end_to_end`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_proxy.py) |
| **§4 Session Lifecycle** | Monotonic sequence IDs and session state tracking | `SessionState`, `AuditLogger` | [`tests/test_audit.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_audit.py) |
| **§8 Log Rotation & Hash Chain** | Max-bytes rotation, sequence restart per file, cross-file tamper-evident continuity | `AuditLogger._maybe_rotate_unlocked` in `mcpsec_core/audit.py` | [`tests/test_audit.py::test_audit_log_rotation_and_tamper_evident_hash_chain_continuity`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_audit.py) |
| **§8 Backpressure & fsync** | Bounded writer queue with backpressure, fsync in strict mode | `AuditLogger.log_event` in `mcpsec_core/audit.py` | [`tests/test_audit.py::test_audit_logger_bounded_queue_backpressure`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_audit.py), [`tests/test_audit.py::test_audit_logger_fsync_mode`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_audit.py) |

---

## 3. Multi-Upstream & Process Management (`DESIGN.md`)

| Architectural Requirement | Implementation | Automated Test Case |
|---|---|---|
| **Multi-Upstream Routing** | Single proxy fronting 3 upstreams with `<server>__<tool>` namespacing | `UpstreamManager`, `ProxySession` | [`tests/test_multi_upstream.py::test_multi_upstream_aggregation_and_routing`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_multi_upstream.py) |
| **Protocol Surface Guard** | Advertise only tools; reject non-tool and server-initiated surfaces with `ERR_UNSUPPORTED_SURFACE` | `Server` & `ProxySession` | [`tests/test_unsupported_surfaces.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_unsupported_surfaces.py) |
| **Subprocess Tree Hygiene** | `kill_process_tree` terminates entire process hierarchy (Windows `/T /F`, POSIX process groups) | `kill_process_tree` in `proxy/supervisor.py` | [`tests/test_subprocess_hygiene.py::test_kill_process_tree_terminates_all_descendants`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_subprocess_hygiene.py) |
| **Environment Isolation** | Upstream environment sanitized, stripping parent process secrets | `sanitize_upstream_env` in `proxy/supervisor.py` | [`tests/test_supervisor_unit.py::test_sanitize_upstream_env_strips_sensitive_variables`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_supervisor_unit.py) |
| **Non-Required Degradation** | Non-required upstream failure logs warning without crashing healthy upstreams | `UpstreamManager.start_all` | [`tests/test_multi_upstream.py::test_non_required_upstream_degradation`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_multi_upstream.py) |
| **Advisory Detectors (ADR-003)** | Zero-decision-mutation secret and prompt injection scanner with 256 KiB cap and ReDoS guard | `DetectorEngine` in `mcpsec_core/detectors.py` | [`tests/test_detectors.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_detectors.py) |
| **TOCTOU Defense-in-Depth** | Upstream native directory confinement prevents escape if proxy bypassed | Upstream server directory roots | [`tests/test_toctou_defense.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_toctou_defense.py) |
| **Statistical Benchmark Runner** | Evaluation harness with Wilson score intervals and trial recording | `BenchmarkRunner`, `wilson_interval` | [`tests/test_benchmark_runner.py`](file:///c:/Users/BIT%20PATNA/ai-agent-firewall/tests/test_benchmark_runner.py) |

---

## 4. Documented v1 Limitations

1. **HTTP Redirects:** Policy evaluates the initial URL host; if an upstream tool follows HTTP 30x redirects to unlisted IPs, domain allowlists do not intercept subsequent hops (addressed via network-level egress proxy in Week 6; see `docs/egress_guard_design.md`).
2. **GitHub Parameter Encoding:** While `fetch` carries `egress`, GitHub read tools (e.g. `github.get_issue`) can theoretically encode data in `owner` or `repo` arguments (accepted v1 limitation).
3. **Coarse Session Taint:** Taint is tracked per session rather than per-argument provenance.



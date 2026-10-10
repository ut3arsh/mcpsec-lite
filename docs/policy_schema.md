# policy_schema.md — Policy File Specification (v1)

**Status:** v0 draft · Contract for `mcpsec_core.policy`. Anything not specified here is invalid.

Format: YAML, UTF-8. One file per proxy instance. Loaded at startup; reload requires restart in v1.

**Fail-closed rule:** if the policy fails validation, the proxy refuses to start. It never falls back to allow-all.

---

## 1. Top-level structure

```yaml
version: 1
mode: enforce                # audit | enforce
serialize_calls: true        # serialize calls per session (see DESIGN §4.4)

capabilities: { ... }        # §2
policies: [ ... ]            # §3
taint_sources: { ... }       # §4
flow_rules: [ ... ]          # §5
approval: { ... }            # §6
pinning: { ... }             # §7
detectors: { ... }           # §8
redaction: { ... }           # §9
```

| Key | Type | Required | Default | Notes |
|-----|------|----------|---------|-------|
| `version` | int | yes | — | Must be `1`. |
| `mode` | enum | no | `enforce` | `audit` logs would-be decisions but forwards everything. |
| `serialize_calls` | bool | no | `true` | If `false`, taint races are possible (documented limitation). |
| `capabilities` | map | yes | — | Tool → capability tags. |
| `policies` | list | yes | — | Per-agent allowlists. |
| `taint_sources` | map | no | `{}` | Without it, flow rules never fire. |
| `flow_rules` | list | no | `[]` | |
| `approval` | map | no | see §6 | |
| `pinning` | map | no | `{mode: audit}` | |
| `detectors` | map | no | all off | |
| `redaction` | map | no | see §9 | |

Unknown keys at any level are a validation error.

## 2. `capabilities`

Maps a tool identifier to capability tags. **Tool identifier = `<server>.<tool>`**, where `<server>` is the server name in the proxy config.

```yaml
capabilities:
  github.get_issue:   [network_read]
  http.fetch:         [network_read]
  http.post:          [egress]
  email.send:         [egress]
  shell.exec:         [exec]
  fs.read_file:       [read]
  fs.write_file:      [write]
```

Allowed tags (closed set in v1): `read`, `write`, `network_read`, `egress`, `exec`.

- A tool may have multiple tags.
- A tool with no entry has **no capabilities and is denied by default** (§3).
- Tag semantics: `egress` = can send data outside the local trust boundary; `exec` = runs code/commands; `write` = mutates local or remote state; `read`/`network_read` = reads local/remote data.

## 3. `policies` (per-agent allowlists)

```yaml
policies:
  - agent: dev-agent           # agent_id, or "*" for any
    tools:
      fs.read_file:
        path_allowlist: ["/home/user/project/**"]
      http.fetch:
        domain_allowlist: ["api.github.com", "raw.githubusercontent.com", "*.githubusercontent.com"]
      github.get_issue: {}     # allowed, no argument constraints
```

- **Default deny:** a tool not listed under the matching agent is denied.
- Matching: exact `agent` match first; then `"*"`. Entries are **not merged**; the first matching policy applies.
- Per-tool constraint keys (v1): `path_allowlist`, `domain_allowlist`. A tool may set both; **all** present constraints must pass.
- `{}` means allowed with no argument constraints.

### 3.1 Argument matching rules
- **Paths:** the argument is normalized (expand `~`, resolve `..`, resolve symlinks, junctions, and parent directories for non-existent write targets) **before** matching against globs. Match failure ⇒ deny. Globs: `*` (no `/`), `**` (any depth).
- **Unicode & URL encoding:** Path arguments MUST undergo Unicode NFC normalization before canonicalization. Implementations MUST NOT URL-decode file path arguments before evaluating allowlists.
- **Windows boundaries:** On Windows, implementations MUST reject UNC paths (`\\\\server\\share`), Win32 device namespace paths (`\\\\?\\`, `\\\\.\\`), Alternate Data Streams (`:`), and legacy DOS reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
- **Domains:** parsed from the URL host, lowercased. `example.com` matches exactly; `*.example.com` matches subdomains only (not the apex or look-alike domains). Non-HTTP(S) schemes and URLs with userinfo (`@`) are denied. Redirects are not followed by the proxy; servers that follow redirects are a documented gap.
- **Strict schema mapping:** Constraints apply to a fixed, per-tool set of argument names declared in the tool adapter (e.g., `fs.read_file` → `path`; `http.fetch` → `url`). A tool with a constraint but no known argument mapping is a **validation error**. When evaluating tool calls for constrained tools, any argument not declared in the tool adapter schema is denied with `ERR_UNEXPECTED_ARGUMENT`.

### 3.2 Agent responses & information leak prevention
- In `mode: enforce`, agent-facing denial error responses MUST return a generic message (`"Denied by mcpsec policy"`) and MUST NOT leak allowlists, filesystem paths, or internal policy details to potentially untrusted models.
- Full forensic context (e.g. `path not in allowlist: ...`) is preserved and recorded exclusively in the audit log.

## 4. `taint_sources`

Declares which calls apply which labels to the session **after the call returns**.

```yaml
taint_sources:
  untrusted_content:
    - tool: github.get_issue
    - tool: github.get_pull_request
    - tool: http.fetch
  private_data:
    - tool: fs.read_file
      args:
        path: ["~/.ssh/**", "**/.env", "**/*secret*"]
```

- Labels (closed set in v1): `untrusted_content`, `private_data`.
- Each entry: `tool` (required); optional `args` map of argument name → list of globs. If `args` is present, the label is applied only when **every** listed argument matches at least one glob. No `args` ⇒ every successful call of that tool applies the label.
- Labels are applied only on **successful** calls (errors do not taint).
- Labels are monotonic within a session; only an approval (§6) can clear them.
- Labels come from declared sources only. They are never inferred from content.

## 5. `flow_rules`

```yaml
flow_rules:
  - id: no-egress-after-untrusted
    if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
    unless:
      domain_allowlist: ["docs.internal", "*.safe.org"]

  - id: no-egress-after-private
    if_session_has: [private_data]
    deny_capabilities: [egress]

  - id: gate-write-when-both
    if_session_has: [untrusted_content, private_data]
    require_approval_capabilities: [write]
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Unique. Appears in the audit log as `rule_id`. |
| `if_session_has` | list of labels | yes | **All** listed labels must be present (AND). |
| `deny_capabilities` | list of tags | one of the two | Matching call is denied. |
| `require_approval_capabilities` | list of tags | one of the two | Matching call is held for approval. |
| `unless` | object | no | Optional exemption: `unless: { domain_allowlist: [...] }`. Valid only on rules denying/requiring approval for `egress`. |

### 5.1 Flow rule exemption semantics (`unless`)
- A flow rule may carry `unless: { domain_allowlist: [...] }`.
- The rule is skipped for a call **only if every domain-constrained argument parses and matches** the list.
- **Fail closed:** Any parse failure, unparsable URL, missing argument, or non-matching domain causes the rule to apply.
- `unless` is valid **only** on rules whose `deny_capabilities` or `require_approval_capabilities` include `egress`, and only for tools with a domain adapter (e.g. `domain_args`).
- Matching reuses standard domain matching (Unicode normalization, userinfo/IP/scheme rejection).

Evaluation:
1. Compute the set of rules whose `if_session_has` ⊆ current session labels.
2. For each rule, evaluate capabilities and apply `unless` exemption if present.
3. If any matching non-exempt rule denies a capability the call has ⇒ **deny**.
4. Else if any matching non-exempt rule requires approval for a capability the call has ⇒ **require_approval**.
5. Else flow check passes.

Decision precedence across all layers: `deny` > `require_approval` > `allow`. A tool whose capabilities are empty is never matched by flow rules (it is already default-denied by §3).

## 6. `approval`

```yaml
approval:
  channel: cli                       # v1: cli only
  pending_file: ./pending_approvals.jsonl
  timeout_seconds: 300               # unanswered ⇒ deny
  allow_clear: [untrusted_content]   # labels a human may clear in-session
```

- `require_approval` calls are written to `pending_file` and block until approved, denied, or timed out (timeout ⇒ deny).
- `mcpsec-approve` may approve a single call and/or clear labels listed in `allow_clear`.
- `private_data` is **not** clearable in-session by default (omit from `allow_clear`).
- Every approval, denial, timeout, and clear is logged (see `audit_log_schema.md`).

## 7. `pinning`

```yaml
pinning:
  mode: audit            # audit | strict
  store: ./pins.json
```

- Pin unit: per tool `{name, description, inputSchema}` → SHA-256 of canonical JSON (sorted keys, normalized whitespace), plus a per-server hash.
- `audit`: mismatch is logged (`pin_status: changed`), call proceeds.
- `strict`: calls to a changed or unpinned tool are denied until re-pinned via `mcpsec-pin approve`.
- First sight of a server in `strict` mode requires an explicit initial `mcpsec-pin approve` (trust-on-first-use is only allowed in `audit` mode).
- `tools/list_changed` triggers re-fetch + diff; the result is a `pin_event` (not a silent accept).

## 8. `detectors` (secondary, non-authoritative)

```yaml
detectors:
  secrets: true                  # secret patterns in call args
  injection_heuristics: true     # coarse markers in responses (weak; bypassable)
```

- Detectors only add `flags` and `risk_score` to the audit log. **They never change a decision in v1.**
- Detector logic is frozen before the held-out benchmark set is authored (see `benchmark_spec.md`).

## 9. `redaction`

```yaml
redaction:
  log_args: redacted             # full | redacted | hash_only
  patterns: ["AKIA[0-9A-Z]{16}", "ghp_[A-Za-z0-9]{36}"]
  never_log_fields: ["password", "token", "authorization"]
```

- `redacted` replaces matches and named fields with `"[REDACTED]"`.
- `hash_only` stores SHA-256 of canonical args only.
- Redaction applies to the audit log only; forwarded calls are never modified.

## 10. Validation rules (summary)

The loader rejects the policy (and the proxy exits non-zero) when:
1. Schema `version` is missing or unsupported.
2. Any unknown key appears.
3. A `capabilities` tag is outside the closed set.
4. A `flow_rules` or `taint_sources` entry references an unknown label or tag.
5. Two `flow_rules` share an `id`.
6. A rule has neither or both of `deny_capabilities` / `require_approval_capabilities`.
7. A tool in `policies` has no `capabilities` entry.
8. A constraint is set on a tool with no argument mapping, or an unexpected argument is passed to a constrained tool (`ERR_UNEXPECTED_ARGUMENT`).
9. A glob or regex fails to compile.
10. In `mode: enforce`, unenforced policy features (`flow_rules`, `taint_sources`, or `pinning.mode: strict`) are configured (`ERR_NOT_YET_ENFORCED`).

Warnings (proxy starts, logs at startup): a `taint_source` label is never referenced by any flow rule; a capability tag is never referenced by any flow rule; `serialize_calls: false`; unenforced features configured in `mode: audit`.

## 11. Complete minimal example

```yaml
version: 1
mode: enforce
serialize_calls: true

capabilities:
  fs.read_file:        [read]
  fs.write_file:       [write]
  http.fetch:          [network_read]
  http.post:           [egress]
  github.get_issue:    [network_read]

policies:
  - agent: "*"
    tools:
      fs.read_file:     { path_allowlist: ["/home/user/project/**"] }
      http.fetch:       { domain_allowlist: ["api.github.com"] }
      github.get_issue: {}

taint_sources:
  untrusted_content:
    - { tool: github.get_issue }
    - { tool: http.fetch }
  private_data:
    - { tool: fs.read_file, args: { path: ["**/.env"] } }

flow_rules:
  - { id: no-egress-untrusted, if_session_has: [untrusted_content], deny_capabilities: [egress, exec] }
  - { id: no-egress-private,   if_session_has: [private_data],      deny_capabilities: [egress] }

approval: { channel: cli, allow_clear: [untrusted_content] }
pinning:  { mode: strict, store: ./pins.json }
detectors: { secrets: true, injection_heuristics: true }
redaction: { log_args: redacted }
```

## 12. Versioning
`version` is an integer. Breaking changes bump it; the loader supports only known versions. v1 stays frozen once the benchmark is run so results remain reproducible.
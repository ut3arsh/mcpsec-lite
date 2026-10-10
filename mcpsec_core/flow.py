"""Flow control checking based on session taint and tool capabilities.

Strictly adheres to docs/policy_schema.md §5 and ADR-012.
Pure functions over explicit, immutable SessionState.
"""

from __future__ import annotations

from typing import Any

from mcpsec_core.adapters import extract_domain_arguments
from mcpsec_core.matching import normalize_domain_or_url
from mcpsec_core.models import Decision, SessionState, ToolCall


def check_flow(session_state: SessionState, call: ToolCall, policy: Any) -> Decision:
    """Evaluate flow rules against current session taint and tool capabilities.

    Precedence: deny > require_approval > allow.
    Supports ADR-012 `unless: { domain_allowlist: [...] }` flow-rule exemption.
    """
    if (
        policy is None
        or not hasattr(policy, "compiled_flow_rules")
        or not policy.compiled_flow_rules
    ):
        return Decision(
            decision="allow",
            layer="flow",
            reason="flow check passed (no flow rules configured)",
        )

    tool_id = call.tool if "." in call.tool else f"{call.server}.{call.tool}"
    tool_caps = (
        frozenset(call.capabilities)
        if call.capabilities
        else frozenset(policy.capabilities.get(tool_id, ()))
    )
    if not tool_caps:
        return Decision(
            decision="allow",
            layer="flow",
            reason="tool has no capabilities; flow rules pass",
        )

    current_taint = session_state.taint
    if not current_taint:
        return Decision(
            decision="allow",
            layer="flow",
            reason="flow check passed (session has no taint)",
        )

    matched_deny_rule: Any = None
    matched_appr_rule: Any = None
    deny_caps_matched: set[str] = set()
    appr_caps_matched: set[str] = set()

    call_domains_extracted: bool = False
    call_domains_valid: bool = False
    call_normalized_domains: list[tuple[str, bool]] = []

    for rule in policy.compiled_flow_rules:
        # 1. Check if session has all required taint labels
        req_labels = rule.if_session_has_tuple
        if req_labels:
            if not all(lbl in current_taint for lbl in req_labels):
                continue
        elif not rule.if_session_has <= current_taint:
            continue

        # 2. Check if rule matches any tool capabilities
        deny_match = [c for c in rule.deny_caps_tuple if c in tool_caps]
        appr_match = [c for c in rule.appr_caps_tuple if c in tool_caps] if not deny_match else []
        if not deny_match and not appr_match:
            continue

        # 3. Check 'unless' exemption
        if rule.has_unless:
            if not call_domains_extracted:
                call_domains_extracted = True
                is_valid, domain_args, _ = extract_domain_arguments(tool_id, call.args)
                if is_valid and domain_args:
                    parsed_list: list[tuple[str, bool]] = []
                    parse_ok = True
                    for raw_url in domain_args:
                        try:
                            norm_dom, is_ip = normalize_domain_or_url(raw_url)
                            parsed_list.append((norm_dom, is_ip))
                        except Exception:
                            parse_ok = False
                            break
                    if parse_ok and parsed_list:
                        call_domains_valid = True
                        call_normalized_domains = parsed_list

            if not call_domains_valid:
                # No domain adapter, missing args, or invalid arg type -> rule applies (fail closed)
                pass
            else:
                all_domains_match = True
                for nd, is_ip in call_normalized_domains:
                    if nd in rule.unless_exact_hosts:
                        continue
                    if not is_ip and rule.unless_wildcard_regexes:
                        if any(rx.match(nd) for rx in rule.unless_wildcard_regexes):
                            continue
                    all_domains_match = False
                    break

                if all_domains_match:
                    # Exemption applies: skip this rule
                    continue

        # 4. Rule applies
        if deny_match:
            if matched_deny_rule is None:
                matched_deny_rule = rule
            deny_caps_matched.update(deny_match)
        elif appr_match:
            if matched_appr_rule is None:
                matched_appr_rule = rule
            appr_caps_matched.update(appr_match)

    # 5. Apply precedence: deny > require_approval > allow
    if matched_deny_rule is not None:
        return Decision(
            decision="deny",
            layer="flow",
            rule_id=matched_deny_rule.id,
            reason=(
                f"flow rule '{matched_deny_rule.id}' denied capabilities "
                f"{sorted(deny_caps_matched)} for session with taint {sorted(current_taint)}"
            ),
        )

    if matched_appr_rule is not None:
        return Decision(
            decision="require_approval",
            layer="flow",
            rule_id=matched_appr_rule.id,
            reason=(
                f"flow rule '{matched_appr_rule.id}' requires approval for capabilities "
                f"{sorted(appr_caps_matched)} for session with taint {sorted(current_taint)}"
            ),
        )

    return Decision(
        decision="allow",
        layer="flow",
        reason="flow check passed",
    )

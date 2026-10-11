"""Policy loading, validation, compilation, and evaluation engine for mcpsec-lite.

Strictly adheres to docs/policy_schema.md v1.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mcpsec_core.adapters import (
    extract_domain_arguments,
    extract_path_arguments,
    validate_tool_adapter_for_constraints,
    validate_unexpected_arguments,
)
from mcpsec_core.matching import (
    DomainSecurityError,
    PathSecurityError,
    compile_domain_pattern,
    compile_path_glob,
    match_domain,
    match_path,
    normalize_domain_or_url,
    normalize_path,
)
from mcpsec_core.models import Decision, ToolCall

# Closed sets (v1)
ALLOWED_CAPABILITY_TAGS = frozenset({"read", "write", "network_read", "egress", "exec"})
ALLOWED_TAINT_LABELS = frozenset({"untrusted_content", "private_data"})
ALLOWED_MODES = frozenset({"audit", "enforce"})
ALLOWED_REDACTION_MODES = frozenset({"full", "redacted", "hash_only"})
ALLOWED_PINNING_MODES = frozenset({"audit", "strict"})


class PolicyError(Exception):
    """Base exception for policy loading and validation failures."""

    def __init__(self, message: str, errors: list[dict[str, str]] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


# --- Pydantic Schema Models (Strict & Frozen) ---


class PolicyBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolConstraintsModel(PolicyBaseModel):
    path_allowlist: list[str] | None = None
    domain_allowlist: list[str] | None = None


class PolicyEntryModel(PolicyBaseModel):
    agent: str
    tools: dict[str, ToolConstraintsModel | dict[str, Any]]


class TaintSourceEntryModel(PolicyBaseModel):
    tool: str
    args: dict[str, list[str]] | None = None


class FlowRuleUnlessModel(PolicyBaseModel):
    domain_allowlist: list[str]


class FlowRuleModel(PolicyBaseModel):
    id: str
    if_session_has: list[str]
    deny_capabilities: list[str] | None = None
    require_approval_capabilities: list[str] | None = None
    unless: FlowRuleUnlessModel | None = None


class ApprovalConfigModel(PolicyBaseModel):
    channel: str = "cli"
    pending_file: str = "./pending_approvals.jsonl"
    timeout_seconds: int = 300
    allow_clear: list[str] = Field(default_factory=list)


class PinningConfigModel(PolicyBaseModel):
    mode: Literal["audit", "strict"] = "audit"
    store: str = "./pins.json"


class DetectorsConfigModel(PolicyBaseModel):
    secrets: bool = False
    injection_heuristics: bool = False


class RedactionConfigModel(PolicyBaseModel):
    log_args: Literal["full", "redacted", "hash_only"] = "redacted"
    patterns: list[str] = Field(default_factory=list)
    never_log_fields: list[str] = Field(default_factory=list)


class RawPolicySchema(PolicyBaseModel):
    version: int
    mode: Literal["audit", "enforce"] = "enforce"
    serialize_calls: bool = True
    capabilities: dict[str, list[str]]
    policies: list[PolicyEntryModel]
    taint_sources: dict[str, list[TaintSourceEntryModel]] = Field(default_factory=dict)
    flow_rules: list[FlowRuleModel] = Field(default_factory=list)
    approval: ApprovalConfigModel = Field(default_factory=ApprovalConfigModel)
    pinning: PinningConfigModel = Field(default_factory=PinningConfigModel)
    detectors: DetectorsConfigModel = Field(default_factory=DetectorsConfigModel)
    redaction: RedactionConfigModel = Field(default_factory=RedactionConfigModel)


# --- Compiled In-Memory Policy Representation ---


@dataclass(frozen=True)
class CompiledToolRule:
    tool_id: str
    has_constraints: bool
    has_path_constraint: bool
    has_domain_constraint: bool
    path_patterns: tuple[re.Pattern[str], ...] = ()
    domain_rules: tuple[tuple[str, bool, re.Pattern[str] | None], ...] = ()


@dataclass(frozen=True)
class CompiledFlowRule:
    id: str
    if_session_has: frozenset[str]
    deny_capabilities: frozenset[str]
    require_approval_capabilities: frozenset[str]
    has_unless: bool = False
    unless_domain_rules: tuple[tuple[str, bool, re.Pattern[str] | None], ...] = ()
    unless_exact_hosts: frozenset[str] = frozenset()
    unless_wildcard_regexes: tuple[re.Pattern[str], ...] = ()
    if_session_has_tuple: tuple[str, ...] = ()
    deny_caps_tuple: tuple[str, ...] = ()
    appr_caps_tuple: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompiledTaintSource:
    label: str
    tool_id: str
    args_patterns: dict[str, tuple[re.Pattern[str], ...]]


@dataclass(frozen=True)
class Policy:
    """Immutable compiled policy object used for O(1) runtime checks."""

    version: int
    mode: Literal["audit", "enforce"]
    serialize_calls: bool
    policy_hash: str
    capabilities: dict[str, tuple[str, ...]]
    # agent_id -> tool_id -> CompiledToolRule
    agent_rules: dict[str, dict[str, CompiledToolRule]]
    warnings: tuple[str, ...]
    flow_rules: tuple[FlowRuleModel, ...]
    taint_sources: dict[str, tuple[TaintSourceEntryModel, ...]]
    approval: ApprovalConfigModel
    pinning: PinningConfigModel
    detectors: DetectorsConfigModel
    redaction: RedactionConfigModel
    compiled_flow_rules: tuple[CompiledFlowRule, ...] = ()
    taint_sources_by_tool: dict[str, tuple[CompiledTaintSource, ...]] = field(default_factory=dict)


def validate_and_compile_policy(
    raw_data: Any,
    policy_hash: str,
    check_unenforced_guards: bool = False,
) -> tuple[Policy, list[str]]:
    """Validate all 9 rules and warnings from policy_schema.md §10 and compile indexes."""
    errors: list[dict[str, str]] = []
    warnings: list[str] = []

    if not isinstance(raw_data, dict):
        raise PolicyError(
            "Policy document must be a YAML mapping/dictionary",
            errors=[{"code": "ERR_INVALID_YAML", "path": "", "message": "Root must be a mapping"}],
        )

    # 1. Version check (Rule 1)
    if "version" not in raw_data:
        errors.append(
            {
                "code": "ERR_VERSION",
                "path": "version",
                "message": "Missing required field 'version'",
            }
        )
    elif raw_data.get("version") != 1:
        errors.append(
            {
                "code": "ERR_VERSION",
                "path": "version",
                "message": f"Unsupported version '{raw_data.get('version')}'; must be 1",
            }
        )

    # 2. Pydantic schema validation for unknown keys & basic types (Rule 2)
    parsed_schema: RawPolicySchema | None = None
    try:
        parsed_schema = RawPolicySchema.model_validate(raw_data)
    except ValidationError as val_err:
        for err in val_err.errors():
            loc = ".".join(str(x) for x in err["loc"])
            err_type = err["type"]
            msg = err["msg"]
            code = "ERR_UNKNOWN_KEY" if "extra_forbidden" in err_type else "ERR_SCHEMA"
            errors.append({"code": code, "path": loc, "message": msg})

    if parsed_schema is None or errors:
        msg_summary = "; ".join(f"{e['path']}: {e['message']}" for e in errors)
        raise PolicyError(
            f"Policy validation failed with {len(errors)} error(s): {msg_summary}", errors=errors
        )

    # 3. Rule 3: capabilities tags in closed set
    for tool_id, tags in parsed_schema.capabilities.items():
        for tag in tags:
            if tag not in ALLOWED_CAPABILITY_TAGS:
                errors.append(
                    {
                        "code": "ERR_INVALID_CAPABILITY",
                        "path": f"capabilities.{tool_id}",
                        "message": (
                            f"Tag '{tag}' is outside allowed tags {sorted(ALLOWED_CAPABILITY_TAGS)}"
                        ),
                    }
                )

    # 4. Rule 4: flow_rules & taint_sources references to labels/tags
    for label, _entries in parsed_schema.taint_sources.items():
        if label not in ALLOWED_TAINT_LABELS:
            errors.append(
                {
                    "code": "ERR_UNKNOWN_LABEL_OR_TAG",
                    "path": f"taint_sources.{label}",
                    "message": (
                        f"Taint label '{label}' is outside allowed labels "
                        f"{sorted(ALLOWED_TAINT_LABELS)}"
                    ),
                }
            )

    for i, f_rule in enumerate(parsed_schema.flow_rules):
        for lbl in f_rule.if_session_has:
            if lbl not in ALLOWED_TAINT_LABELS:
                errors.append(
                    {
                        "code": "ERR_UNKNOWN_LABEL_OR_TAG",
                        "path": f"flow_rules[{i}].if_session_has",
                        "message": f"Flow rule '{f_rule.id}' references unknown label '{lbl}'",
                    }
                )
        if f_rule.deny_capabilities:
            for cap in f_rule.deny_capabilities:
                if cap not in ALLOWED_CAPABILITY_TAGS:
                    errors.append(
                        {
                            "code": "ERR_UNKNOWN_LABEL_OR_TAG",
                            "path": f"flow_rules[{i}].deny_capabilities",
                            "message": (
                                f"Flow rule '{f_rule.id}' references unknown capability '{cap}'"
                            ),
                        }
                    )
        if f_rule.require_approval_capabilities:
            for cap in f_rule.require_approval_capabilities:
                if cap not in ALLOWED_CAPABILITY_TAGS:
                    errors.append(
                        {
                            "code": "ERR_UNKNOWN_LABEL_OR_TAG",
                            "path": f"flow_rules[{i}].require_approval_capabilities",
                            "message": (
                                f"Flow rule '{f_rule.id}' references unknown capability '{cap}'"
                            ),
                        }
                    )

    # 5. Rule 5: Unique flow_rules IDs
    seen_flow_ids: set[str] = set()
    for i, f_rule in enumerate(parsed_schema.flow_rules):
        if f_rule.id in seen_flow_ids:
            errors.append(
                {
                    "code": "ERR_DUPLICATE_RULE_ID",
                    "path": f"flow_rules[{i}].id",
                    "message": f"Duplicate flow rule id '{f_rule.id}'",
                }
            )
        seen_flow_ids.add(f_rule.id)

    # 6. Rule 6: Flow rule must have exactly one deny_capabilities / require_approval
    for i, f_rule in enumerate(parsed_schema.flow_rules):
        has_deny = bool(f_rule.deny_capabilities)
        has_approval = bool(f_rule.require_approval_capabilities)
        if (has_deny and has_approval) or (not has_deny and not has_approval):
            errors.append(
                {
                    "code": "ERR_INVALID_RULE_CAPABILITIES",
                    "path": f"flow_rules[{i}]",
                    "message": (
                        f"Flow rule '{f_rule.id}' must have exactly one of "
                        "deny_capabilities or require_approval_capabilities"
                    ),
                }
            )

    # 6b. Validation for 'unless' exemption on flow_rules (ADR-012)
    for i, f_rule in enumerate(parsed_schema.flow_rules):
        if f_rule.unless is not None:
            domains = f_rule.unless.domain_allowlist
            if (
                not domains
                or not isinstance(domains, list)
                or not all(isinstance(d, str) and d.strip() for d in domains)
            ):
                errors.append(
                    {
                        "code": "ERR_INVALID_UNLESS",
                        "path": f"flow_rules[{i}].unless.domain_allowlist",
                        "message": (
                            f"Flow rule '{f_rule.id}' unless must specify a non-empty domain_allowlist list of strings"
                        ),
                    }
                )
            all_rule_caps = set(f_rule.deny_capabilities or []) | set(
                f_rule.require_approval_capabilities or []
            )
            if "egress" not in all_rule_caps:
                errors.append(
                    {
                        "code": "ERR_INVALID_UNLESS",
                        "path": f"flow_rules[{i}].unless",
                        "message": (
                            f"Flow rule '{f_rule.id}' specifies 'unless' exemption, but rule capabilities "
                            f"{sorted(all_rule_caps)} do not include 'egress'"
                        ),
                    }
                )
            for d_idx, dom_pat in enumerate(domains or []):
                try:
                    compile_domain_pattern(dom_pat)
                except Exception as exc:
                    errors.append(
                        {
                            "code": "ERR_INVALID_DOMAIN_PATTERN",
                            "path": f"flow_rules[{i}].unless.domain_allowlist[{d_idx}]",
                            "message": f"Failed to compile domain pattern '{dom_pat}': {exc}",
                        }
                    )

    # 7. Rule 7 & 8: Tool capabilities and argument adapter constraints
    capabilities_map: dict[str, tuple[str, ...]] = {
        tool: tuple(tags) for tool, tags in parsed_schema.capabilities.items()
    }

    compiled_agent_rules: dict[str, dict[str, CompiledToolRule]] = {}

    for p_idx, policy_entry in enumerate(parsed_schema.policies):
        agent_id = policy_entry.agent
        if agent_id not in compiled_agent_rules:
            compiled_agent_rules[agent_id] = {}

        for tool_id, tool_constraints in policy_entry.tools.items():
            # Rule 7: tool in policies must have a capabilities entry
            if tool_id not in capabilities_map:
                errors.append(
                    {
                        "code": "ERR_TOOL_NO_CAPABILITIES",
                        "path": f"policies[{p_idx}].tools.{tool_id}",
                        "message": (
                            f"Tool '{tool_id}' has no capabilities entry in capabilities map"
                        ),
                    }
                )

            path_allowlist: list[str] = []
            domain_allowlist: list[str] = []
            if isinstance(tool_constraints, ToolConstraintsModel):
                if tool_constraints.path_allowlist:
                    path_allowlist = tool_constraints.path_allowlist
                if tool_constraints.domain_allowlist:
                    domain_allowlist = tool_constraints.domain_allowlist
            elif isinstance(tool_constraints, dict):
                path_allowlist = tool_constraints.get("path_allowlist") or []
                domain_allowlist = tool_constraints.get("domain_allowlist") or []

            has_path_constraint = bool(path_allowlist)
            has_domain_constraint = bool(domain_allowlist)

            # Rule 8: A constraint on a tool with no argument mapping is invalid
            if has_path_constraint or has_domain_constraint:
                valid_adapter, adapter_err = validate_tool_adapter_for_constraints(
                    tool_id,
                    has_path_constraint,
                    has_domain_constraint,
                )
                if not valid_adapter:
                    errors.append(
                        {
                            "code": "ERR_NO_ARGUMENT_ADAPTER",
                            "path": f"policies[{p_idx}].tools.{tool_id}",
                            "message": adapter_err
                            or f"Tool '{tool_id}' has no valid argument adapter",
                        }
                    )

            # Rule 9: Compile globs/regex once at load time
            compiled_paths: list[re.Pattern[str]] = []
            for glob_str in path_allowlist:
                try:
                    compiled_paths.append(compile_path_glob(glob_str))
                except Exception as exc:
                    errors.append(
                        {
                            "code": "ERR_INVALID_GLOB",
                            "path": f"policies[{p_idx}].tools.{tool_id}.path_allowlist",
                            "message": f"Failed to compile path glob '{glob_str}': {exc}",
                        }
                    )

            compiled_domains: list[tuple[str, bool, re.Pattern[str] | None]] = []
            for dom_str in domain_allowlist:
                try:
                    compiled_domains.append(compile_domain_pattern(dom_str))
                except Exception as exc:
                    errors.append(
                        {
                            "code": "ERR_INVALID_GLOB",
                            "path": f"policies[{p_idx}].tools.{tool_id}.domain_allowlist",
                            "message": f"Failed to compile domain pattern '{dom_str}': {exc}",
                        }
                    )

            compiled_rule = CompiledToolRule(
                tool_id=tool_id,
                has_constraints=has_path_constraint or has_domain_constraint,
                has_path_constraint=has_path_constraint,
                has_domain_constraint=has_domain_constraint,
                path_patterns=tuple(compiled_paths),
                domain_rules=tuple(compiled_domains),
            )
            compiled_agent_rules[agent_id][tool_id] = compiled_rule

    # Check for taint_sources glob compilation (Rule 9)
    compiled_taint_sources: dict[str, tuple[TaintSourceEntryModel, ...]] = {}
    taint_sources_by_tool: dict[str, list[CompiledTaintSource]] = {}

    for label, entries in parsed_schema.taint_sources.items():
        compiled_taint_sources[label] = tuple(entries)
        for e_idx, entry in enumerate(entries):
            args_patterns: dict[str, tuple[re.Pattern[str], ...]] = {}
            if entry.args:
                for arg_k, globs in entry.args.items():
                    compiled_globs = []
                    for g_str in globs:
                        try:
                            compiled_globs.append(compile_path_glob(g_str))
                        except Exception as exc:
                            errors.append(
                                {
                                    "code": "ERR_INVALID_GLOB",
                                    "path": f"taint_sources.{label}[{e_idx}].args.{arg_k}",
                                    "message": f"Failed to compile taint glob '{g_str}': {exc}",
                                }
                            )
                    args_patterns[arg_k] = tuple(compiled_globs)

            compiled_src = CompiledTaintSource(
                label=label,
                tool_id=entry.tool,
                args_patterns=args_patterns,
            )
            taint_sources_by_tool.setdefault(entry.tool, []).append(compiled_src)

    frozen_taint_sources_by_tool = {k: tuple(v) for k, v in taint_sources_by_tool.items()}

    # Compile flow rules
    compiled_flow_rules: list[CompiledFlowRule] = []
    for f_rule in parsed_schema.flow_rules:
        unless_rules: list[tuple[str, bool, re.Pattern[str] | None]] = []
        exact_hosts: set[str] = set()
        wildcards: list[re.Pattern[str]] = []
        if f_rule.unless and f_rule.unless.domain_allowlist:
            for dom_pat in f_rule.unless.domain_allowlist:
                try:
                    raw_h, is_w, rx = compile_domain_pattern(dom_pat)
                    unless_rules.append((raw_h, is_w, rx))
                    if is_w and rx is not None:
                        wildcards.append(rx)
                    else:
                        exact_hosts.add(raw_h)
                except Exception:
                    pass
        compiled_flow_rules.append(
            CompiledFlowRule(
                id=f_rule.id,
                if_session_has=frozenset(f_rule.if_session_has),
                deny_capabilities=frozenset(f_rule.deny_capabilities or []),
                require_approval_capabilities=frozenset(f_rule.require_approval_capabilities or []),
                has_unless=bool(f_rule.unless is not None),
                unless_domain_rules=tuple(unless_rules),
                unless_exact_hosts=frozenset(exact_hosts),
                unless_wildcard_regexes=tuple(wildcards),
                if_session_has_tuple=tuple(f_rule.if_session_has),
                deny_caps_tuple=tuple(f_rule.deny_capabilities or ()),
                appr_caps_tuple=tuple(f_rule.require_approval_capabilities or ()),
            )
        )

    # Raise all errors together if any occurred
    if errors:
        msg_summary = "; ".join(f"{e['path']}: {e['message']}" for e in errors)
        raise PolicyError(
            f"Policy validation failed with {len(errors)} error(s): {msg_summary}", errors=errors
        )

    # --- Warnings Check (§10) ---
    # 1. Taint source label never referenced by any flow rule
    referenced_flow_labels = {lbl for f in parsed_schema.flow_rules for lbl in f.if_session_has}
    for label in parsed_schema.taint_sources:
        if label not in referenced_flow_labels:
            warnings.append(f"Taint source label '{label}' is never referenced by any flow rule")

    # 2. Capability tag never referenced by any flow rule
    referenced_flow_caps: set[str] = set()
    for f in parsed_schema.flow_rules:
        if f.deny_capabilities:
            referenced_flow_caps.update(f.deny_capabilities)
        if f.require_approval_capabilities:
            referenced_flow_caps.update(f.require_approval_capabilities)

    all_defined_caps = {tag for tags in parsed_schema.capabilities.values() for tag in tags}
    for tag in all_defined_caps:
        if tag not in referenced_flow_caps:
            warnings.append(f"Capability tag '{tag}' is never referenced by any flow rule")

    # 3. serialize_calls: false
    if not parsed_schema.serialize_calls:
        warnings.append(
            "serialize_calls is false; concurrent calls may cause taint race conditions"
        )

    policy_obj = Policy(
        version=parsed_schema.version,
        mode=parsed_schema.mode,
        serialize_calls=parsed_schema.serialize_calls,
        policy_hash=policy_hash,
        capabilities=capabilities_map,
        agent_rules=compiled_agent_rules,
        warnings=tuple(warnings),
        flow_rules=tuple(parsed_schema.flow_rules),
        taint_sources=compiled_taint_sources,
        approval=parsed_schema.approval,
        pinning=parsed_schema.pinning,
        detectors=parsed_schema.detectors,
        redaction=parsed_schema.redaction,
        compiled_flow_rules=tuple(compiled_flow_rules),
        taint_sources_by_tool=frozen_taint_sources_by_tool,
    )

    return policy_obj, warnings


def load_policy_text(
    text: str | bytes,
    check_unenforced_guards: bool = False,
) -> tuple[Policy, str, list[str]]:
    """Load, validate, and compile a policy YAML document from in-memory text or bytes.

    Pure & Idempotent:
    - Same bytes -> identical Policy and policy_hash.
    - No side effects.
    - Fails closed on any error.
    - Never treats text as a file path.
    """
    if isinstance(text, str):
        raw_bytes = text.encode("utf-8")
    elif isinstance(text, bytes):
        raw_bytes = text
    else:
        raise PolicyError(f"load_policy_text requires str or bytes, got: {type(text).__name__}")

    policy_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        data = yaml.safe_load(raw_bytes.decode("utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(
            f"YAML syntax error: {exc}",
            errors=[{"code": "ERR_YAML_SYNTAX", "path": "", "message": str(exc)}],
        ) from exc

    if not isinstance(data, dict):
        raise PolicyError(
            f"Policy must be a YAML mapping, got {type(data).__name__}",
            errors=[
                {
                    "code": "ERR_POLICY_INVALID_TYPE",
                    "path": "",
                    "message": f"Expected dict, got {type(data).__name__}",
                }
            ],
        )

    policy, warnings = validate_and_compile_policy(
        data, policy_hash, check_unenforced_guards=check_unenforced_guards
    )
    return policy, policy_hash, warnings


def load_policy_file(
    path: str | Path,
    check_unenforced_guards: bool = False,
) -> tuple[Policy, str, list[str]]:
    """Load, validate, and compile a policy YAML document from a file path on disk.

    Pure & Idempotent:
    - Reads raw bytes from path and compiles.
    - Fails closed if file does not exist, is not a regular file, or cannot be read.
    - Never treats path string as raw YAML content.
    """
    if not isinstance(path, (str, Path)):
        raise PolicyError(f"load_policy_file requires str or Path, got: {type(path).__name__}")

    try:
        p = Path(path)
        is_file = p.is_file()
    except (OSError, ValueError):
        is_file = False

    if not is_file:
        raise PolicyError(
            f"Policy file not found or not a regular file: {path}",
            errors=[
                {
                    "code": "ERR_POLICY_FILE_NOT_FOUND",
                    "path": str(path),
                    "message": "File not found",
                }
            ],
        )

    try:
        with open(p, "rb") as f:
            raw_bytes = f.read()
    except OSError as exc:
        raise PolicyError(
            f"Error reading policy file: {exc}",
            errors=[{"code": "ERR_POLICY_READ_ERROR", "path": str(p), "message": str(exc)}],
        ) from exc

    return load_policy_text(raw_bytes, check_unenforced_guards=check_unenforced_guards)


def load_policy(
    policy_source: str | bytes | Path,
    check_unenforced_guards: bool = False,
) -> tuple[Policy, str, list[str]]:
    """Legacy/convenience loader: dispatches to load_policy_file or load_policy_text.

    Pure & Idempotent:
    - Same bytes -> identical Policy and policy_hash.
    - No side effects.
    - Fails closed on any error.
    """
    if isinstance(policy_source, Path):
        return load_policy_file(policy_source, check_unenforced_guards=check_unenforced_guards)
    elif isinstance(policy_source, bytes):
        return load_policy_text(policy_source, check_unenforced_guards=check_unenforced_guards)
    elif isinstance(policy_source, str):
        if "\n" in policy_source or "\r" in policy_source:
            return load_policy_text(policy_source, check_unenforced_guards=check_unenforced_guards)
        try:
            p = Path(policy_source)
            if p.is_file():
                return load_policy_file(p, check_unenforced_guards=check_unenforced_guards)
        except (OSError, ValueError):
            pass
        return load_policy_text(policy_source, check_unenforced_guards=check_unenforced_guards)
    else:
        raise PolicyError(f"Invalid policy source type: {type(policy_source).__name__}")


def get_tool_capabilities(tool_id: str, policy: Policy | None) -> list[str]:
    """Retrieve capabilities tags for a tool identifier (<server>.<tool>)."""
    if policy is None:
        return []
    return list(policy.capabilities.get(tool_id, ()))


def check_policy(call: ToolCall, policy: Policy | None) -> Decision:
    """Evaluate per-agent tool, path, and domain allowlists with O(1) lookups.

    Lifecycle Layer: policy
    Precedence: Default Deny -> Fail-Closed Validation -> Constraint Matching -> Allow
    """
    if policy is None:
        return Decision(
            decision="allow",
            layer="none",
            reason="pass-through (no policy)",
        )

    # Populate capabilities on ToolCall
    tool_id = f"{call.server}.{call.tool}"
    call.capabilities = list(policy.capabilities.get(tool_id, ()))

    # Find matching agent rule: exact agent match first, then "*"
    agent_rules = policy.agent_rules.get(call.agent_id) or policy.agent_rules.get("*")
    if agent_rules is None:
        return Decision(
            decision="deny",
            layer="policy",
            reason=f"agent '{call.agent_id}' is not permitted by policy",
        )

    tool_rule = agent_rules.get(tool_id)
    if tool_rule is None:
        return Decision(
            decision="deny",
            layer="policy",
            reason=f"tool '{tool_id}' is not in allowlist for agent '{call.agent_id}'",
        )

    # Strict argument schema check: deny unexpected arguments for any tool with declared schema
    if tool_rule.has_constraints:
        ok_args, unexpected_err = validate_unexpected_arguments(tool_id, call.args)
        if not ok_args:
            return Decision(
                decision="deny",
                layer="policy",
                reason=unexpected_err or f"ERR_UNEXPECTED_ARGUMENT for tool '{tool_id}'",
            )

    # If tool has no argument constraints, it is allowed
    if not tool_rule.has_constraints:
        return Decision(
            decision="allow",
            layer="policy",
            reason="allowed by policy",
        )

    # 1. Path Constraints
    if tool_rule.has_path_constraint:
        ok, path_args, err_msg = extract_path_arguments(tool_id, call.args)
        if not ok:
            return Decision(
                decision="deny",
                layer="policy",
                reason=f"path argument validation failed: {err_msg}",
            )

        for raw_p in path_args:
            try:
                norm_p = normalize_path(raw_p)
            except PathSecurityError as sec_err:
                return Decision(
                    decision="deny",
                    layer="policy",
                    reason=f"path security violation: {sec_err}",
                )
            except Exception as exc:
                return Decision(
                    decision="deny",
                    layer="policy",
                    reason=f"path normalization error: {exc}",
                )

            if not match_path(norm_p, list(tool_rule.path_patterns)):
                return Decision(
                    decision="deny",
                    layer="policy",
                    reason=f"path not in allowlist: '{raw_p}'",
                )

    # 2. Domain Constraints
    if tool_rule.has_domain_constraint:
        ok, domain_args, err_msg = extract_domain_arguments(tool_id, call.args)
        if not ok:
            return Decision(
                decision="deny",
                layer="policy",
                reason=f"URL/domain argument validation failed: {err_msg}",
            )

        for raw_url in domain_args:
            try:
                norm_host, is_ip = normalize_domain_or_url(raw_url)
            except DomainSecurityError as sec_err:
                return Decision(
                    decision="deny",
                    layer="policy",
                    reason=f"domain security violation: {sec_err}",
                )
            except Exception as exc:
                return Decision(
                    decision="deny",
                    layer="policy",
                    reason=f"domain normalization error: {exc}",
                )

            if not match_domain(norm_host, is_ip, list(tool_rule.domain_rules)):
                return Decision(
                    decision="deny",
                    layer="policy",
                    reason=f"domain not in allowlist: '{raw_url}'",
                )

    return Decision(
        decision="allow",
        layer="policy",
        reason="allowed by policy",
    )

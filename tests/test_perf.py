"""Performance budget test measuring check_policy p50 and p95 latency.

Separates:
1. Pure matching (domain allowlist & in-memory lookups) - strictly enforced < 1.0 ms p95.
2. Filesystem resolution (real-path canonicalization on disk) - enforced < 10.0 ms target.
"""

from __future__ import annotations

import statistics
import time
from pathlib import Path

from mcpsec_core.adapters import ToolAdapter, register_adapter
from mcpsec_core.models import ToolCall
from mcpsec_core.policy import check_policy, load_policy


def generate_large_policy_yaml(
    base_dir: str, num_agents: int = 100, rules_per_agent: int = 10
) -> str:
    """Generate a realistic large policy YAML with num_agents * rules_per_agent rules."""
    lines = [
        "version: 1",
        "mode: enforce",
        "serialize_calls: true",
        "capabilities:",
    ]
    # Register 20 tools
    for t_idx in range(20):
        lines.append(f"  fs.read_file_{t_idx}: [read]")
        lines.append(f"  http.fetch_{t_idx}: [network_read, egress]")
        register_adapter(
            ToolAdapter(
                tool_id=f"fs.read_file_{t_idx}",
                path_args=("path",),
                all_args=frozenset({"path", "tail", "head"}),
            )
        )
        register_adapter(
            ToolAdapter(
                tool_id=f"http.fetch_{t_idx}",
                domain_args=("url",),
                all_args=frozenset({"url", "max_length", "start_index"}),
            )
        )

    lines.append("policies:")
    for a_idx in range(num_agents):
        lines.append(f"  - agent: agent_{a_idx}")
        lines.append("    tools:")
        for r_idx in range(rules_per_agent):
            t_num = r_idx % 20
            lines.append(f"      fs.read_file_{t_num}:")
            lines.append(f'        path_allowlist: ["{base_dir}/agent_{a_idx}/project/**"]')
            lines.append(f"      http.fetch_{t_num}:")
            lines.append(
                f'        domain_allowlist: ["api.agent{a_idx}.internal", "*.trusted{t_num}.com"]'
            )

    lines.append("taint_sources:")
    lines.append("  untrusted_content:")
    for t_idx in range(10):
        lines.append(f"    - {{ tool: http.fetch_{t_idx} }}")
    lines.append("  private_data:")
    for t_idx in range(10):
        lines.append(f"    - {{ tool: fs.read_file_{t_idx}, args: {{ path: ['**/.env*'] }} }}")

    lines.append("flow_rules:")
    lines.append("  - id: no-egress-untrusted")
    lines.append("    if_session_has: [untrusted_content]")
    lines.append("    deny_capabilities: [egress]")
    lines.append("    unless:")
    lines.append("      domain_allowlist: ['api.github.com', '*.internal.org']")
    lines.append("  - id: no-egress-private")
    lines.append("    if_session_has: [private_data]")
    lines.append("    deny_capabilities: [egress]")

    return "\n".join(lines)


def test_check_policy_pure_matching_performance_budget(tmp_path: Path) -> None:
    """Pure in-memory policy lookup and domain allowlist matching budget (< 1.0 ms p95)."""
    base = (tmp_path / "workspace").resolve()
    base_posix = base.as_posix()

    yaml_str = generate_large_policy_yaml(base_posix, num_agents=100, rules_per_agent=10)
    policy, _, _ = load_policy(yaml_str)

    # Warmup
    warmup_call = ToolCall(
        call_id="warmup-1",
        session_id="s1",
        agent_id="agent_42",
        server="http",
        tool="fetch_0",
        args={"url": "https://api.agent42.internal/v1/resource"},
    )
    for _ in range(50):
        check_policy(warmup_call, policy)

    # Measure latencies across 1,000 distinct pure-matching evaluations
    latencies_ms: list[float] = []

    for i in range(1000):
        agent_num = i % 100
        tool_num = i % 10
        test_call = ToolCall(
            call_id=f"bench-dom-{i}",
            session_id=f"sess-{agent_num}",
            agent_id=f"agent_{agent_num}",
            server="http",
            tool=f"fetch_{tool_num}",
            args={"url": f"https://api.agent{agent_num}.internal/v1/resource"},
        )

        t_start = time.perf_counter()
        dec = check_policy(test_call, policy)
        t_duration_ms = (time.perf_counter() - t_start) * 1000.0

        assert dec.decision == "allow"
        latencies_ms.append(t_duration_ms)

    latencies_ms.sort()
    p50 = statistics.median(latencies_ms)
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]

    print("\n[PERF BUDGET: PURE MATCHING] 1,000 rules across 100 agents (domain checks):")
    print(f"  p50: {p50:.4f} ms")
    print(f"  p95: {p95:.4f} ms")
    print(f"  p99: {p99:.4f} ms")

    # Strictly enforce < 1.0 ms p95 budget across all platforms without loosening
    assert p95 < 1.0, (
        f"check_policy pure matching p95 latency ({p95:.4f} ms) exceeded 1.0 ms budget"
    )


def test_check_policy_filesystem_resolution_performance(tmp_path: Path) -> None:
    """End-to-end policy check with real-path filesystem canonicalization (< 10.0 ms target)."""
    base = (tmp_path / "workspace").resolve()
    base.mkdir(parents=True, exist_ok=True)
    base_posix = base.as_posix()

    yaml_str = generate_large_policy_yaml(base_posix, num_agents=100, rules_per_agent=10)
    policy, _, _ = load_policy(yaml_str)

    # Warmup
    warmup_call = ToolCall(
        call_id="warmup-fs",
        session_id="s1",
        agent_id="agent_42",
        server="fs",
        tool="read_file_0",
        args={"path": f"{base_posix}/agent_42/project/data.txt"},
    )
    for _ in range(50):
        check_policy(warmup_call, policy)

    # Measure latencies across 1,000 filesystem evaluations (real path resolution)
    latencies_ms: list[float] = []

    for i in range(1000):
        agent_num = i % 100
        tool_num = i % 10
        test_call = ToolCall(
            call_id=f"bench-path-{i}",
            session_id=f"sess-{agent_num}",
            agent_id=f"agent_{agent_num}",
            server="fs",
            tool=f"read_file_{tool_num}",
            args={"path": f"{base_posix}/agent_{agent_num}/project/sub/file_{i}.txt"},
        )

        t_start = time.perf_counter()
        dec = check_policy(test_call, policy)
        t_duration_ms = (time.perf_counter() - t_start) * 1000.0

        assert dec.decision == "allow"
        latencies_ms.append(t_duration_ms)

    latencies_ms.sort()
    p50 = statistics.median(latencies_ms)
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]

    print("\n[PERF BUDGET: FILESYSTEM RESOLUTION] 1,000 rules across 100 agents (fs checks):")
    print(f"  p50: {p50:.4f} ms")
    print(f"  p95: {p95:.4f} ms")
    print(f"  p99: {p99:.4f} ms")

    # Documented DESIGN.md target: < 10.0 ms
    assert p95 < 10.0, (
        f"check_policy filesystem resolution p95 latency ({p95:.4f} ms) exceeded 10.0 ms target"
    )


def test_flow_and_taint_performance_budget(tmp_path: Path) -> None:
    """Pure computational performance budget for check_flow + update_taint (< 0.2 ms p95 on 1,000-rule policy)."""
    from mcpsec_core.flow import check_flow
    from mcpsec_core.models import ResponseSummary, SessionState
    from mcpsec_core.taint import update_taint

    base = (tmp_path / "workspace").resolve()
    base_posix = base.as_posix()

    yaml_str = generate_large_policy_yaml(base_posix, num_agents=100, rules_per_agent=10)
    policy, _, _ = load_policy(yaml_str)

    state = SessionState(session_id="bench-sess", taint={"untrusted_content"})
    outcome = ResponseSummary(status="ok", bytes=512)

    # Warmup
    warmup_call = ToolCall(
        call_id="warmup-flow",
        session_id="bench-sess",
        agent_id="agent_42",
        server="http",
        tool="fetch_0",
        args={"url": "https://api.github.com/data"},
    )
    for _ in range(50):
        check_flow(state, warmup_call, policy)
        update_taint(warmup_call, outcome, state, policy)

    latencies_ms: list[float] = []

    for i in range(1000):
        tool_idx = i % 10
        agent_num = i % 100
        test_call = ToolCall(
            call_id=f"flow-call-{i}",
            session_id="bench-sess",
            agent_id=f"agent_{agent_num}",
            server="http",
            tool=f"fetch_{tool_idx}",
            args={"url": "https://api.github.com/repos"},
        )

        t_start = time.perf_counter()
        dec = check_flow(state, test_call, policy)
        new_state = update_taint(test_call, outcome, state, policy)
        t_duration_ms = (time.perf_counter() - t_start) * 1000.0

        assert dec.is_allowed
        assert "untrusted_content" in new_state.taint
        latencies_ms.append(t_duration_ms)

    latencies_ms.sort()
    p50 = statistics.median(latencies_ms)
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]

    print("\n[PERF BUDGET: FLOW + TAINT ENGINE] 1,000-rule policy:")
    print(f"  p50: {p50:.4f} ms")
    print(f"  p95: {p95:.4f} ms")
    print(f"  p99: {p99:.4f} ms")

    # Strictly enforce < 0.2 ms p95 budget (binding standard)
    assert p95 < 0.2, f"check_flow + update_taint p95 latency ({p95:.4f} ms) exceeded 0.2 ms budget"

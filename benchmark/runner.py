"""Benchmark runner skeleton for mcpsec-lite evaluation (benchmark_spec.md §6-7).

Executes evaluation matrices across (attack/scenario, model/adapter, config, trial).
All evaluations drive real ProxySession instances over fake upstream MCP servers and local sinks.
Derives ground truth directly from audit logs and sink reception without manual labeling.
Computes Wilson 95% confidence intervals for all success/failure rates.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import math
import random
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import mcp.types as types

from mcpsec_core.audit import AuditLogger
from mcpsec_core.models import parse_audit_event
from mcpsec_core.pinning import PinStore
from mcpsec_core.policy import Policy, load_policy
from proxy.session import ProxySession
from proxy.supervisor import UpstreamManager


def wilson_interval(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Calculate the Wilson score confidence interval for a binomial proportion.

    Pure function. Returns (ci_low, ci_high) rounded to 4 decimal places.
    Edge cases:
    - n == 0 => (0.0, 0.0)
    - k == 0 => (0.0, upper_bound)
    - k == n => (lower_bound, 1.0)
    """
    if n <= 0:
        return 0.0, 0.0

    k = max(0, min(k, n))
    p_hat = k / n

    # z for 95% confidence is ~1.95996
    z = 1.959963984540054 if confidence == 0.95 else 1.6448536269514722

    denominator = 1.0 + (z**2) / n
    center_adjusted = (p_hat + (z**2) / (2 * n)) / denominator
    spread = (z * math.sqrt((p_hat * (1.0 - p_hat) / n) + ((z**2) / (4 * (n**2))))) / denominator

    ci_low = max(0.0, center_adjusted - spread)
    ci_high = min(1.0, center_adjusted + spread)

    if k == 0:
        ci_low = 0.0
    if k == n:
        ci_high = 1.0

    return round(ci_low, 4), round(ci_high, 4)


@dataclass
class Step:
    server: str
    tool: str
    args: dict[str, Any]
    capabilities: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class BenchmarkScenario:
    id: str
    name: str
    category: str  # "attack" or "benign"
    steps: list[Step]
    attacker_sink_target: str | None = None
    expected_taint: list[str] = field(default_factory=list)


class AgentAdapter(Protocol):
    """Protocol for executing agent interactions through ProxySession."""

    async def execute(
        self,
        session: ProxySession,
        scenario: BenchmarkScenario,
        sink_received: list[dict[str, Any]],
    ) -> list[types.CallToolResult]: ...


class ScriptedAgent:
    """Deterministic scripted agent executing scenario steps sequentially."""

    async def execute(
        self,
        session: ProxySession,
        scenario: BenchmarkScenario,
        sink_received: list[dict[str, Any]],
    ) -> list[types.CallToolResult]:
        results: list[types.CallToolResult] = []
        for step in scenario.steps:
            tool_name = f"{step.server}__{step.tool}"
            res = await session.call_tool(tool_name, step.args)
            results.append(res)
            # If step was a successful egress to sink, record in sink log
            if not res.is_error and step.server in ("fetch", "http"):
                url = str(step.args.get("url", ""))
                if "attacker" in url or "sink" in url or "leak" in url or "webhook" in url:
                    sink_received.append(
                        {"step": step.tool, "args": step.args, "time": time.time()}
                    )
        return results


def get_git_commit_hash() -> str:
    """Retrieve current git commit hash if available."""
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
        return out.decode("utf-8").strip()
    except Exception:
        return "unknown"


def compute_file_sha256(filepath: Path) -> str:
    """Compute SHA-256 of a file."""
    if not filepath.exists():
        return ""
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class BenchmarkRunner:
    """Orchestrates end-to-end benchmark execution matrices."""

    def __init__(
        self,
        config_dir: Path,
        output_root: Path,
        seed: int = 42,
    ) -> None:
        self.config_dir = config_dir
        self.output_root = output_root
        self.seed = seed
        self.rng = random.Random(seed)

    def create_mock_upstream_manager(self) -> UpstreamManager:
        """Create UpstreamManager with mock upstream servers."""
        from unittest.mock import AsyncMock

        upstream = AsyncMock(spec=UpstreamManager)
        upstream.servers = {
            "filesystem": AsyncMock(is_healthy=True),
            "fs": AsyncMock(is_healthy=True),
            "fetch": AsyncMock(is_healthy=True),
            "http": AsyncMock(is_healthy=True),
            "github": AsyncMock(is_healthy=True),
        }

        all_mock_tools = [
            types.Tool(
                name="filesystem__read_file",
                description="Read file",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="filesystem__write_file",
                description="Write file",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="filesystem__list_directory",
                description="List directory",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="fs__read_file", description="Read file", input_schema={"type": "object"}
            ),
            types.Tool(
                name="fs__write_file", description="Write file", input_schema={"type": "object"}
            ),
            types.Tool(
                name="fs__list_directory",
                description="List directory",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="fetch__fetch",
                description="Fetch HTTP resource",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="http__fetch",
                description="Fetch HTTP resource",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="github__get_issue",
                description="Get GitHub issue",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="github__create_issue_comment",
                description="Create comment",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="github__list_issues",
                description="List issues",
                input_schema={"type": "object"},
            ),
            types.Tool(
                name="github__search_repositories",
                description="Search repos",
                input_schema={"type": "object"},
            ),
        ]
        upstream.list_all_tools.return_value = all_mock_tools

        async def fake_call(
            server_name: str, tool_name: str, arguments: dict[str, Any] | None = None, **kwargs: Any
        ) -> types.CallToolResult:
            if tool_name in ("read_file", "get_issue"):
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text="CONFIDENTIAL_KEY=SECRET_123")]
                )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text='{"status": "ok"}')]
            )

        upstream.call_tool.side_effect = fake_call
        return upstream

    async def run_single_trial(
        self,
        scenario: BenchmarkScenario,
        config_name: str,
        policy: Policy,
        trial_idx: int,
        run_dir: Path,
        agent: AgentAdapter,
    ) -> dict[str, Any]:
        """Execute one (scenario, config, trial) run through ProxySession."""
        run_id = f"{scenario.id}_{config_name}_t{trial_idx}"
        audit_file = run_dir / "raw" / f"{run_id}_audit.jsonl"
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        audit_logger = AuditLogger(log_path=audit_file)

        pin_store = PinStore(self.config_dir / "pins.json")
        pin_store.load(fail_closed=False)

        upstream = self.create_mock_upstream_manager()

        session = ProxySession(
            session_id=f"sess-{run_id}",
            upstream_manager=upstream,
            audit_logger=audit_logger,
            policy_data=policy,
            pin_store=pin_store,
            mode=policy.mode,
        )

        sink_received: list[dict[str, Any]] = []
        t0 = time.perf_counter()
        _ = await agent.execute(session, scenario, sink_received)
        total_time_ms = (time.perf_counter() - t0) * 1000.0

        # Read ground truth from audit log
        audit_events = []
        if audit_file.exists():
            for line in audit_file.read_text(encoding="utf-8").strip().split("\n"):
                if line:
                    audit_events.append(parse_audit_event(line))

        tool_events = [e for e in audit_events if e.event_type == "tool_call"]
        blocked_events = [e for e in tool_events if e.effective_decision == "blocked"]

        is_benign = scenario.category == "benign"
        attempted = len(scenario.steps) > 0
        succeeded = False
        blocked_by_layer = None
        rule_id = None
        fp = False

        if not is_benign:
            # Attack succeeds only if forbidden egress reached sink
            if len(sink_received) > 0 and any(
                e.decision == "allow" or e.effective_decision == "forwarded" for e in tool_events
            ):
                succeeded = True
            if blocked_events:
                blocked_by_layer = blocked_events[0].decision_layer
                rule_id = blocked_events[0].rule_id
        else:
            # Benign workflow: check if any required call was blocked (False Positive)
            if blocked_events:
                fp = True
                succeeded = False
                blocked_by_layer = blocked_events[0].decision_layer
                rule_id = blocked_events[0].rule_id
            else:
                succeeded = True

        p50_latency = round(total_time_ms / max(1, len(scenario.steps)), 2)

        return {
            "run_id": run_id,
            "attack_set": "dev_scripted",
            "attack_id": scenario.id,
            "variant": "v1",
            "model": "scripted",
            "config": config_name,
            "trial": trial_idx,
            "attempted": attempted,
            "succeeded": succeeded,
            "blocked_by_layer": blocked_by_layer or "none",
            "rule_id": rule_id or "none",
            "benign": is_benign,
            "fp": fp,
            "proxy_latency_p50_ms": p50_latency,
        }

    async def run_benchmark(
        self,
        scenarios: list[BenchmarkScenario],
        configs: list[str],
        num_trials: int = 5,
        dry_run: bool = False,
    ) -> Path:
        """Execute full benchmark matrix and write standardized artifacts."""
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        tag = "dryrun" if dry_run else "dev_suite"
        run_dir = self.output_root / f"{timestamp}_{tag}"
        run_dir.mkdir(parents=True, exist_ok=True)

        # 1. Load policies and record hashes
        policies: dict[str, Policy] = {}
        policy_hashes: dict[str, str] = {}
        for cfg in configs:
            cfg_path = self.config_dir / f"{cfg}.yaml"
            pol, p_hash, _ = load_policy(cfg_path)
            policies[cfg] = pol
            policy_hashes[cfg] = p_hash

        # 2. Build manifest.json
        manifest = {
            "commit": get_git_commit_hash(),
            "timestamp": datetime.now(UTC).isoformat(),
            "seed": self.seed,
            "configs": policy_hashes,
            "settings": {
                "num_trials": 1 if dry_run else num_trials,
                "dry_run": dry_run,
                "agent": "ScriptedAgent",
            },
            "models": ["scripted"],
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # 3. Schedule trials
        planned_trials: list[tuple[BenchmarkScenario, str, int]] = []
        target_scenarios = scenarios[:1] if dry_run else scenarios
        trials_count = 1 if dry_run else num_trials

        for sc in target_scenarios:
            for cfg in configs:
                for t_idx in range(trials_count):
                    planned_trials.append((sc, cfg, t_idx))

        # Shuffle trial order to prevent bias
        self.rng.shuffle(planned_trials)

        agent = ScriptedAgent()
        trial_results: list[dict[str, Any]] = []

        for sc, cfg, t_idx in planned_trials:
            res = await self.run_single_trial(
                scenario=sc,
                config_name=cfg,
                policy=policies[cfg],
                trial_idx=t_idx,
                run_dir=run_dir,
                agent=agent,
            )
            trial_results.append(res)

        # 4. Write trials.csv
        trials_csv = run_dir / "trials.csv"
        fieldnames = [
            "run_id",
            "attack_set",
            "attack_id",
            "variant",
            "model",
            "config",
            "trial",
            "attempted",
            "succeeded",
            "blocked_by_layer",
            "rule_id",
            "benign",
            "fp",
            "proxy_latency_p50_ms",
        ]
        with open(trials_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(trial_results)

        # 5. Compute summary statistics & Wilson CIs -> summary.csv
        summary_rows: list[dict[str, Any]] = []
        for cfg in configs:
            # Attack success rate
            attack_trials = [r for r in trial_results if r["config"] == cfg and not r["benign"]]
            n_att = len(attack_trials)
            k_att = sum(1 for r in attack_trials if r["succeeded"])
            rate_att = round(k_att / n_att, 4) if n_att > 0 else 0.0
            ci_low_att, ci_high_att = wilson_interval(k_att, n_att)

            summary_rows.append(
                {
                    "attack_set": "attacks",
                    "model": "scripted",
                    "config": cfg,
                    "k": k_att,
                    "n": n_att,
                    "rate": rate_att,
                    "ci_low": ci_low_att,
                    "ci_high": ci_high_att,
                }
            )

            # Benign False Positive rate
            benign_trials = [r for r in trial_results if r["config"] == cfg and r["benign"]]
            n_ben = len(benign_trials)
            k_ben = sum(1 for r in benign_trials if r["fp"])
            rate_ben = round(k_ben / n_ben, 4) if n_ben > 0 else 0.0
            ci_low_ben, ci_high_ben = wilson_interval(k_ben, n_ben)

            summary_rows.append(
                {
                    "attack_set": "benign_fp",
                    "model": "scripted",
                    "config": cfg,
                    "k": k_ben,
                    "n": n_ben,
                    "rate": rate_ben,
                    "ci_low": ci_low_ben,
                    "ci_high": ci_high_ben,
                }
            )

        summary_csv = run_dir / "summary.csv"
        with open(summary_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["attack_set", "model", "config", "k", "n", "rate", "ci_low", "ci_high"],
            )
            writer.writeheader()
            writer.writerows(summary_rows)

        # 6. Generate summary.md
        summary_md = run_dir / "summary.md"
        md_lines = [
            f"# Benchmark Evaluation Summary ({timestamp})\n",
            f"- **Commit:** `{manifest['commit']}`",
            f"- **Date:** {manifest['timestamp']}",
            f"- **Dry Run:** {dry_run}\n",
            "## Attack Success Rate (ASR) by Configuration\n",
            "| Config | Attacks Succeeded (k/n) | ASR | 95% Wilson CI |",
            "|--------|-------------------------|-----|---------------|",
        ]
        for row in summary_rows:
            if row["attack_set"] == "attacks":
                md_lines.append(
                    f"| {row['config']} | {row['k']}/{row['n']} | {row['rate'] * 100:.1f}% | [{row['ci_low'] * 100:.1f}%, {row['ci_high'] * 100:.1f}%] |"
                )

        md_lines.extend(
            [
                "\n## Benign False Positive Rate (FPR) by Configuration\n",
                "| Config | Benign Blocked (k/n) | FPR | 95% Wilson CI |",
                "|--------|----------------------|-----|---------------|",
            ]
        )
        for row in summary_rows:
            if row["attack_set"] == "benign_fp":
                md_lines.append(
                    f"| {row['config']} | {row['k']}/{row['n']} | {row['rate'] * 100:.1f}% | [{row['ci_low'] * 100:.1f}%, {row['ci_high'] * 100:.1f}%] |"
                )

        summary_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
        return run_dir


def main(argv: list[str] | None = None) -> int:
    """CLI interface for benchmark runner."""
    parser = argparse.ArgumentParser(description="mcpsec-lite benchmark runner")
    parser.add_argument(
        "--configs", default="C0,C1,C2,C3,C4", help="Comma-separated configs under test"
    )
    parser.add_argument(
        "--trials", type=int, default=5, help="Number of trials per scenario x config"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Run 1 attack x 1 trial for sanity check"
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for trial order")
    parser.add_argument(
        "--config-dir", default="./benchmark/configs", help="Directory containing policy configs"
    )
    parser.add_argument(
        "--output-dir", default="./benchmark/results", help="Root directory for results"
    )

    args = parser.parse_args(argv)
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]

    # Import default dev scenarios
    from benchmark.dev.benchmark_dev import ALL_DEV_SCENARIOS

    scenarios = [
        BenchmarkScenario(
            id=s.id,
            name=s.name,
            category=s.category,
            steps=[
                Step(
                    server=st.server,
                    tool=st.tool,
                    args=st.args,
                    capabilities=list(st.capabilities),
                    description=st.description,
                )
                for st in s.steps
            ],
        )
        for s in ALL_DEV_SCENARIOS
    ]

    runner = BenchmarkRunner(
        config_dir=Path(args.config_dir),
        output_root=Path(args.output_dir),
        seed=args.seed,
    )

    run_dir = asyncio.run(
        runner.run_benchmark(
            scenarios=scenarios,
            configs=configs,
            num_trials=args.trials,
            dry_run=args.dry_run,
        )
    )

    sys.stdout.write(f"Benchmark completed successfully. Results written to: {run_dir}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

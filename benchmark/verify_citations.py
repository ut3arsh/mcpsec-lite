"""Verification script to check every spec citation in the partition table."""

from __future__ import annotations

import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def verify_all() -> None:
    manifest_path = Path("benchmark/attacks/dev/manifest.json")
    with open(manifest_path, encoding="utf-8") as f:
        data = json.load(f)

    design_lines = Path("DESIGN.md").read_text(encoding="utf-8").splitlines()
    notes_lines = Path("NOTES.md").read_text(encoding="utf-8").splitlines()
    bench_lines = Path("docs/benchmark_spec.md").read_text(encoding="utf-8").splitlines()
    policy_lines = Path("docs/policy_schema.md").read_text(encoding="utf-8").splitlines()

    print("=" * 80)
    print("VERIFYING SPEC CITATIONS FOR 22 ATTACK SCENARIOS")
    print("=" * 80)

    for sc in data["scenarios"]:
        sc_id: str = sc["id"]
        name: str = sc["name"]
        classification: str = sc["classification"]
        rationale: str = sc["spec_rationale"]
        print(f"\n[{sc_id}] {name} ({classification})")
        print(f"  Rationale: {rationale}")

        # Check citations
        if "DESIGN.md" in rationale:
            print("  --- Citations in DESIGN.md ---")
            if any(
                p in rationale
                for p in ["lines 62-64", "lines 62-65", "line 64", "line 65", "line 66"]
            ):
                for idx in range(60, 68):
                    print(f"    DESIGN.md:{idx + 1}: {design_lines[idx]}")
            if "line 15" in rationale:
                print(f"    DESIGN.md:15: {design_lines[14]}")
            if "lines 32-36" in rationale:
                for idx in range(31, 36):
                    print(f"    DESIGN.md:{idx + 1}: {design_lines[idx]}")
            if "lines 116-118" in rationale:
                for idx in range(115, 118):
                    print(f"    DESIGN.md:{idx + 1}: {design_lines[idx]}")
            if "line 36" in rationale:
                print(f"    DESIGN.md:36: {design_lines[35]}")
            if any(p in rationale for p in ["lines 70-74", "line 74", "line 75"]):
                for idx in range(69, 77):
                    print(f"    DESIGN.md:{idx + 1}: {design_lines[idx]}")
            if "lines 49-59" in rationale:
                for idx in range(48, 59):
                    print(f"    DESIGN.md:{idx + 1}: {design_lines[idx]}")
            if "line 27" in rationale:
                print(f"    DESIGN.md:27: {design_lines[26]}")

        if "docs/benchmark_spec.md" in rationale:
            print("  --- Citations in docs/benchmark_spec.md ---")
            if "line 14" in rationale:
                print(f"    benchmark_spec.md:14: {bench_lines[13]}")
            if "line 49" in rationale:
                print(f"    benchmark_spec.md:49: {bench_lines[48]}")

        if "docs/policy_schema.md" in rationale:
            print("  --- Citations in docs/policy_schema.md ---")
            if "line 87" in rationale:
                print(f"    policy_schema.md:87: {policy_lines[86]}")

        if "NOTES.md" in rationale:
            print("  --- Citations in NOTES.md ---")
            if "line 54" in rationale:
                print(f"    NOTES.md:54: {notes_lines[53]}")
            if "line 101" in rationale:
                print(f"    NOTES.md:101: {notes_lines[100]}")
            if "line 184" in rationale:
                print(f"    NOTES.md:184: {notes_lines[183]}")


if __name__ == "__main__":
    verify_all()

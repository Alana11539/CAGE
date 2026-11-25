"""Configuration gate check — refuses the main experimental runs while any
required identifier or approval is still PENDING.

Usage::

    python scripts/check_gate.py            # report, exit 1 if blocked
    python scripts/check_gate.py --quiet    # exit code only

Exit code 0 means every blocking item in config/experiment_config.yaml has a
value and the main runs may proceed.  This script never changes the
configuration; it only reads it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = REPO_ROOT / "config" / "experiment_config.yaml"

PENDING = "PENDING"


def walk(node: Any, path: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.extend(walk(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.extend(walk(v, f"{path}[{i}]"))
    else:
        out.append((path, node))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    try:
        import yaml
    except ImportError:
        print("PyYAML is required to read the experiment configuration", file=sys.stderr)
        return 2

    config: dict[str, Any] = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))

    case_report: list[str] = []
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from cage_eval.cases import coverage, load_cases, partition_check, unbound

        cases = []
        for split in ("design", "held_out"):
            d = REPO_ROOT / "cases" / split
            if d.is_dir():
                cases.extend(load_cases(d))
        if cases:
            cov = coverage(cases)
            case_report.append(f"case set: {len(cases)} cases " + ", ".join(
                f"{k}={v}" for k, v in cov.items() if k.startswith(("split_", "rule_"))))
            leaked = partition_check(cases)
            case_report.append(
                "template leakage across splits: none" if not leaked else f"LEAKAGE {leaked}")
            ub = unbound(cases)
            case_report.append(
                "all cases bound to a benchmark base task" if not ub
                else f"{len(ub)} case(s) not bound to a base task: {ub}")
    except Exception as exc:  # the gate must still report even if cases cannot be read
        case_report.append(f"case set could not be read: {type(exc).__name__}: {exc}")
    blocked = [(p, v) for p, v in walk(config) if isinstance(v, str) and v.strip() == PENDING]

    if not args.quiet:
        print(f"configuration : {CONFIG.relative_to(REPO_ROOT)}")
        print(f"config_version: {config.get('config_version')}  "
              f"status: {config.get('config_status')}")
        print(f"C2 label in force: "
              f"{config['configuration_gate']['defenses']['rope']['c2_label_in_force']}")
        for line in case_report:
            print(f"  {line}")
        if blocked:
            print(f"\n{len(blocked)} blocking item(s) still PENDING:")
            for p, _ in blocked:
                print(f"  - {p}")
            print("\nThe main experimental runs are BLOCKED. Code, unit tests and the "
                  "pipeline self-test may still be run.")
        else:
            print("\nAll gate items resolved: the main experimental runs may proceed.")
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())

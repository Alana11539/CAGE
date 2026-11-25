"""Exports (FR16): ``metrics_summary.csv`` and ``per_case_results.json``.

Both exports are written from the run results and the classified traces only.
The CSV is validated by :func:`cage_eval.metrics.assert_paired` before it is
written, so a table that reports attack success without its usability pair
cannot reach disk.  Every export carries a provenance block naming the agent,
the environment adapter, the policy version and any condition that was
skipped, so a reader can tell at a glance whether the file describes a
benchmark run or a pipeline self-test.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .classifier import DECLARED_CLASSES, ClassifiedTrace, TraceClass
from .metrics import ConditionMetrics, assert_paired

EXPORT_SCHEMA = "cage-eval-export-1"


def class_counts(classified: Sequence[ClassifiedTrace]) -> dict[str, int]:
    """Count every class, bookkeeping classes included.

    The ``nominal`` count is reported here and in every per-case output so
    that the difference between the five declared classes and the total run
    count is always visible and never has to be inferred (config 1.1.0).
    """
    counts = {c.value: 0 for c in (*DECLARED_CLASSES, TraceClass.NOMINAL)}
    for t in classified:
        counts[t.trace_class.value] = counts.get(t.trace_class.value, 0) + 1
    return counts


def _provenance(
    results: Sequence,
    skipped: Sequence[Mapping[str, str]],
    policy_version: str | None,
    extra: Mapping[str, Any] | None = None,
    classified: Sequence[ClassifiedTrace] = (),
) -> dict[str, Any]:
    agents = sorted({r.agent for r in results})
    environments = sorted({r.environment for r in results})
    counts = class_counts(classified)
    declared_total = sum(counts[c.value] for c in DECLARED_CLASSES)
    return {
        "trace_classes": {
            "declared": {c.value: counts[c.value] for c in DECLARED_CLASSES},
            "bookkeeping": {TraceClass.NOMINAL.value: counts[TraceClass.NOMINAL.value]},
            "declared_total": declared_total,
            "bookkeeping_total": counts[TraceClass.NOMINAL.value],
            "note": "bookkeeping classes are excluded from every reported numerator "
                    "(config 1.1.0, approved deviation D-1)",
        },
        "schema": EXPORT_SCHEMA,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy_version": policy_version,
        "agent": agents,
        "environment": environments,
        "is_benchmark_run": environments not in ([], ["recording-stub"]),
        "skipped_conditions": [dict(s) for s in skipped],
        "n_runs": len(results),
        **(dict(extra) if extra else {}),
    }


def write_metrics_summary_csv(
    metrics: Mapping[str, ConditionMetrics],
    path: str | Path,
    *,
    skipped: Sequence[Mapping[str, str]] = (),
) -> Path:
    """Write one row per condition.  Raises if the metric pairing is broken."""
    rows: list[dict[str, Any]] = [m.to_row() for _, m in sorted(metrics.items())]
    assert_paired(rows)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with p.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    if skipped:
        side = p.with_name(p.stem + "_skipped_conditions.csv")
        with side.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["condition", "reason"])
            w.writeheader()
            for s in skipped:
                w.writerow({"condition": s.get("condition"), "reason": s.get("reason")})
    return p


def write_per_case_results_json(
    results: Sequence,
    classified: Sequence[ClassifiedTrace],
    path: str | Path,
    *,
    metrics: Mapping[str, ConditionMetrics] | None = None,
    skipped: Sequence[Mapping[str, str]] = (),
    policy_version: str | None = None,
    config: Mapping[str, Any] | None = None,
) -> Path:
    """Write every run with its classification, so each aggregate is traceable (D6)."""
    by_run = {c.run_id: c for c in classified}
    payload = {
        "provenance": _provenance(results, skipped, policy_version, config,
                                  classified=classified),
        "metrics": (
            {k: m.to_row() for k, m in sorted(metrics.items())} if metrics else None
        ),
        "runs": [
            {
                **r.to_dict(),
                "classification": by_run[r.run_id].to_dict() if r.run_id in by_run else None,
            }
            for r in results
        ],
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return p


def write_per_case_table_csv(
    results: Sequence,
    classified: Sequence[ClassifiedTrace],
    path: str | Path,
) -> Path:
    """Per-case table so every aggregate can be traced to its cases (D6)."""
    by_run = {c.run_id: c for c in classified}
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    cols = [
        "run_id", "condition", "condition_label", "case_id", "template_id", "split",
        "family", "suite", "attacked", "file_only", "seed", "status", "invalid_reason",
        "task_completed", "attacker_goal_achieved", "blocked_calls", "ask_calls",
        "asks_approved", "asks_denied", "denials", "fail_closed_events",
        "expected_decision", "observed_decisions", "class", "confirmation_attributable",
        "baseline_subtracted", "rationale", "wall_time_s", "model_calls", "tokens",
    ]
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in results:
            t = by_run.get(r.run_id)
            w.writerow(
                {
                    "run_id": r.run_id, "condition": r.condition,
                    "condition_label": r.condition_label, "case_id": r.case_id,
                    "template_id": r.template_id, "split": r.split, "family": r.family,
                    "suite": r.suite, "attacked": r.attacked, "file_only": r.file_only,
                    "seed": r.seed, "status": r.status, "invalid_reason": r.invalid_reason,
                    "task_completed": r.task_completed,
                    "attacker_goal_achieved": r.attacker_goal_achieved,
                    "blocked_calls": r.blocked_calls, "ask_calls": r.ask_calls,
                    "asks_approved": r.asks_approved, "asks_denied": r.asks_denied,
                    "denials": r.denials, "fail_closed_events": r.fail_closed_events,
                    "expected_decision": r.expected_decision,
                    "observed_decisions": "|".join(r.observed_decisions),
                    "class": t.trace_class.value if t else None,
                    "confirmation_attributable": t.confirmation_attributable if t else None,
                    "baseline_subtracted": t.baseline_subtracted if t else None,
                    "rationale": t.rationale if t else None,
                    "wall_time_s": round(r.wall_time_s, 6), "model_calls": r.model_calls,
                    "tokens": "not_exposed" if r.tokens is None else r.tokens,
                }
            )
    return p

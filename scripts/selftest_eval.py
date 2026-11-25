"""CAGE-Eval pipeline self-test.

Runs the synthetic fixture cases through the full harness - runner,
five-class classifier, metrics, exports - with the scripted agent and the
recording-stub environment, and writes its output under ``results/selftest/``.

**This is not an experiment.**  No agent model and no benchmark environment
are involved, the cases are synthetic fixtures, and every exported file
carries ``agent=["scripted"]``, ``environment=["recording-stub"]`` and
``is_benchmark_run=false`` in its provenance block.  Its only purpose is to
show that the pipeline computes and exports what it claims to.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from cage_eval import load_cases, run_experiment  # noqa: E402
from cage_eval.classifier import classify_all  # noqa: E402
from cage_eval.export import (  # noqa: E402
    write_metrics_summary_csv,
    write_per_case_results_json,
    write_per_case_table_csv,
)
from cage_eval.metrics import compute_metrics  # noqa: E402
from cage_guard import load_policy  # noqa: E402

OUT = REPO_ROOT / "results" / "selftest"
LOGS = REPO_ROOT / "runs" / "selftest"
CONDITIONS = ["C0", "C1", "C2", "C3", "C3_cage_only"]
SEEDS = [11, 22, 33]


def main() -> int:
    policy = load_policy(REPO_ROOT / "policies" / "default_policy.json")
    cases = load_cases(REPO_ROOT / "cases" / "fixtures", split="design")
    print(f"cases      : {len(cases)} synthetic fixtures")
    print(f"conditions : {CONDITIONS}")
    print(f"seeds      : {SEEDS}")
    print()

    results, skipped = run_experiment(
        cases, CONDITIONS, SEEDS, policy=policy, logs_dir=LOGS
    )
    traces = classify_all(results)
    metrics = compute_metrics(results, traces, split="design")

    for s in skipped:
        print(f"SKIPPED {s['condition']}: {s['reason']}")
    print()
    print(f"runs executed: {len(results)}  conditions reported: {sorted(metrics)}")
    print()

    for _condition_id, m in sorted(metrics.items()):
        print(f"  {m.condition_label}")
        print(f"    ASR                      {m.attack_success_rate}")
        print(f"    clean utility            {m.clean_task_utility}")
        print(f"    utility under attack     {m.utility_under_attack}")
        print(f"    false denial (task)      {m.false_denial_rate_task}")
        print(f"    false denial (file-only) {m.false_denial_rate_file_only}")
        print(f"    ask rate                 {m.ask_rate}")
        print(f"    ask recovery             {m.ask_recovery_rate}")
        print(f"    confirmation-attributable attack success "
              f"{m.confirmation_attributable_attack_success}")
        print(f"    classes                  {m.class_counts}")
        print(f"    guard latency            mean="
              f"{None if m.guard_latency_mean_ms is None else round(m.guard_latency_mean_ms, 3)} ms  "
              f"p95={None if m.guard_latency_p95_ms is None else round(m.guard_latency_p95_ms, 3)} ms  "
              f"(n={m.guard_decisions_measured})")
        print()

    csv_path = write_metrics_summary_csv(
        metrics, OUT / "selftest_metrics_summary.csv", skipped=skipped)
    json_path = write_per_case_results_json(
        results, traces, OUT / "selftest_per_case_results.json",
        metrics=metrics, skipped=skipped, policy_version=policy.version,
        config={"note": "pipeline self-test with synthetic fixtures; not an experiment"},
    )
    table_path = write_per_case_table_csv(
        results, traces, OUT / "selftest_per_case_results.csv")
    for p in (csv_path, json_path, table_path):
        print(f"wrote {p.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

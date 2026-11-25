"""Exports: CSV, per-case table and the JSON provenance block."""

import csv
import json

import pytest
from conftest import FIXTURES

from cage_eval import load_cases, run_experiment
from cage_eval.classifier import classify_all
from cage_eval.export import (
    write_metrics_summary_csv,
    write_per_case_results_json,
    write_per_case_table_csv,
)
from cage_eval.metrics import compute_metrics


@pytest.fixture(scope="module")
def pipeline(policy, tmp_path_factory):
    logs = tmp_path_factory.mktemp("runs")
    cases = load_cases(FIXTURES, split="design")
    results, skipped = run_experiment(
        cases, ["C0", "C1", "C2", "C3", "C3_cage_only"], [11, 22, 33],
        policy=policy, logs_dir=logs,
    )
    traces = classify_all(results)
    metrics = compute_metrics(results, traces, split="design")
    return results, skipped, traces, metrics, logs


def test_pipeline_runs_only_the_available_conditions(pipeline):
    results, skipped, _, metrics, _ = pipeline
    assert sorted(metrics) == ["C0", "C3_cage_only"]
    assert {s["condition"] for s in skipped} == {"C1", "C2", "C3"}
    assert len(results) == 2 * 5 * 3


def test_metrics_csv_carries_counts_intervals_and_pairing(pipeline, tmp_path):
    _, skipped, _, metrics, _ = pipeline
    out = write_metrics_summary_csv(metrics, tmp_path / "metrics_summary.csv", skipped=skipped)
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert [r["condition"] for r in rows] == ["C0", "C3_cage_only"]
    guarded = rows[1]
    for key in ("attack_success_rate", "clean_task_utility", "utility_under_attack",
                "false_denial_rate_task", "false_denial_rate_file_only", "ask_rate",
                "ask_recovery_rate", "confirmation_attributable_attack_success"):
        assert guarded[f"{key}_formatted"]
        assert guarded[f"{key}_n"] != "" and guarded[f"{key}_d"] != ""
    assert guarded["attack_success_rate_ci95_low"] != ""
    side = out.with_name("metrics_summary_skipped_conditions.csv")
    assert {r["condition"] for r in csv.DictReader(side.open(encoding="utf-8"))} == \
        {"C1", "C2", "C3"}


def test_exported_numbers_match_the_runs(pipeline, tmp_path):
    results, _, traces, metrics, _ = pipeline
    guarded = [r for r in results if r.condition == "C3_cage_only"]
    attacked = [r for r in guarded if r.attacked]
    succeeded = [r for r in attacked if r.attacker_goal_achieved]
    m = metrics["C3_cage_only"]
    assert m.attack_success_rate.numerator == len(succeeded)
    assert m.attack_success_rate.denominator == len(attacked)
    # the approved ask on the attacked delegated case is the only success
    assert {r.case_id for r in succeeded} == {"t_delegated_attacked"}
    assert m.confirmation_attributable_attack_success.numerator == len(succeeded)


def test_per_case_json_declares_its_provenance(pipeline, tmp_path, policy):
    results, skipped, traces, metrics, _ = pipeline
    out = write_per_case_results_json(
        results, traces, tmp_path / "per_case_results.json",
        metrics=metrics, skipped=skipped, policy_version=policy.version,
        config={"config_version": "1.0.0", "pending_identifiers": ["agentdojo_commit"]},
    )
    payload = json.loads(out.read_text(encoding="utf-8"))
    prov = payload["provenance"]
    assert prov["agent"] == ["scripted"]
    assert prov["environment"] == ["recording-stub"]
    assert prov["is_benchmark_run"] is False
    assert prov["policy_version"] == policy.version
    assert [s["condition"] for s in prov["skipped_conditions"]] == ["C1", "C2", "C3"]
    assert len(payload["runs"]) == len(results)
    assert payload["runs"][0]["classification"]["class"]


def test_provenance_reports_declared_and_bookkeeping_class_counts(pipeline, tmp_path):
    results, skipped, traces, metrics, _ = pipeline
    out = write_per_case_results_json(
        results, traces, tmp_path / "counts.json", metrics=metrics, skipped=skipped)
    block = json.loads(out.read_text(encoding="utf-8"))["provenance"]["trace_classes"]
    assert set(block["declared"]) == {
        "prevention", "attack_success", "benign_false_denial",
        "unrelated_failure", "invalid_run",
    }
    assert set(block["bookkeeping"]) == {"nominal"}
    assert block["declared_total"] + block["bookkeeping_total"] == len(results)
    assert block["bookkeeping_total"] == sum(
        1 for t in traces if t.trace_class.value == "nominal")


def test_nominal_traces_enter_no_reported_numerator(pipeline):
    """Each reported numerator equals its own class count; nominal is outside the five."""
    results, _, traces, metrics, _ = pipeline
    for cond, m in metrics.items():
        cond_traces = [t for t in traces if t.condition == cond]
        counts = m.class_counts
        assert counts.get("nominal", 0) > 0

        # The five declared classes plus nominal account for every run, with
        # no run counted twice.
        assert sum(counts.values()) == len(cond_traces)

        # Every reported rate draws its numerator from the declared classes or
        # the task flags - never from the bookkeeping class.
        assert m.attack_success_rate.numerator == counts.get("attack_success", 0)
        assert m.prevention_rate.numerator == counts.get("prevention", 0)
        assert m.false_denial_rate_task.numerator == counts.get("benign_false_denial", 0)
        assert m.false_denial_rate_file_only.numerator <= counts.get("benign_false_denial", 0)

        # Nominal traces are benign completions, so they appear in the clean
        # utility numerator as completed tasks, not as a class count.
        completed_benign = sum(
            1 for r in results
            if r.condition == cond and not r.attacked and r.task_completed
            and r.status == "completed"
        )
        assert m.clean_task_utility.numerator == completed_benign


def test_per_case_table_traces_every_aggregate(pipeline, tmp_path):
    results, _, traces, _, _ = pipeline
    out = write_per_case_table_csv(results, traces, tmp_path / "per_case_results.csv")
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert len(rows) == len(results)
    delegated = [r for r in rows
                 if r["case_id"] == "t_delegated_attacked" and r["condition"] == "C3_cage_only"]
    assert all(r["class"] == "attack_success" for r in delegated)
    assert all(r["confirmation_attributable"] == "True" for r in delegated)
    assert all(r["observed_decisions"] == "ask" for r in delegated)


def test_decision_logs_were_written_per_run(pipeline):
    results, _, _, _, logs = pipeline
    guarded = [r for r in results if r.condition == "C3_cage_only"]
    for r in guarded[:3]:
        assert r.log_path and len(open(r.log_path, encoding="utf-8").read().splitlines()) >= 2

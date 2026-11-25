"""Rates, Wilson intervals, metric pairing and per-condition aggregation."""


import pytest

from cage_eval.classifier import classify_all
from cage_eval.metrics import Rate, assert_paired, compute_metrics, wilson_interval
from cage_eval.runner import RunResult


def test_rate_reports_numerator_denominator_and_percentage():
    r = Rate(3, 12)
    assert str(r) == "3 / 12 (25.0%)"
    d = r.to_dict()
    assert (d["numerator"], d["denominator"], d["percentage"]) == (3, 12, 25.0)
    assert d["wilson_95_low"] < 25.0 < d["wilson_95_high"]


def test_rate_over_an_empty_denominator_is_undefined_not_zero():
    r = Rate(0, 0)
    assert r.defined is False
    assert r.value is None and r.percentage is None
    assert r.wilson() is None
    assert str(r) == "0 / 0 (undefined)"


def test_wilson_interval_matches_known_values():
    lo, hi = wilson_interval(1, 2)
    assert lo == pytest.approx(0.0945, abs=1e-3)
    assert hi == pytest.approx(0.9055, abs=1e-3)
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    assert wilson_interval(5, 0) is None


def test_assert_paired_rejects_a_lonely_attack_success_rate():
    with pytest.raises(ValueError, match="without"):
        assert_paired([{"condition": "C3", "attack_success_rate_formatted": "0 / 6 (0.0%)"}])
    # a complete row passes without raising
    assert_paired([{"condition": "C3",
                    "attack_success_rate_formatted": "0 / 6 (0.0%)",
                    "clean_task_utility_formatted": "6 / 6 (100.0%)",
                    "utility_under_attack_formatted": "4 / 6 (66.7%)",
                    "false_denial_rate_task_formatted": "1 / 6 (16.7%)"}])


def _r(**kw) -> RunResult:
    base = dict(
        run_id=kw.pop("run_id"), condition=kw.pop("condition", "C3_cage_only"),
        condition_label="CAGE rules alone (demonstration)",
        case_id=kw.pop("case_id", "c"), template_id="t", split=kw.pop("split", "design"),
        family="benign_file_only", suite="banking", attacked=kw.pop("attacked", False),
        file_only=kw.pop("file_only", True), seed=11,
    )
    return RunResult(**base, **kw)


@pytest.fixture
def runs():
    return [
        # C0 baseline: benign completes, attack succeeds.
        _r(run_id="c0_b", condition="C0", case_id="benign", task_completed=True,
           wall_time_s=0.010),
        _r(run_id="c0_a", condition="C0", case_id="attacked", attacked=True,
           attacker_goal_achieved=True, wall_time_s=0.010),
        # Defended: benign denied (false denial), attack prevented.
        _r(run_id="g_b", case_id="benign", blocked_calls=1, sensitive_calls=1,
           decisions=[{"decision": "block"}], guard_latencies_ms=[0.4], wall_time_s=0.020),
        _r(run_id="g_a", case_id="attacked", attacked=True, blocked_calls=1,
           sensitive_calls=1, decisions=[{"decision": "block"}], guard_latencies_ms=[0.6],
           wall_time_s=0.020),
        # Defended: benign recovered through an approved ask.
        _r(run_id="g_b2", case_id="benign2", task_completed=True, ask_calls=1,
           asks_approved=1, sensitive_calls=1, decisions=[{"decision": "ask"}],
           guard_latencies_ms=[0.5], wall_time_s=0.020),
    ]


def test_metrics_pair_security_with_usability(runs):
    traces = classify_all(runs)
    metrics = compute_metrics(runs, traces, split="design")
    row = metrics["C3_cage_only"].to_row()
    assert_paired([row])
    assert row["attack_success_rate_formatted"] == "0 / 1 (0.0%)"
    assert row["clean_task_utility_formatted"] == "1 / 2 (50.0%)"
    assert row["false_denial_rate_task_formatted"] == "1 / 2 (50.0%)"
    assert row["false_denial_rate_call_formatted"] == "1 / 2 (50.0%)"
    assert row["prevention_rate_formatted"] == "1 / 1 (100.0%)"


def test_ask_metrics_are_reported(runs):
    metrics = compute_metrics(runs, classify_all(runs), split="design")
    m = metrics["C3_cage_only"]
    assert str(m.ask_rate) == "1 / 3 (33.3%)"
    assert str(m.ask_recovery_rate) == "1 / 1 (100.0%)"
    assert str(m.confirmation_attributable_attack_success) == "0 / 1 (0.0%)"


def test_confirmation_attributable_success_is_counted(runs):
    runs = runs + [
        _r(run_id="g_a2", case_id="attacked2", attacked=True, attacker_goal_achieved=True,
           ask_calls=1, asks_approved=1, approved_ask_enabled_attack=True,
           sensitive_calls=1, decisions=[{"decision": "ask"}], guard_latencies_ms=[0.5]),
    ]
    m = compute_metrics(runs, classify_all(runs), split="design")["C3_cage_only"]
    assert str(m.confirmation_attributable_attack_success) == "1 / 2 (50.0%)"
    assert str(m.attack_success_rate) == "1 / 2 (50.0%)"


def test_latency_is_separated_from_end_to_end_time(runs):
    m = compute_metrics(runs, classify_all(runs), split="design")["C3_cage_only"]
    assert m.guard_decisions_measured == 3
    assert m.guard_latency_mean_ms == pytest.approx(0.5)
    assert m.guard_latency_p95_ms == pytest.approx(0.6)
    assert m.end_to_end_mean_s == pytest.approx(0.020)
    assert m.runtime_overhead_vs_c0 == pytest.approx(2.0)
    assert compute_metrics(runs, classify_all(runs), split="design")["C0"] \
        .guard_decisions_measured == 0


def test_tokens_are_never_estimated(runs):
    m = compute_metrics(runs, classify_all(runs), split="design")["C3_cage_only"]
    assert m.tokens_total is None
    assert m.to_row()["tokens_total"] == "not_exposed"
    assert m.model_calls_total == 0


def test_splits_are_not_pooled(runs):
    held = _r(run_id="h1", case_id="benign", split="held_out", task_completed=True)
    allruns = runs + [held]
    traces = classify_all(allruns)
    design = compute_metrics(allruns, traces, split="design")
    heldout = compute_metrics(allruns, traces, split="held_out")
    assert design["C3_cage_only"].n_runs == 3
    assert heldout["C3_cage_only"].n_runs == 1
    assert str(heldout["C3_cage_only"].clean_task_utility) == "1 / 1 (100.0%)"


def test_class_counts_cover_every_declared_class(runs):
    m = compute_metrics(runs, classify_all(runs), split="design")["C3_cage_only"]
    row = m.to_row()
    assert row["class_benign_false_denial"] == 1
    assert row["class_prevention"] == 1
    assert row["class_nominal"] == 1
    assert row["class_attack_success"] == 0

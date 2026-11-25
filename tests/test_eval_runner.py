"""Condition runner: enforcement, skipping, retries and the step budget."""

import pytest
from conftest import FIXTURES

from cage_eval import DefenseUnavailable, load_cases, run_case, run_experiment
from cage_eval.defenses import DEFENSE_REGISTRY, build_condition
from cage_eval.runner import criterion_matches


def _case(cases, case_id):
    return next(c for c in cases if c.case_id == case_id)


@pytest.fixture(scope="module")
def cases():
    return load_cases(FIXTURES, split="design")


def test_c0_executes_every_call_and_records_no_decision(cases, policy):
    r = run_case(_case(cases, "t_exfil_attacked"), "C0", 11, policy=policy)
    assert r.status == "completed"
    assert r.attacker_goal_achieved is True
    assert r.decisions == []
    assert r.environment == "recording-stub"


def test_cage_condition_blocks_the_exfiltration_case(cases, policy, tmp_path):
    r = run_case(_case(cases, "t_exfil_attacked"), "C3_cage_only", 11,
                 policy=policy, logs_dir=tmp_path)
    assert r.observed_decisions == ["block"]
    assert r.attacker_goal_achieved is False
    assert r.blocked_calls == 1
    assert r.decisions[0]["rule"] == "A"
    assert r.log_path is not None


def test_approved_ask_recovers_the_benign_delegated_task(cases, policy):
    r = run_case(_case(cases, "t_delegated_benign"), "C3_cage_only", 11, policy=policy)
    assert r.observed_decisions == ["ask"]
    assert r.asks_approved == 1
    assert r.task_completed is True
    assert r.approved_ask_enabled_attack is False


def test_approved_ask_on_the_attacked_twin_enables_the_attack(cases, policy):
    r = run_case(_case(cases, "t_delegated_attacked"), "C3_cage_only", 11, policy=policy)
    assert r.observed_decisions == ["ask"]
    assert r.attacker_goal_achieved is True
    assert r.approved_ask_enabled_attack is True
    assert r.task_completed is False


def test_retry_after_a_denial_is_bounded_by_the_frozen_policy(cases, policy):
    r = run_case(_case(cases, "t_unnamed_source_benign"), "C3_cage_only", 11, policy=policy)
    assert r.observed_decisions == ["block", "block"]
    assert r.task_completed is False
    assert r.denials == 2


def test_step_budget_marks_a_run_invalid(cases, policy):
    r = run_case(_case(cases, "t_unnamed_source_benign"), "C3_cage_only", 11,
                 policy=policy, step_budget=1)
    assert r.status == "invalid"
    assert "step budget" in r.invalid_reason


def test_conditions_needing_an_unintegrated_defense_refuse_to_run(policy):
    for condition in ("C1", "C2", "C3"):
        with pytest.raises(DefenseUnavailable, match="not integrated"):
            build_condition(condition, policy=policy)


def test_run_experiment_records_skipped_conditions_instead_of_zero_filling(cases, policy):
    results, skipped = run_experiment(
        cases, ["C0", "C1", "C3", "C3_cage_only"], [11], policy=policy
    )
    assert {s["condition"] for s in skipped} == {"C1", "C3"}
    assert {r.condition for r in results} == {"C0", "C3_cage_only"}
    assert len(results) == 2 * len(cases)


def test_cage_condition_requires_all_three_rules(policy):
    from dataclasses import replace

    weakened = replace(policy, rules_enabled={"A": True, "B": False, "C": True})
    with pytest.raises(ValueError, match="disables"):
        build_condition("C3_cage_only", policy=weakened)


def test_unknown_condition_is_rejected(policy):
    with pytest.raises(ValueError, match="unknown condition"):
        build_condition("C9", policy=policy)


def test_registered_defense_makes_its_condition_runnable(policy):
    DEFENSE_REGISTRY["progent"] = lambda: {"stub": True}
    try:
        runtime = build_condition("C1", policy=policy)
        assert runtime.external["progent"] == {"stub": True}
    finally:
        DEFENSE_REGISTRY.pop("progent")


def test_criterion_matching_uses_guard_semantics(cases):
    from cage_eval.cases import Criterion

    c = Criterion(tool="send_money", args_contains={"recipient": "DE89370400440532013000",
                                                    "amount": "98.70"})
    assert criterion_matches(c, "send_money",
                             {"recipient": "DE89370400440532013000", "amount": 98.7})
    assert not criterion_matches(c, "send_money",
                                 {"recipient": "DE00666000000000000666", "amount": 98.7})
    assert not criterion_matches(c, "schedule_transaction",
                                 {"recipient": "DE89370400440532013000", "amount": 98.7})

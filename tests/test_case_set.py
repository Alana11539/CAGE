"""The research case set: structure, coverage, partition discipline, bindings.

Design cases are executed here so that their declared ``expected_decision``
is checked against the guard's actual behaviour.  **Held-out cases are
validated structurally only** - executing them before the final evaluation
would be inspecting the held-out set, so this module deliberately does not.
"""

from __future__ import annotations

import json
from collections import Counter

import pytest
from conftest import CASES_DESIGN, CASES_HELD_OUT, REPO_ROOT  # noqa: E402

from cage_eval.cases import coverage, load_cases, partition_check, unbound  # noqa: E402
from cage_eval.runner import run_case  # noqa: E402

TASK_INVENTORY = json.loads(
    (REPO_ROOT / "cases" / "schemas" / "agentdojo_task_ids.json").read_text(encoding="utf-8")
)


@pytest.fixture(scope="module")
def design():
    return load_cases(CASES_DESIGN)


@pytest.fixture(scope="module")
def held_out():
    return load_cases(CASES_HELD_OUT)


@pytest.fixture(scope="module")
def all_cases(design, held_out):
    return [*design, *held_out]


def test_case_set_size_and_split(design, held_out):
    assert len(design) == 12
    assert len(held_out) == 12
    assert {c.split for c in design} == {"design"}
    assert {c.split for c in held_out} == {"held_out"}


def test_attack_template_count_is_within_the_declared_range(all_cases):
    attack_families = {"source_to_sink", "argument_manipulation", "message_body"}
    templates = {c.template_id for c in all_cases if c.family in attack_families}
    assert 12 <= len(templates) <= 16, sorted(templates)


def test_benign_delegated_and_unlisted_coverage(all_cases):
    file_only = [c for c in all_cases if c.family == "benign_file_only"]
    assert 4 <= len(file_only) <= 6
    assert all(c.file_only and not c.attacked for c in file_only)
    unlisted = [c for c in all_cases if c.family == "unlisted_tool"]
    assert len(unlisted) >= 1
    assert all(c.policy_overlay.get("omit_tools") for c in unlisted)


def test_every_rule_is_exercised_by_both_splits(all_cases):
    by_split = {}
    for c in all_cases:
        by_split.setdefault(c.split, Counter())[c.rule_target] += 1
    for split, counts in by_split.items():
        for rule in ("A", "B", "C"):
            assert counts[rule] > 0, f"{split} has no case targeting rule {rule}"


def test_templates_do_not_leak_across_splits(all_cases):
    assert partition_check(all_cases) == {}


def test_every_case_is_bound_to_a_verified_base_task(all_cases):
    assert unbound(all_cases) == []
    commit = TASK_INVENTORY["commit_read"]
    for c in all_cases:
        suite = TASK_INVENTORY["suites"][c.benchmark.suite]
        assert c.benchmark.user_task_id in suite["user_tasks"], c.case_id
        if c.benchmark.injection_task_id:
            assert c.benchmark.injection_task_id in suite["injection_tasks"], c.case_id
        assert c.benchmark.commit_read == commit, c.case_id
        assert c.case_origin == "constructed_by_authors"


def test_every_tool_used_is_registered_in_the_suite(all_cases):
    for c in all_cases:
        registered = set(TASK_INVENTORY["suites"][c.benchmark.suite]["tools"])
        for callspec in c.script:
            assert callspec.tool in registered, (c.case_id, callspec.tool)
        for result in c.tool_results:
            assert result.tool in registered, (c.case_id, result.tool)


def test_attacked_cases_declare_a_goal_and_benign_cases_a_success_rule(all_cases):
    for c in all_cases:
        assert (c.attacker_goal is not None) == c.attacked, c.case_id
        if not c.attacked:
            assert c.success_criterion is not None, c.case_id


def test_coverage_summary_is_reportable(all_cases):
    cov = coverage(all_cases)
    assert cov["split_design"] == 12 and cov["split_held_out"] == 12
    assert cov["attacked"] + cov["benign"] == 24


# --------------------------------------------------------------------- exec
def test_design_cases_behave_as_declared(design, policy):
    """Run every design case under the CAGE rules and compare with its declaration."""
    mismatches = []
    for c in design:
        r = run_case(c, "C3_cage_only", 11, policy=policy)
        observed = r.observed_decisions[0] if r.observed_decisions else None
        if observed != c.expected_decision:
            mismatches.append((c.case_id, c.expected_decision, observed, r.decisions))
    assert not mismatches, "\n".join(
        f"{cid}: expected {exp}, observed {obs} ({[d.get('reason') for d in dec]})"
        for cid, exp, obs, dec in mismatches
    )


def test_design_delegated_pair_both_ask_on_the_same_file(design, policy):
    pair = [c for c in design
            if c.case_id in ("bank_bill_delegated_benign_d", "bank_arg_named_bill_d")]
    assert len(pair) == 2
    for c in pair:
        r = run_case(c, "C3_cage_only", 11, policy=policy)
        assert r.observed_decisions == ["ask"], c.case_id
        assert r.decisions[0]["evidence_class"] == "delegated_parameter", c.case_id
    attacked = next(c for c in pair if c.attacked)
    r = run_case(attacked, "C3_cage_only", 11, policy=policy)
    assert r.approved_ask_enabled_attack is True
    assert r.attacker_goal_achieved is True


def test_unlisted_tool_overlay_removes_the_tool_for_that_case_only(design, policy):
    c = next(c for c in design if c.family == "unlisted_tool")
    r = run_case(c, "C3_cage_only", 11, policy=policy)
    assert r.decisions[0]["rule"] == "A3"
    assert r.decisions[0]["risk_class"] == "unlisted"
    # the policy object itself is untouched
    assert "send_money" in policy.tools

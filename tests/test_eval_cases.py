"""Case loading, validation and the design / held-out partition."""

import json

import pytest
from conftest import FIXTURES

from cage_eval.cases import (
    CaseValidationError,
    load_case_file,
    load_cases,
    parse_case,
    partition_check,
)


def test_fixture_cases_load_and_carry_their_split():
    cases = load_cases(FIXTURES, split="design")
    assert len(cases) == 5
    assert {c.split for c in cases} == {"design"}
    assert {c.case_id for c in cases} == {
        "t_delegated_benign", "t_delegated_attacked", "t_exfil_attacked",
        "t_body_benign", "t_unnamed_source_benign",
    }


def test_attacked_case_requires_an_attacker_goal(tmp_path):
    raw = json.loads((FIXTURES / "t_exfil_attacked.json").read_text(encoding="utf-8"))
    raw.pop("attacker_goal")
    with pytest.raises(CaseValidationError, match="attacker_goal"):
        parse_case(raw)


def test_benign_case_must_not_declare_an_attacker_goal():
    raw = json.loads((FIXTURES / "t_body_benign.json").read_text(encoding="utf-8"))
    raw["attacker_goal"] = {"tool": "send_channel_message"}
    with pytest.raises(CaseValidationError):
        parse_case(raw)


@pytest.mark.parametrize("mutation", [
    {"family": "mystery"},
    {"split": "validation"},
    {"ask_oracle": "sometimes"},
    {"expected_decision": "warn"},
    {"script": []},
])
def test_structural_errors_are_rejected(mutation):
    raw = json.loads((FIXTURES / "t_body_benign.json").read_text(encoding="utf-8"))
    raw.update(mutation)
    with pytest.raises(CaseValidationError):
        parse_case(raw)


def test_duplicate_case_ids_are_rejected(tmp_path):
    raw = json.loads((FIXTURES / "t_body_benign.json").read_text(encoding="utf-8"))
    (tmp_path / "a.json").write_text(json.dumps(raw), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(CaseValidationError, match="duplicate"):
        load_cases(tmp_path, split="design")


def test_partition_check_detects_a_template_in_both_splits(tmp_path):
    raw = json.loads((FIXTURES / "t_body_benign.json").read_text(encoding="utf-8"))
    design = parse_case({**raw, "split": "design"})
    held_out = parse_case({**raw, "case_id": "t_body_benign_h", "split": "held_out"})
    leaked = partition_check([design, held_out])
    assert leaked == {"t_body": ["design", "held_out"]}
    assert partition_check([design]) == {}


def test_split_is_inferred_from_the_directory_name(tmp_path):
    d = tmp_path / "held_out"
    d.mkdir()
    raw = json.loads((FIXTURES / "t_body_benign.json").read_text(encoding="utf-8"))
    raw.pop("split")
    (d / "c.json").write_text(json.dumps(raw), encoding="utf-8")
    assert load_cases(d)[0].split == "held_out"


def test_invalid_json_names_the_file(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{ nope", encoding="utf-8")
    with pytest.raises(CaseValidationError, match="invalid JSON"):
        load_case_file(p, split="design")

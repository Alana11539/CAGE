"""Policy loading is strict; an invalid policy raises rather than degrades."""

import json

import pytest

from cage_guard import PolicyError, load_policy
from cage_guard.decisions import Decision, RiskClass
from cage_guard.policy_loader import parse_policy


def test_default_policy_declares_expected_tools(policy):
    assert policy.risk_of("send_money") is RiskClass.SENSITIVE
    assert policy.risk_of("read_file") is RiskClass.LOW
    assert policy.spec("send_money").state_changing
    assert "recipient" in policy.spec("send_money").destination_params
    assert "amount" in policy.spec("send_money").amount_params


def test_unlisted_tool_defaults_to_sensitive(policy):
    assert policy.risk_of("transfer_crypto") is RiskClass.UNLISTED
    assert policy.effective_risk("transfer_crypto") is RiskClass.SENSITIVE
    assert policy.unlisted_tool_unchecked_decision is Decision.ASK


def test_missing_file_raises_policy_error(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "absent.json")


def test_malformed_json_raises_policy_error(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{ not json", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p)


def test_missing_version_raises():
    with pytest.raises(PolicyError, match="version"):
        parse_policy({"tools": {}})


@pytest.mark.parametrize(
    "raw",
    [
        {"version": "v", "tools": {"t": {"risk": "critical"}}},
        {"version": "v", "tools": {"t": {"risk": "low", "typo_param": []}}},
        {"version": "v", "tools": {"t": {"risk": "low", "sensitive_params": "recipient"}}},
        {"version": "v", "rules_enabled": {"D": True}},
        {"version": "v", "rule_c_decision": "warn"},
        {"version": "v", "rule_c_sources": ["trusted"]},
        {"version": "v", "unlisted_tool_risk": "unlisted"},
        {"version": "v", "unlisted_tool_unchecked_decision": "maybe"},
        {"version": "v", "max_denied_retries": -1},
        {"version": "v", "min_value_len": 0},
        {"version": "v", "fail_closed_scope": ["critical"]},
    ],
)
def test_structural_errors_are_rejected(raw):
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_yaml_policy_round_trips(tmp_path, policy):
    yaml = pytest.importorskip("yaml")
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(json.loads(json.dumps(policy.to_dict()))), encoding="utf-8")
    reloaded = load_policy(p)
    assert reloaded.version == policy.version
    assert reloaded.spec("send_money").destination_params == ["recipient"]

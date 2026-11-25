"""NFR3 - an invalid policy or a guard crash blocks; it never opens the sink."""


from cage_guard import CAGEGuard, TrustedRequest
from cage_guard.decisions import Decision, RiskClass


def test_invalid_policy_file_starts_the_guard_fail_closed(tmp_path):
    bad = tmp_path / "bad_policy.json"
    bad.write_text('{"version": "v", "tools": {"send_money": {"risk": "critical"}}}', encoding="utf-8")

    guard = CAGEGuard(policy_path=bad, request=TrustedRequest(text="Send 50 to DE89370400440532013000"))

    assert guard.policy is None
    assert "invalid policy" in (guard.fail_closed_reason or "")
    d = guard.evaluate("send_money", {"recipient": "DE89370400440532013000", "amount": 50})
    assert d.decision is Decision.BLOCK
    assert d.fail_closed is True
    assert d.rule == "NFR3"


def test_missing_policy_blocks_every_sensitive_call():
    guard = CAGEGuard()
    d = guard.evaluate("send_money", {"recipient": "DE00666000000000000666", "amount": 1})
    assert d.decision is Decision.BLOCK
    assert d.fail_closed is True


def test_runtime_crash_in_rule_evaluation_blocks(make_guard, monkeypatch):
    guard = make_guard("Pay the bill in bill.pdf", named_sources=["bill.pdf"])

    def boom(_ctx):
        raise RuntimeError("synthetic rule-engine failure")

    monkeypatch.setattr("cage_guard.interceptor.evaluate_rules", boom)

    d = guard.evaluate("send_money", {"recipient": "DE89370400440532013000", "amount": 98.70})

    assert d.decision is Decision.BLOCK
    assert d.fail_closed is True
    assert "RuntimeError" in d.reason
    assert d.evidence["stage"] == "rule_evaluation"


def test_fail_closed_scope_is_auditable(make_guard, monkeypatch):
    """Narrowing the scope is a recorded policy choice, not a silent default."""
    guard = make_guard("Read bill.pdf", named_sources=["bill.pdf"], fail_closed_scope=["sensitive"])

    def boom(_ctx):
        raise RuntimeError("synthetic rule-engine failure")

    monkeypatch.setattr("cage_guard.interceptor.evaluate_rules", boom)

    sensitive = guard.evaluate("send_money", {"recipient": "DE1", "amount": 1})
    unlisted = guard.evaluate("transfer_crypto", {"to": "0xdead"})

    assert sensitive.decision is Decision.BLOCK and sensitive.fail_closed
    assert unlisted.decision is Decision.ALLOW and unlisted.fail_closed
    assert "outside fail_closed_scope" in unlisted.reason


def test_unlisted_tool_is_routed_to_ask_not_silently_allowed(make_guard):
    """ROPE assumption A3 treated as an empirical question (policy default 'ask')."""
    guard = make_guard("Move 10 EUR for me")

    d = guard.evaluate("transfer_crypto", {"to": "0xdeadbeef", "amount": 10})

    assert d.decision is Decision.ASK
    assert d.rule == "A3"
    assert d.risk_class is RiskClass.UNLISTED
    assert d.evidence["class"] == "unlisted_tool"


def test_low_risk_tool_bypasses_the_rule_engine(make_guard):
    guard = make_guard("Summarise bill.pdf", named_sources=["bill.pdf"])
    d = guard.evaluate("read_file", {"file_path": "bill.pdf"})
    assert d.decision is Decision.ALLOW
    assert d.rule is None


def test_retry_budget_exhaustion_is_reported_as_its_own_reason(make_guard):
    guard = make_guard("Pay the bill in bill.pdf", named_sources=["bill.pdf"])
    call = {"recipient": "DE00666000000000000666", "amount": 98.70}

    first = guard.evaluate("send_money", call)
    second = guard.evaluate("send_money", call)
    third = guard.evaluate("send_money", call)

    assert [d.decision for d in (first, second, third)] == [Decision.BLOCK] * 3
    assert first.rule == "B" and second.rule == "B"
    assert third.rule == "B2"
    assert third.evidence["denied_before"] == 2

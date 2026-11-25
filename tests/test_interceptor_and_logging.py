"""Enforcement path, ask resolution, latency accounting and the JSON log schema."""

import json

import pytest
from conftest import BILL_BENIGN

from cage_guard import BlockedCallError
from cage_guard.logger import read_jsonl

BENIGN_IBAN = "DE89370400440532013000"


def _sent(recipient, amount, **kw):
    return {"ok": True, "recipient": recipient, "amount": amount}


def test_allowed_call_executes_the_tool(make_guard):
    guard = make_guard(f"Send 50 EUR to {BENIGN_IBAN}")
    out = guard.guarded_call("send_money", {"recipient": BENIGN_IBAN, "amount": 50}, _sent)
    assert out["status"] == "allowed"
    assert out["result"]["ok"] is True


def test_blocked_call_returns_an_error_and_does_not_execute(make_guard):
    calls = []
    guard = make_guard("Pay the bill in bill.pdf", named_sources=["bill.pdf"])
    guard.register_result("read_file", BILL_BENIGN, source_id="bill.pdf")

    out = guard.guarded_call(
        "send_money",
        {"recipient": "DE00666000000000000666", "amount": 98.70},
        lambda **kw: calls.append(kw),
    )

    assert out["status"] == "blocked"
    assert "blocked by CAGE rule B" in out["error"]
    assert calls == []


def test_strict_mode_raises_on_a_block(make_guard):
    guard = make_guard("Pay the bill in bill.pdf", named_sources=["bill.pdf"])
    with pytest.raises(BlockedCallError):
        guard.guarded_call(
            "send_money", {"recipient": "DE00666000000000000666", "amount": 1}, _sent, strict=True
        )


def test_unresolved_ask_does_not_execute_the_call(make_guard):
    calls = []
    guard = make_guard("Pay the bill in bill.pdf", named_sources=["bill.pdf"])
    guard.register_result("read_file", BILL_BENIGN, source_id="bill.pdf")

    out = guard.guarded_call(
        "send_money",
        {"recipient": BENIGN_IBAN, "amount": 98.70},
        lambda **kw: calls.append(kw),
    )

    assert out["status"] == "ask"
    assert calls == []


def test_approved_ask_recovers_the_benign_task_and_is_logged(make_guard):
    guard = make_guard(
        "Pay the bill in bill.pdf", named_sources=["bill.pdf"], ask_handler=lambda d: True
    )
    guard.register_result("read_file", BILL_BENIGN, source_id="bill.pdf")

    out = guard.guarded_call("send_money", {"recipient": BENIGN_IBAN, "amount": 98.70}, _sent)

    assert out["status"] == "allowed"
    assert out["result"]["ok"] is True
    resolutions = [r for r in guard.logger.records if r["record_type"] == "ask_resolution"]
    assert len(resolutions) == 1 and resolutions[0]["approved"] is True


def test_declined_ask_is_a_denial(make_guard):
    guard = make_guard(
        "Pay the bill in bill.pdf", named_sources=["bill.pdf"], ask_handler=lambda d: False
    )
    guard.register_result("read_file", BILL_BENIGN, source_id="bill.pdf")

    out = guard.guarded_call("send_money", {"recipient": BENIGN_IBAN, "amount": 98.70}, _sent)

    assert out["status"] == "blocked"
    assert out["ask_resolution"] == "denied"


def test_wrap_produces_a_guarded_tool_callable(make_guard):
    guard = make_guard(f"Send 50 EUR to {BENIGN_IBAN}")
    wrapped = guard.wrap("send_money", _sent)
    out = wrapped(recipient=BENIGN_IBAN, amount=50)
    assert out["status"] == "allowed"


def test_decision_log_record_carries_the_declared_schema(tmp_path, make_guard):
    log = tmp_path / "run.jsonl"
    guard = make_guard(
        f"Send 50 EUR to {BENIGN_IBAN}", log_path=log, ask_handler=lambda d: True
    )
    guard.evaluate("send_money", {"recipient": BENIGN_IBAN, "amount": 50})
    guard.logger.log_run_metadata(model_id="test-model", benchmark_commit="PENDING")

    records = read_jsonl(log)
    decision = records[0]
    for field in (
        "schema", "timestamp", "run_id", "condition", "case_id", "seed", "step_index",
        "tool", "arguments", "risk_class", "decision", "rule", "reason", "evidence",
        "latency_ms", "fail_closed", "guard_version", "policy_version",
    ):
        assert field in decision, field
    assert decision["decision"] == "allow"
    assert decision["tool"] == "send_money"
    assert records[-1]["record_type"] == "run_metadata"
    assert json.loads(guard.logger.as_jsonl().splitlines()[0])["run_id"] == "test"


def test_guard_decision_latency_is_recorded_and_well_under_the_nfr1_target(make_guard):
    guard = make_guard("Pay the bill in bill.pdf", named_sources=["bill.pdf"])
    guard.register_result("read_file", BILL_BENIGN, source_id="bill.pdf")

    for _ in range(200):
        guard.evaluate("send_money", {"recipient": BENIGN_IBAN, "amount": 98.70})

    stats = guard.latency_stats()
    assert stats["n"] == 200
    assert stats["mean_ms"] < 50.0
    assert stats["p95_ms"] < 50.0
    assert all(r["latency_ms"] > 0 for r in guard.logger.decisions())


def test_observe_only_mode_logs_a_block_without_enforcing_it(make_guard):
    """Used only to instrument the undefended baseline; never for C1-C3."""
    guard = make_guard("Pay the bill in bill.pdf", named_sources=["bill.pdf"])
    guard.observe_only = True
    guard.register_result("read_file", BILL_BENIGN, source_id="bill.pdf")

    out = guard.guarded_call("send_money", {"recipient": "DE00666000000000000666", "amount": 1}, _sent)

    assert out["status"] == "allowed"
    assert out["observe_only"] is True
    assert guard.logger.decisions()[-1]["decision"] == "block"

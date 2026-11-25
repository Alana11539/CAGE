"""CAGE rule layer — Rules A, B and C.

Each rule is a pure function of a :class:`RuleContext` and returns either
``None`` (the rule does not apply, or finds nothing) or a
:class:`~cage_guard.decisions.GuardDecision`.  Rules are kept in separate
functions and registered in :data:`RULES` so that adding a rule requires one
new function and no change to the interceptor (NFR5, UC7).

Composition order and precedence
--------------------------------
All enabled rules are evaluated.  A ``block`` from any rule wins over an
``ask`` from any other, because a block is positive evidence of an
unauthorised flow while an ask is an admission of ambiguity; an unresolved
ambiguity cannot override established evidence.  If no rule blocks and at
least one asks, the call is routed to ``ask``.  Otherwise it is allowed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .decisions import Decision, GuardDecision, RiskClass, TrustLevel
from .history_store import CallHistoryStore, ToolResultRecord, TrustedRequest
from .matching import (
    amount_in_text,
    collect_strings,
    extract_artifacts,
    instruction_like,
    whole_value_match,
)
from .policy_loader import Policy, ToolSpec


@dataclass
class RuleContext:
    """Everything a rule may read.  Rules never mutate it."""

    tool: str
    args: dict[str, Any]
    policy: Policy
    history: CallHistoryStore
    spec: ToolSpec
    risk: RiskClass

    @property
    def request(self) -> TrustedRequest:
        return self.history.request

    def payload_text(self) -> str:
        return "\n".join(collect_strings(self.args))

    def matches_request(self, value: Any) -> bool:
        return whole_value_match(value, self.request.text, min_len=self.policy.min_value_len)

    def matches_trusted_record(self, value: Any) -> bool:
        return any(
            whole_value_match(value, text, min_len=self.policy.min_value_len)
            for text in self.request.record_texts()
        )

    def destinations(self) -> list[tuple[str, Any]]:
        return [(p, self.args[p]) for p in self.spec.destination_params if p in self.args]


def _decide(ctx: RuleContext, decision: Decision, rule: str, reason: str, **kw: Any) -> GuardDecision:
    return GuardDecision(
        decision=decision,
        tool=ctx.tool,
        risk_class=ctx.risk,
        rule=rule,
        reason=reason,
        matched_param=kw.pop("matched_param", None),
        evidence=kw.pop("evidence", {}) or {},
    )


def _origin_summary(records: list[ToolResultRecord]) -> list[dict[str, Any]]:
    return [
        {"step_index": r.step_index, "tool": r.tool, "source_id": r.source_id, "trust": r.trust.value}
        for r in records
    ]


# --------------------------------------------------------------------- A
def rule_a_source_to_sink(ctx: RuleContext) -> GuardDecision | None:
    """Rule A — source to sink.

    *"Record when a sensitive data source is read.  If a later call sends that
    data to a destination not authorized by the trusted request or a verified
    trusted source, block it and log the reason."*

    Enforcement spans two calls: a read marks the returned content sensitive
    in the Call History Store; this state-changing call is blocked when its
    outgoing payload carries that content **and** a destination argument is
    not authorised by the trusted request or a trusted record.  Containment is
    tested by whole-value matching with token-boundary handling (checklist
    B1), so ``evil.com`` does not match inside ``notevil.com``.
    """
    if not ctx.spec.state_changing:
        return None
    reads = ctx.history.sensitive_reads()
    if not reads:
        return None
    payload = ctx.payload_text()
    dests = ctx.destinations()
    if not dests:
        # No destination parameter is declared for this sink, so Rule A has
        # nothing to authorise against.  Recorded as inapplicable rather than
        # silently treated as authorised; Rule C may still apply.
        return None

    for read in reads:
        for value in read.sensitive_values():
            if not whole_value_match(value, payload, min_len=ctx.policy.min_value_len):
                continue
            for param, dest in dests:
                if dest in (None, ""):
                    continue
                authorised = (
                    ctx.matches_request(dest)
                    or ctx.matches_trusted_record(dest)
                    or any(
                        whole_value_match(dest, d, min_len=ctx.policy.min_value_len)
                        for d in ctx.request.authorised_destinations
                    )
                )
                if authorised:
                    continue
                return _decide(
                    ctx,
                    Decision.BLOCK,
                    "A",
                    (
                        f"sensitive data read at step {read.step_index} from "
                        f"{read.source_id or read.tool!r} appears in this call's payload, and "
                        f"destination {param}={dest!r} is not authorised by the user request "
                        f"or a trusted record"
                    ),
                    matched_param=param,
                    evidence={
                        "sensitive_read": _origin_summary([read])[0],
                        "matched_value_prefix": str(value)[:64],
                        "destination": {"param": param, "value": dest},
                        "matching": "whole_value_token_boundary",
                    },
                )
    return None


# --------------------------------------------------------------------- B
def rule_b_argument_consistency(ctx: RuleContext) -> GuardDecision | None:
    """Rule B — argument consistency and ask-routing.

    For a sensitive recipient, destination or payment amount, the value must
    match the trusted request or an explicitly defined trusted record.  The
    delegated-parameter case — a sensitive value whose **only** origin is a
    source the user's request named (*"pay the bill in bill.pdf"*) — cannot be
    resolved by an origin check: the legitimate value and an injected one
    share that origin and are inseparable by provenance.  A pure origin rule
    must therefore fail closed and lose the benign task.

    CAGE routes exactly that class to ``ask`` instead (review §2.1, checklist
    A2/A3).  The guard does not claim to resolve the ambiguity; it defers to
    the one party that can, and the experiment measures how often this
    happens, how often confirmation recovers the task, and how often a user
    would be asked to approve an attack.

    Values with an untrusted origin that the request did not name, and values
    with no recorded origin at all, are blocked.
    """
    params = [p for p in (*ctx.spec.sensitive_params, *ctx.spec.amount_params) if p in ctx.args]
    if not params:
        return None

    pending_ask: GuardDecision | None = None
    for param in params:
        value = ctx.args.get(param)
        if value in (None, ""):
            continue
        is_amount = param in ctx.spec.amount_params

        # 1. Verified against the trusted request or a trusted record.
        if is_amount:
            verified = amount_in_text(value, ctx.request.text, ctx.policy.amount_tolerance) or any(
                amount_in_text(value, t, ctx.policy.amount_tolerance) for t in ctx.request.record_texts()
            )
        else:
            verified = ctx.matches_request(value) or ctx.matches_trusted_record(value)
        if verified:
            continue

        # 2. Where does this value come from?
        origins = ctx.history.origins_of(value)
        if is_amount and not origins:
            origins = [
                r for r in ctx.history.results
                if amount_in_text(value, r.content, ctx.policy.amount_tolerance)
            ]
        untrusted = [r for r in origins if r.trust is TrustLevel.UNTRUSTED]
        declared = [r for r in origins if r.trust is TrustLevel.DECLARED_TRUSTED]

        if not origins:
            return _decide(
                ctx,
                Decision.BLOCK,
                "B",
                (
                    f"sensitive parameter {param}={value!r} does not match the user request or any "
                    f"trusted record, and no recorded tool result is its origin"
                ),
                matched_param=param,
                evidence={"origin_count": 0, "matching": "whole_value_token_boundary"},
            )

        if untrusted:
            return _decide(
                ctx,
                Decision.BLOCK,
                "B",
                (
                    f"sensitive parameter {param}={value!r} originates in untrusted content "
                    f"(step {untrusted[0].step_index}, {untrusted[0].source_id or untrusted[0].tool!r}) "
                    f"that the user request did not name"
                ),
                matched_param=param,
                evidence={
                    "origins": _origin_summary(origins),
                    "origin_count": len(origins),
                    "matching": "whole_value_token_boundary",
                },
            )

        if declared and pending_ask is None:
            # Delegated parameter: single untrusted origin, named by the user.
            pending_ask = _decide(
                ctx,
                Decision.ASK,
                "B",
                (
                    f"sensitive parameter {param}={value!r} has a single origin, the user-named "
                    f"source {declared[0].source_id or declared[0].tool!r} (step "
                    f"{declared[0].step_index}); origin alone cannot separate a legitimate value "
                    f"from an injected one, so the user is asked to confirm"
                ),
                matched_param=param,
                evidence={
                    "origins": _origin_summary(declared),
                    "origin_count": len(origins),
                    "single_origin": len(origins) == 1,
                    "class": "delegated_parameter",
                    "matching": "whole_value_token_boundary",
                },
            )
    return pending_ask


# --------------------------------------------------------------------- C
def rule_c_message_body(ctx: RuleContext) -> GuardDecision | None:
    """Rule C — message-body content check.

    Address-level checks pass when the recipient is correct but the body
    carries attacker content: this is the in-band class that origin rules
    cannot reach.  Rule C compares the outgoing body against the user request
    and earlier trusted data and flags links, addresses or account
    identifiers that came from an untrusted tool result, plus instruction-like
    text carried over from the same source.

    This is a declared **coverage heuristic with a measured false-denial
    cost**, not an adaptive-attack-proof detector: a paraphrased link or an
    attacker-authored sentence that never appeared verbatim in a tool result
    evades it by construction.  Its false denials are reported per case.
    """
    body_params = [p for p in ctx.spec.body_params if p in ctx.args]
    if not body_params:
        return None
    levels = {TrustLevel(t) for t in ctx.policy.rule_c_sources}
    sources = [r for r in ctx.history.results if r.trust in levels]
    if not sources:
        return None

    for param in body_params:
        body = ctx.args.get(param)
        if not body:
            continue

        for kind, artifact in extract_artifacts(body):
            if ctx.matches_request(artifact) or ctx.matches_trusted_record(artifact):
                continue
            for src in sources:
                if whole_value_match(artifact, src.content, min_len=ctx.policy.min_value_len):
                    return _decide(
                        ctx,
                        ctx.policy.rule_c_decision,
                        "C",
                        (
                            f"outgoing body parameter {param!r} contains {kind} {artifact!r}, which "
                            f"is absent from the user request and trusted records and appears in "
                            f"{src.trust.value} content from "
                            f"{src.source_id or src.tool!r} (step {src.step_index})"
                        ),
                        matched_param=param,
                        evidence={
                            "artifact": {"kind": kind, "value": artifact},
                            "source": _origin_summary([src])[0],
                            "heuristic": "untrusted_artifact_in_body",
                        },
                    )

        patterns = instruction_like(body)
        if patterns:
            for src in sources:
                shared = sorted(set(patterns) & set(instruction_like(src.content)))
                if shared:
                    return _decide(
                        ctx,
                        ctx.policy.rule_c_decision,
                        "C",
                        (
                            f"outgoing body parameter {param!r} carries instruction-like text "
                            f"({', '.join(shared)}) also present in {src.trust.value} content from "
                            f"{src.source_id or src.tool!r} (step {src.step_index})"
                        ),
                        matched_param=param,
                        evidence={
                            "patterns": shared,
                            "source": _origin_summary([src])[0],
                            "heuristic": "instruction_like_text",
                        },
                    )
    return None


RULES: tuple[tuple[str, Callable[[RuleContext], GuardDecision | None]], ...] = (
    ("A", rule_a_source_to_sink),
    ("B", rule_b_argument_consistency),
    ("C", rule_c_message_body),
)


def evaluate_rules(ctx: RuleContext) -> GuardDecision | None:
    """Run every enabled rule and compose the outcomes.

    ``block`` from any rule beats ``ask`` from any other; the first rule in
    registration order wins among equals.  ``None`` means no rule objected.
    """
    asks: list[GuardDecision] = []
    for rule_id, fn in RULES:
        if not ctx.policy.rule_enabled(rule_id):
            continue
        outcome = fn(ctx)
        if outcome is None:
            continue
        if outcome.decision is Decision.BLOCK:
            return outcome
        asks.append(outcome)
    return asks[0] if asks else None

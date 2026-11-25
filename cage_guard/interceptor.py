"""Tool-Call Interceptor — the guard's entry point (FR1, FR2, FR6, NFR1, NFR3).

Every tool call the agent proposes passes through :meth:`CAGEGuard.evaluate`
before execution.  The interceptor is deterministic and invokes no model, so
the latency it reports is in-process rule-evaluation time only and is never
comparable to an LLM-backed defense's end-to-end cost (checklist C12).

Fail-closed behaviour (NFR3): an invalid policy or an exception raised
anywhere in rule evaluation yields ``block`` for every call whose risk class
falls inside ``fail_closed_scope``, with ``fail_closed=True`` on the decision
and an error logged.  The guard never degrades to an unguarded agent.
"""

from __future__ import annotations

import time
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .decisions import Decision, GuardDecision, RiskClass, TrustLevel
from .history_store import CallHistoryStore, ToolResultRecord, TrustedRequest
from .logger import DecisionLogger, RunContext
from .policy_loader import Policy, PolicyError, load_policy
from .rules import RuleContext, evaluate_rules

GUARD_VERSION = "1.0.0"


class BlockedCallError(RuntimeError):
    """Raised by :meth:`CAGEGuard.guarded_call` in strict mode on a denial."""

    def __init__(self, decision: GuardDecision) -> None:
        super().__init__(f"{decision.tool} blocked by CAGE rule {decision.rule}: {decision.reason}")
        self.decision = decision


class CAGEGuard:
    """Middleware between an agent and its tools.

    Parameters
    ----------
    policy, policy_path:
        A parsed :class:`~cage_guard.policy_loader.Policy` or a path to load.
        If loading raises :class:`PolicyError` the guard starts in fail-closed
        mode instead of raising, so a misconfigured deployment denies rather
        than runs unguarded.
    ask_handler:
        Callable ``(GuardDecision) -> bool`` consulted when a rule returns
        ``ask``.  ``None`` leaves the ask unresolved: :meth:`guarded_call`
        does not execute the call and reports ``status="ask"`` so the Console
        (UC3) or CAGE-Eval's scripted oracle can resolve it later.
    observe_only:
        Evaluate and log decisions but execute every call regardless.  Used
        only to instrument the undefended baseline; never for C1-C3.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        policy_path: str | Path | None = None,
        request: TrustedRequest | None = None,
        history: CallHistoryStore | None = None,
        logger: DecisionLogger | None = None,
        run_context: RunContext | None = None,
        ask_handler: Callable[[GuardDecision], bool] | None = None,
        observe_only: bool = False,
    ) -> None:
        self.fail_closed_reason: str | None = None
        self.policy: Policy | None = policy
        if policy is None and policy_path is not None:
            try:
                self.policy = load_policy(policy_path)
            except PolicyError as exc:
                self.policy = None
                self.fail_closed_reason = f"invalid policy: {exc}"
        if self.policy is None and self.fail_closed_reason is None:
            self.fail_closed_reason = "no policy supplied"

        self.history = history or CallHistoryStore(request or TrustedRequest())
        if request is not None and history is not None:
            self.history.request = request
        self.logger = logger or DecisionLogger(
            context=run_context,
            guard_version=GUARD_VERSION,
            policy_version=self.policy.version if self.policy else None,
        )
        self.ask_handler = ask_handler
        self.observe_only = bool(observe_only)
        self.latencies_ms: list[float] = []

    # ------------------------------------------------------------ helpers
    @property
    def request(self) -> TrustedRequest:
        return self.history.request

    def register_result(
        self,
        tool: str,
        content: Any,
        *,
        source_id: str | None = None,
        trust: TrustLevel | None = None,
        sensitive: bool | None = None,
        values: Sequence[str] | None = None,
    ) -> ToolResultRecord:
        """Record a tool result so later calls can be evaluated against it.

        ``sensitive`` defaults to the ``reads_sensitive`` flag declared for the
        tool in the risk table, so Rule A's left-hand side comes from the
        policy rather than from each adapter remembering to pass a flag; an
        explicit ``True``/``False`` still overrides the declaration.  Passing
        ``values`` is what makes Rule A precise: without it the recorded
        content must appear verbatim in a later payload to match.
        """
        if sensitive is None:
            sensitive = bool(self.policy.spec(tool).reads_sensitive) if self.policy else False
        return self.history.record_result(
            tool, content, source_id=source_id, trust=trust, sensitive=sensitive, values=values
        )

    def _risk(self, tool: str) -> RiskClass:
        return self.policy.risk_of(tool) if self.policy else RiskClass.UNLISTED

    def _in_fail_closed_scope(self, risk: RiskClass) -> bool:
        scope = self.policy.fail_closed_scope if self.policy else ["low", "sensitive", "unlisted"]
        return risk.value in scope

    def _fail_closed(self, tool: str, risk: RiskClass, reason: str, detail: dict[str, Any]) -> GuardDecision:
        if self._in_fail_closed_scope(risk):
            return GuardDecision(
                decision=Decision.BLOCK,
                tool=tool,
                risk_class=risk,
                rule="NFR3",
                reason=f"fail-closed: {reason}",
                evidence=detail,
                fail_closed=True,
            )
        return GuardDecision(
            decision=Decision.ALLOW,
            tool=tool,
            risk_class=risk,
            rule="NFR3",
            reason=f"guard unavailable ({reason}); risk class {risk.value} is outside fail_closed_scope",
            evidence=detail,
            fail_closed=True,
        )

    # ----------------------------------------------------------- decision
    def evaluate(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        step_index: int | None = None,
    ) -> GuardDecision:
        """Decide ``allow`` / ``block`` / ``ask`` for one proposed call.

        Always returns a decision — never raises.  The reported
        ``latency_ms`` covers interception and rule evaluation only.
        """
        args = dict(args or {})
        step = self.history.next_step() if step_index is None else step_index
        t0 = time.perf_counter()

        if self.policy is None:
            decision = self._fail_closed(
                tool, RiskClass.UNLISTED, self.fail_closed_reason or "policy unavailable",
                {"stage": "policy_load"},
            )
        else:
            try:
                spec = self.policy.spec(tool)
                risk = spec.risk
                effective = self.policy.effective_risk(tool)
                denied_before = self.history.denied_count(tool, args)
                if denied_before > self.policy.max_denied_retries:
                    decision = GuardDecision(
                        decision=Decision.BLOCK,
                        tool=tool,
                        risk_class=risk,
                        rule="B2",
                        reason=(
                            f"retry budget exhausted: this call has already been denied "
                            f"{denied_before} times (max_denied_retries="
                            f"{self.policy.max_denied_retries})"
                        ),
                        evidence={"denied_before": denied_before},
                    )
                elif effective is RiskClass.LOW:
                    decision = GuardDecision(
                        decision=Decision.ALLOW,
                        tool=tool,
                        risk_class=risk,
                        reason="tool is declared low risk in the tool-risk table; no rule applies",
                    )
                else:
                    ctx = RuleContext(
                        tool=tool, args=args, policy=self.policy, history=self.history,
                        spec=spec, risk=risk,
                    )
                    outcome = evaluate_rules(ctx)
                    if outcome is None and tool not in self.policy.tools:
                        # Absent from the tool-risk table: no rule has a
                        # declared parameter to check, so the call is
                        # unverifiable rather than verified (ROPE A3).
                        outcome = GuardDecision(
                            decision=self.policy.unlisted_tool_unchecked_decision,
                            tool=tool,
                            risk_class=risk,
                            rule="A3",
                            reason=(
                                f"tool {tool!r} is absent from the tool-risk table, so no rule "
                                f"can check its parameters; the call is treated as unverifiable "
                                f"and routed to "
                                f"{self.policy.unlisted_tool_unchecked_decision.value}"
                            ),
                            evidence={"class": "unlisted_tool", "declared": False},
                        )
                    decision = outcome or GuardDecision(
                        decision=Decision.ALLOW,
                        tool=tool,
                        risk_class=risk,
                        reason="no rule objected: every sensitive value is verified against the "
                               "user request or a trusted record",
                    )
            except Exception as exc:  # NFR3: a guard crash must not open the sink
                decision = self._fail_closed(
                    tool, self._risk(tool), f"{type(exc).__name__}: {exc}",
                    {"stage": "rule_evaluation", "traceback": traceback.format_exc(limit=3)},
                )

        latency_ms = (time.perf_counter() - t0) * 1000.0
        decision = GuardDecision(
            decision=decision.decision,
            tool=decision.tool,
            risk_class=decision.risk_class,
            rule=decision.rule,
            reason=decision.reason,
            matched_param=decision.matched_param,
            evidence=decision.evidence,
            latency_ms=latency_ms,
            fail_closed=decision.fail_closed,
        )
        self.latencies_ms.append(latency_ms)
        self.history.record_call(
            tool, args, decision.decision, rule=decision.rule, reason=decision.reason,
            latency_ms=latency_ms, step_index=step,
        )
        self.logger.log_decision(decision, step_index=step, arguments=args)
        return decision

    # -------------------------------------------------------- enforcement
    def guarded_call(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        fn: Callable[..., Any] | None = None,
        *,
        strict: bool = False,
    ) -> dict[str, Any]:
        """Evaluate, then execute the call only if the decision permits it.

        Returns a dict with ``status`` in ``{"allowed", "blocked", "ask"}``,
        the ``decision`` record, and either ``result`` or ``error``.  A blocked
        call returns an error and a reason to the agent so that it may
        continue the task where possible (FR6) rather than terminating the
        run; ``strict=True`` raises :class:`BlockedCallError` instead.
        """
        args = dict(args or {})
        decision = self.evaluate(tool, args)
        permitted = decision.decision is Decision.ALLOW

        if decision.decision is Decision.ASK:
            approved: bool | None = None
            if self.ask_handler is not None:
                approved = bool(self.ask_handler(decision))
                self.logger.log_ask_resolution(
                    step_index=self.history.calls[-1].step_index,
                    tool=tool,
                    approved=approved,
                    reason=decision.reason,
                )
            if approved is None:
                return {"status": "ask", "decision": decision, "error": decision.reason}
            if not approved:
                return {"status": "blocked", "decision": decision,
                        "error": f"user declined: {decision.reason}", "ask_resolution": "denied"}
            permitted = True

        if permitted or (self.observe_only and decision.decision is Decision.BLOCK):
            if fn is None:
                return {"status": "allowed", "decision": decision, "result": None,
                        "observe_only": self.observe_only and decision.decision is Decision.BLOCK}
            return {
                "status": "allowed",
                "decision": decision,
                "result": fn(**args),
                "observe_only": self.observe_only and decision.decision is Decision.BLOCK,
            }

        if strict:
            raise BlockedCallError(decision)
        return {"status": "blocked", "decision": decision,
                "error": f"blocked by CAGE rule {decision.rule}: {decision.reason}"}

    def wrap(self, tool: str, fn: Callable[..., Any]) -> Callable[..., dict[str, Any]]:
        """Return a guarded version of ``fn`` registered under ``tool`` (UC1)."""

        def _wrapped(**kwargs: Any) -> dict[str, Any]:
            return self.guarded_call(tool, kwargs, fn)

        _wrapped.__name__ = f"guarded_{tool}"
        _wrapped.__doc__ = f"CAGE-guarded wrapper around tool {tool!r}."
        return _wrapped

    # -------------------------------------------------------------- stats
    def latency_stats(self) -> dict[str, float]:
        """Mean and p95 guard decision latency in milliseconds (NFR1)."""
        xs = sorted(self.latencies_ms)
        if not xs:
            return {"n": 0, "mean_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
        k = max(0, min(len(xs) - 1, int(round(0.95 * (len(xs) - 1)))))
        return {
            "n": float(len(xs)),
            "mean_ms": sum(xs) / len(xs),
            "p95_ms": xs[k],
            "max_ms": xs[-1],
        }

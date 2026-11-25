"""Call History Store — the composition-aware state of one run.

Rule A spans two calls (a sensitive read, then a send), so the guard is not
memoryless: it needs a per-run record of what was read, from which source, at
which trust level, and what was called.  This module is that record.  It
holds no policy and makes no decisions.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .decisions import TrustLevel
from .matching import canonical, collect_strings, match_any, whole_value_match


@dataclass
class TrustedRequest:
    """The user's request: the only unconditionally trusted input (FR4).

    ``named_sources`` are the sources the request itself names (``bill.pdf``
    in *"pay the bill in bill.pdf"*).  Naming a source does **not** make its
    content trusted — it makes the source *declared-trusted*, which is what
    routes a single-origin sensitive parameter to ``ask`` rather than to
    ``allow`` (review §2.1, checklist A2).

    ``trusted_records`` are platform-maintained records whose content may be
    treated as verified (an authenticated payee list, a contacts directory).
    """

    text: str = ""
    named_sources: list[str] = field(default_factory=list)
    trusted_records: dict[str, str] = field(default_factory=dict)
    authorised_destinations: list[str] = field(default_factory=list)

    def names_source(self, source_id: str | None) -> bool:
        """True when the request explicitly names ``source_id``."""
        if not source_id:
            return False
        sid = canonical(source_id)
        if any(sid == canonical(s) for s in self.named_sources):
            return True
        return whole_value_match(source_id, self.text)

    def mentions(self, value: Any) -> bool:
        """True when ``value`` appears verbatim in the request text."""
        return whole_value_match(value, self.text)

    def record_texts(self) -> list[str]:
        return list(self.trusted_records.values())

    def verified(self, value: Any) -> bool:
        """True when ``value`` is in the request or in a trusted record."""
        return self.mentions(value) or match_any(value, self.record_texts())

    def trust_of_source(self, source_id: str | None) -> TrustLevel:
        if source_id and source_id in self.trusted_records:
            return TrustLevel.TRUSTED
        return TrustLevel.DECLARED_TRUSTED if self.names_source(source_id) else TrustLevel.UNTRUSTED


@dataclass
class ToolResultRecord:
    """One tool result observed by the guard."""

    step_index: int
    tool: str
    source_id: str | None
    trust: TrustLevel
    content: str
    sensitive: bool = False
    values: list[str] = field(default_factory=list)

    def carries(self, value: Any) -> bool:
        return whole_value_match(value, self.content)

    def sensitive_values(self) -> list[str]:
        """Explicitly declared sensitive values, else the whole content."""
        return list(self.values) if self.values else ([self.content] if self.content else [])


@dataclass
class CallRecord:
    """One intercepted call and the decision taken on it."""

    step_index: int
    tool: str
    args: dict[str, Any]
    decision: str
    rule: str | None = None
    reason: str = ""
    latency_ms: float = 0.0


class CallHistoryStore:
    """Per-run history of tool results and intercepted calls."""

    def __init__(self, request: TrustedRequest | None = None) -> None:
        self.request: TrustedRequest = request or TrustedRequest()
        self.results: list[ToolResultRecord] = []
        self.calls: list[CallRecord] = []
        self._step = 0

    # ---------------------------------------------------------------- writes
    def next_step(self) -> int:
        self._step += 1
        return self._step

    def record_result(
        self,
        tool: str,
        content: Any,
        *,
        source_id: str | None = None,
        trust: TrustLevel | None = None,
        sensitive: bool = False,
        values: Sequence[str] | None = None,
        step_index: int | None = None,
    ) -> ToolResultRecord:
        """Record a tool result and its provenance.

        ``trust`` defaults to the trust level implied by the user's request:
        a source the request names is *declared-trusted*, anything else is
        *untrusted*.
        """
        rec = ToolResultRecord(
            step_index=self.next_step() if step_index is None else step_index,
            tool=tool,
            source_id=source_id,
            trust=trust or self.request.trust_of_source(source_id),
            content="" if content is None else str(content),
            sensitive=sensitive,
            values=[str(v) for v in (values or [])],
        )
        self.results.append(rec)
        return rec

    def record_call(self, tool: str, args: dict[str, Any], decision: Any, **kw: Any) -> CallRecord:
        rec = CallRecord(
            step_index=kw.pop("step_index", None) or self.next_step(),
            tool=tool,
            args=dict(args),
            decision=getattr(decision, "value", str(decision)),
            **kw,
        )
        self.calls.append(rec)
        return rec

    # ----------------------------------------------------------------- reads
    def sensitive_reads(self) -> list[ToolResultRecord]:
        """Results marked sensitive — the left-hand side of Rule A."""
        return [r for r in self.results if r.sensitive]

    def origins_of(self, value: Any) -> list[ToolResultRecord]:
        """Every recorded result whose content carries ``value``.

        The *number* of distinct origins is what Rule B keys on: a sensitive
        value whose only origin is a single user-named source is the
        delegated-parameter case and is routed to ``ask``.
        """
        return [r for r in self.results if r.carries(value)]

    def origins_by_trust(self, value: Any, trust: TrustLevel) -> list[ToolResultRecord]:
        return [r for r in self.origins_of(value) if r.trust is trust]

    def results_at(self, *trust: TrustLevel) -> list[ToolResultRecord]:
        wanted = set(trust)
        return [r for r in self.results if r.trust in wanted]

    def denied_count(self, tool: str, args: dict[str, Any]) -> int:
        """How many times this exact call has already been denied (B2)."""
        key = _call_key(tool, args)
        return sum(1 for c in self.calls if c.decision == "block" and _call_key(c.tool, c.args) == key)

    def payload_strings(self, args: dict[str, Any]) -> list[str]:
        return collect_strings(args)

    def reset(self) -> None:
        self.results.clear()
        self.calls.clear()
        self._step = 0


def _call_key(tool: str, args: dict[str, Any]) -> str:
    items = sorted((str(k), canonical(v)) for k, v in (args or {}).items())
    return tool + "|" + "|".join(f"{k}={v}" for k, v in items)

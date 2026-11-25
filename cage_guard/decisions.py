"""Decision vocabulary for CAGE-Guard.

The three-way decision is the methodological core of the system.  A *block*
is an assertion by the guard that it has positive evidence of an
unauthorised flow or value.  An *ask* is an admission that the guard cannot
discriminate and that the user can.  The two are never conflated: an ask that
the user approves on a benign case is a *recovered task*, while an ask the
user approves on an attacked case is a *confirmation-attributable attack
success*.  Both are counted separately by CAGE-Eval.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """The guard's three possible outcomes (FR2)."""

    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


class TrustLevel(str, Enum):
    """Trust boundaries, following the threat model of ROPE [5].

    TRUSTED            the user's request and platform-maintained identity
    DECLARED_TRUSTED   a record or source the user's request explicitly names
    UNTRUSTED          every other retrieved content and tool output
    """

    TRUSTED = "trusted"
    DECLARED_TRUSTED = "declared_trusted"
    UNTRUSTED = "untrusted"


class RiskClass(str, Enum):
    """Tool-risk table classes (FR7)."""

    LOW = "low"
    SENSITIVE = "sensitive"
    UNLISTED = "unlisted"


@dataclass(frozen=True)
class GuardDecision:
    """One immutable decision about one intercepted tool call.

    ``evidence`` carries the machine-readable grounds for the decision (the
    matched value, its recorded origin, the unauthorised destination) so that
    the Console can display a reason and CAGE-Eval can classify a trace
    without re-deriving anything.
    """

    decision: Decision
    tool: str
    risk_class: RiskClass
    rule: str | None = None
    reason: str = ""
    matched_param: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    fail_closed: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def denied(self) -> bool:
        """True for a hard block only.  An unresolved ask is not a denial."""
        return self.decision is Decision.BLOCK

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        d["risk_class"] = self.risk_class.value
        return d

    def __str__(self) -> str:  # pragma: no cover - display helper
        rule = self.rule or "-"
        return f"[{self.decision.value.upper()}] {self.tool} rule={rule}: {self.reason}"

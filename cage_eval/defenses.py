"""Conditions C0-C3 and their defense adapters.

Each condition declares which external defense it needs.  Progent and ROPE
are **conditional on the compatibility pilot**, so their adapters raise
:class:`DefenseUnavailable` until a real implementation is wired in.  The
runner turns that into a *skipped* condition carrying the reason; nothing
downstream ever computes a metric over a condition that did not run, and no
substitute is quietly inserted.

If the released ROPE implementation cannot be run, the substitute is a
locally built origin-tracking baseline whose label is
``"C2 (ROPE-inspired)"`` everywhere — in the condition registry, the exported
tables and the per-case JSON.  The string ``"ROPE"`` alone is reserved for the
released implementation and is never emitted by the fallback.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cage_guard import CAGEGuard, CallHistoryStore, DecisionLogger, Policy, TrustedRequest
from cage_guard.logger import RunContext


class DefenseUnavailable(RuntimeError):
    """Raised when a condition's external defense is not integrated."""


@dataclass(frozen=True)
class ConditionSpec:
    """One experimental condition."""

    condition_id: str
    label: str
    requires: tuple = ()
    uses_cage_rules: bool = False
    research_condition: bool = True
    description: str = ""


CONDITIONS: dict[str, ConditionSpec] = {
    "C0": ConditionSpec(
        "C0", "C0 (no defense)",
        description="Baseline agent with no external guard; the reference point for "
                    "every comparison and the source of the unrelated-failure baseline.",
    ),
    "C1": ConditionSpec(
        "C1", "C1 (Progent)", requires=("progent",),
        description="Per-call privilege control. Conditional on the compatibility pilot.",
    ),
    "C2": ConditionSpec(
        "C2", "C2 (ROPE)", requires=("rope",),
        description="Origin-based enforcement using the released implementation. "
                    "If it cannot be run, condition C2_inspired is used instead and is "
                    "never reported as ROPE.",
    ),
    "C2_inspired": ConditionSpec(
        "C2_inspired", "C2 (ROPE-inspired)", requires=("rope_inspired",),
        description="Locally built origin-tracking baseline used only when the released "
                    "ROPE implementation cannot be run. Never labelled ROPE and never "
                    "compared against published ROPE percentages.",
    ),
    "C3": ConditionSpec(
        "C3", "C3 (Progent + CAGE rules)", requires=("progent",), uses_cage_rules=True,
        description="Progent with the CAGE rule layer as Guard 2 (FR8).",
    ),
    "C3_cage_only": ConditionSpec(
        "C3_cage_only", "CAGE rules alone (demonstration)", uses_cage_rules=True,
        research_condition=False,
        description="The guard alone, without Progent (FR8, demonstration path). Used for "
                    "the live demo and for pipeline self-tests; not a research condition "
                    "and not reported in the C1/C2/C3 contrast tables.",
    ),
}

#: Registry of integrated external defenses.  Empty until the pilot passes.
DEFENSE_REGISTRY: dict[str, Callable[..., Any]] = {}


def register_defense(name: str, factory: Callable[..., Any]) -> None:
    """Register a real defense implementation (called by the integration code)."""
    DEFENSE_REGISTRY[name] = factory


@dataclass
class ConditionRuntime:
    """What the runner needs to execute one condition."""

    spec: ConditionSpec
    guard: CAGEGuard | None = None
    external: dict[str, Any] = field(default_factory=dict)

    @property
    def enforcing(self) -> bool:
        return self.guard is not None or bool(self.external)


def build_condition(
    condition_id: str,
    *,
    policy: Policy | None = None,
    request: TrustedRequest | None = None,
    logger: DecisionLogger | None = None,
    run_context: RunContext | None = None,
    ask_handler: Callable[[Any], bool] | None = None,
) -> ConditionRuntime:
    """Construct the runtime for one condition, or refuse.

    Raises :class:`DefenseUnavailable` when the condition needs an external
    defense that has not been registered, and :class:`ValueError` when a
    condition that must enforce the CAGE rules is handed a policy with a rule
    disabled or a guard in observe-only mode.
    """
    if condition_id not in CONDITIONS:
        raise ValueError(f"unknown condition {condition_id!r}; known: {sorted(CONDITIONS)}")
    spec = CONDITIONS[condition_id]

    external: dict[str, Any] = {}
    for dep in spec.requires:
        if dep not in DEFENSE_REGISTRY:
            raise DefenseUnavailable(
                f"condition {spec.condition_id} requires the {dep!r} defense, which is not "
                f"integrated; run the compatibility pilot and register it before reporting "
                f"this condition"
            )
        external[dep] = DEFENSE_REGISTRY[dep]()

    guard: CAGEGuard | None = None
    if spec.uses_cage_rules:
        if policy is None:
            raise ValueError(f"condition {spec.condition_id} needs a policy for the CAGE rules")
        missing = [r for r in ("A", "B", "C") if not policy.rule_enabled(r)]
        if missing:
            raise ValueError(
                f"condition {spec.condition_id} requires Rules A, B and C; the supplied policy "
                f"disables {missing}. Enabling them is a configuration change that must be "
                f"recorded, not made implicitly."
            )
        guard = CAGEGuard(
            policy,
            history=CallHistoryStore(request or TrustedRequest()),
            logger=logger,
            run_context=run_context,
            ask_handler=ask_handler,
        )
        if guard.observe_only:
            raise ValueError("observe_only must be False for an enforcing condition")

    return ConditionRuntime(spec=spec, guard=guard, external=external)

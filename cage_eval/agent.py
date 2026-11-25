"""Agent adapters.

The research runs require a real agent model on the real control path; that
adapter is pending the frozen model revision and the AgentDojo commit, so the
only adapter implemented here is :class:`ScriptedAgent`, which replays the
tool calls a case declares.  A scripted agent exercises the guard, the
classifier and the metrics pipeline deterministically and **is not an agent
model**: every result it produces is labelled ``agent="scripted"`` in the run
metadata so it can never be mistaken for a measurement of model behaviour.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from .cases import Case


class AgentAdapter(Protocol):
    """Minimal interface the runner needs from an agent."""

    name: str

    def propose(self, case: Case, seed: int) -> Iterator[tuple[str, dict[str, Any], bool]]:
        """Yield ``(tool, args, retry_on_block)`` triples in order."""

    def observe(self, tool: str, outcome: dict[str, Any]) -> None:
        """Receive the outcome of the last call (FR6: errors reach the agent)."""

    @property
    def model_calls(self) -> int:
        """Number of model invocations made.  Zero for a scripted agent."""


@dataclass
class ScriptedAgent:
    """Replays a case's declared call script.

    ``retry_on_block`` on a call makes the agent re-propose the identical call
    once after a denial, which is what exercises the frozen retry policy
    (checklist B2).
    """

    name: str = "scripted"
    observations: list[dict[str, Any]] = field(default_factory=list)

    def propose(self, case: Case, seed: int) -> Iterator[tuple[str, dict[str, Any], bool]]:
        for call in case.script:
            yield call.tool, dict(call.args), call.retry_on_block

    def observe(self, tool: str, outcome: dict[str, Any]) -> None:
        self.observations.append({"tool": tool, **outcome})

    @property
    def model_calls(self) -> int:
        return 0

    @property
    def tokens(self) -> int | None:
        """Token counts are not exposed by a scripted agent (reported as unknown)."""
        return None

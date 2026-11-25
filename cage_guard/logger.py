"""Decision logging — the single source of truth for every metric (NFR9).

One JSON record per intercepted call, written as JSON Lines so a run can be
streamed and partially-written runs remain parseable.  CAGE-Eval computes all
metrics from these records and the CAGE Console only displays them; neither
recomputes a decision.

Record schema (one object per line)::

    record_type   "decision" | "ask_resolution" | "run_metadata"
    run_id        identifier of the run
    condition     C0 | C1 | C2 | C3
    case_id       case identifier
    seed          random seed in force
    step_index    position of the call within the run
    tool          tool name
    arguments     the intercepted arguments
    risk_class    low | sensitive | unlisted
    decision      allow | block | ask
    rule          rule that fired (A | B | C), or null
    reason        human-readable justification
    evidence      machine-readable grounds for the decision
    latency_ms    guard decision latency, excluding all model time
    fail_closed   true when the decision came from the fail-closed path
    timestamp     UTC ISO-8601
    guard_version / policy_version
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cage-log-1"


@dataclass
class RunContext:
    """Identifiers stamped onto every record of one run."""

    run_id: str = "run"
    condition: str = "C3"
    case_id: str = "unspecified"
    seed: int | None = None
    model_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "run_id": self.run_id,
            "condition": self.condition,
            "case_id": self.case_id,
            "seed": self.seed,
            "model_id": self.model_id,
        }
        d.update(self.extra)
        return d


class DecisionLogger:
    """Append-only JSONL logger.  Thread-safe; keeps records in memory too."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        context: RunContext | None = None,
        guard_version: str = "1.0.0",
        policy_version: str | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.context = context or RunContext()
        self.guard_version = guard_version
        self.policy_version = policy_version
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- writing
    def _emit(self, record: dict[str, Any]) -> dict[str, Any]:
        record = {
            "schema": SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "guard_version": self.guard_version,
            "policy_version": self.policy_version,
            **self.context.to_dict(),
            **record,
        }
        with self._lock:
            self.records.append(record)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")
        return record

    def log_decision(self, decision: Any, *, step_index: int, arguments: dict[str, Any]) -> dict[str, Any]:
        payload = decision.to_dict() if hasattr(decision, "to_dict") else dict(decision)
        payload.pop("tool", None)
        return self._emit(
            {
                "record_type": "decision",
                "step_index": step_index,
                "tool": getattr(decision, "tool", None),
                "arguments": arguments,
                **payload,
            }
        )

    def log_ask_resolution(
        self,
        *,
        step_index: int,
        tool: str,
        approved: bool,
        resolver: str = "user",
        reason: str = "",
    ) -> dict[str, Any]:
        """Record how an ``ask`` was resolved.

        Kept distinct from the decision record: an approved ask on a benign
        case is a recovered task, while an approved ask on an attacked case is
        a confirmation-attributable attack success.
        """
        return self._emit(
            {
                "record_type": "ask_resolution",
                "step_index": step_index,
                "tool": tool,
                "approved": bool(approved),
                "resolver": resolver,
                "reason": reason,
            }
        )

    def log_run_metadata(self, **metadata: Any) -> dict[str, Any]:
        """Record environment, model and commit identifiers for the run (NFR4)."""
        return self._emit({"record_type": "run_metadata", "metadata": metadata})

    # ------------------------------------------------------------- reading
    def decisions(self) -> list[dict[str, Any]]:
        return [r for r in self.records if r.get("record_type") == "decision"]

    def as_jsonl(self) -> str:
        return "".join(json.dumps(r, default=str, ensure_ascii=False) + "\n" for r in self.records)


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read a decision log back.  CAGE-Eval and the Console both use this."""
    out: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out

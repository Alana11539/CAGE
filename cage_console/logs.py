"""Read-only access to the shared decision logs and exported results.

Grouping and counting only.  Every rate the Console displays is read from a
CAGE-Eval export; this module never derives one, so the dashboard cannot
drift from the harness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RunSummary:
    """One run as the log file describes it."""

    run_id: str
    condition: str
    case_id: str
    seed: int | None
    split: str | None = None
    family: str | None = None
    attacked: bool | None = None
    agent: str | None = None
    environment: str | None = None
    policy_version: str | None = None
    guard_version: str | None = None
    n_decisions: int = 0
    decision_counts: dict[str, int] = field(default_factory=dict)
    rules_fired: dict[str, int] = field(default_factory=dict)
    asks_approved: int = 0
    asks_denied: int = 0
    fail_closed_events: int = 0
    log_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class LogStore:
    """Scans a directory tree of ``*.jsonl`` decision logs.

    Results are cached per file on ``(path, mtime, size)`` so repeated
    requests do not re-parse unchanged logs.
    """

    def __init__(self, logs_dir: str | Path, results_dir: str | Path | None = None) -> None:
        self.logs_dir = Path(logs_dir)
        self.results_dir = Path(results_dir) if results_dir else None
        self._cache: dict[Path, tuple] = {}

    # ----------------------------------------------------------- discovery
    def log_files(self) -> list[Path]:
        if not self.logs_dir.is_dir():
            return []
        return sorted(p for p in self.logs_dir.rglob("*.jsonl") if p.is_file())

    def _records(self, path: Path) -> list[dict[str, Any]]:
        stat = path.stat()
        key = (stat.st_mtime_ns, stat.st_size)
        cached = self._cache.get(path)
        if cached and cached[0] == key:
            return cached[1]
        records: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    # A partially written final line is skipped rather than
                    # failing the whole run view; JSONL is append-only.
                    continue
        self._cache[path] = (key, records)
        return records

    # ------------------------------------------------------------- queries
    def runs(self) -> list[RunSummary]:
        out: list[RunSummary] = []
        for path in self.log_files():
            records = self._records(path)
            if not records:
                continue
            first = records[0]
            summary = RunSummary(
                run_id=first.get("run_id", path.stem),
                condition=first.get("condition", "unknown"),
                case_id=first.get("case_id", "unknown"),
                seed=first.get("seed"),
                split=first.get("split"),
                family=first.get("family"),
                attacked=first.get("attacked"),
                agent=first.get("agent"),
                environment=first.get("environment"),
                policy_version=first.get("policy_version"),
                guard_version=first.get("guard_version"),
                log_file=str(path),
            )
            for r in records:
                kind = r.get("record_type")
                if kind == "decision":
                    summary.n_decisions += 1
                    d = r.get("decision", "unknown")
                    summary.decision_counts[d] = summary.decision_counts.get(d, 0) + 1
                    rule = r.get("rule")
                    if rule:
                        summary.rules_fired[rule] = summary.rules_fired.get(rule, 0) + 1
                    if r.get("fail_closed"):
                        summary.fail_closed_events += 1
                elif kind == "ask_resolution":
                    if r.get("approved"):
                        summary.asks_approved += 1
                    else:
                        summary.asks_denied += 1
            out.append(summary)
        return out

    def run(self, run_id: str) -> dict[str, Any] | None:
        """Full timeline for one run: every record, in file order."""
        for path in self.log_files():
            records = self._records(path)
            if records and records[0].get("run_id", path.stem) == run_id:
                decisions = [r for r in records if r.get("record_type") == "decision"]
                asks = {
                    r.get("step_index"): r
                    for r in records if r.get("record_type") == "ask_resolution"
                }
                timeline = [
                    {**d, "ask_resolution": asks.get(d.get("step_index"))} for d in decisions
                ]
                metadata = [r for r in records if r.get("record_type") == "run_metadata"]
                return {
                    "run_id": run_id,
                    "log_file": str(path),
                    "timeline": timeline,
                    "metadata": metadata,
                    "record_count": len(records),
                }
        return None

    # ------------------------------------------------------------ exports
    def result_files(self) -> list[Path]:
        if self.results_dir is None or not self.results_dir.is_dir():
            return []
        return sorted(self.results_dir.rglob("*per_case_results.json"))

    def exports(self) -> list[dict[str, Any]]:
        """Every CAGE-Eval export found, newest first, read verbatim."""
        out = []
        for p in self.result_files():
            try:
                payload = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            out.append(
                {
                    "file": str(p),
                    "name": p.name,
                    "provenance": payload.get("provenance"),
                    "metrics": payload.get("metrics"),
                    "n_runs": len(payload.get("runs", [])),
                }
            )
        return sorted(out, key=lambda e: (e["provenance"] or {}).get("generated", ""), reverse=True)

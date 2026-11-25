"""Case definitions and loading (D4).

A case is a JSON document with an ID, a goal, a scoring rule and an expected
outcome.  Cases are partitioned **by attack template** into ``cases/design``
(used while rules are written) and ``cases/held_out`` (untouched until the
final evaluation); the loader records which split a case came from and the
runner refuses to mix them in one reported table.

Benign and attacked variants of the same template are linked through
``template_id`` so that over-blocking is measured against the same task the
attack targets.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Case families, aligned to the threat model and the residual classes of [5].
FAMILIES = (
    "source_to_sink",
    "argument_manipulation",
    "message_body",
    "benign_file_only",
    "benign_verified_value",
    "benign_linked_body",
    "unlisted_tool",
)

SPLITS = ("design", "held_out")

#: Which rule a case is built to exercise. Recorded per case so that coverage
#: of Rules A, B and C can be reported rather than asserted.
RULE_TARGETS = ("A", "B", "C", "A3", "none")

#: How a case relates to the benchmark.
#:   template            - no benchmark task behind it yet
#:   bound_to_base_task  - constructed against the environment and schema of a
#:                         named AgentDojo task, whose identifier was read from
#:                         the repository (never invented)
BINDING_STATES = ("template", "bound_to_base_task")

#: Keys permitted in a case's policy overlay. The overlay exists for the
#: unlisted-tool case, which probes ROPE assumption A3 empirically by removing
#: a tool from the risk table for that case only.
POLICY_OVERLAY_KEYS = ("omit_tools",)


class CaseValidationError(ValueError):
    """Raised when a case document is missing a required field or malformed."""


@dataclass(frozen=True)
class ToolResultSpec:
    """A tool result the environment returns during the case."""

    tool: str
    content: str
    source_id: str | None = None
    values: list[str] = field(default_factory=list)
    sensitive: bool | None = None
    trust: str | None = None


@dataclass(frozen=True)
class CallSpec:
    """One tool call the agent proposes, in order."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    retry_on_block: bool = False


@dataclass(frozen=True)
class Criterion:
    """Match an executed call: tool name plus required argument values.

    ``args_contains`` is compared with the guard's own whole-value matching so
    that a scoring rule and an enforcement rule cannot disagree about whether
    two values are the same.
    """

    tool: str
    args_contains: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BenchmarkBinding:
    """The AgentDojo task a case was constructed against.

    A CAGE case is **not** an AgentDojo task: it is constructed by the authors
    against a named task's environment and schema. Recording the identifier,
    the repository and the commit the identifier was read from keeps that
    distinction auditable and stops a constructed case being reported as a
    benchmark case.
    """

    suite: str | None = None
    user_task_id: str | None = None
    injection_task_id: str | None = None
    repository: str | None = None
    commit_read: str | None = None
    retrieved: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "user_task_id": self.user_task_id,
            "injection_task_id": self.injection_task_id,
            "repository": self.repository,
            "commit_read": self.commit_read,
            "retrieved": self.retrieved,
        }


@dataclass(frozen=True)
class Case:
    """One evaluation case."""

    case_id: str
    split: str
    family: str
    suite: str
    attacked: bool
    user_request: str
    template_id: str
    named_sources: list[str] = field(default_factory=list)
    trusted_records: dict[str, str] = field(default_factory=dict)
    tool_results: list[ToolResultSpec] = field(default_factory=list)
    script: list[CallSpec] = field(default_factory=list)
    success_criterion: Criterion | None = None
    attacker_goal: Criterion | None = None
    expected_decision: str | None = None
    ask_oracle: str = "deny"
    file_only: bool = False
    notes: str = ""
    source_path: str | None = None
    rule_target: str = "none"
    case_origin: str = "constructed_by_authors"
    binding_status: str = "template"
    benchmark: BenchmarkBinding = field(default_factory=BenchmarkBinding)
    policy_overlay: dict[str, Any] = field(default_factory=dict)

    @property
    def benign(self) -> bool:
        return not self.attacked

    @property
    def bound(self) -> bool:
        """True when the case names a real benchmark base task."""
        return self.binding_status == "bound_to_base_task"

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "template_id": self.template_id,
            "split": self.split,
            "family": self.family,
            "suite": self.suite,
            "attacked": self.attacked,
            "file_only": self.file_only,
            "expected_decision": self.expected_decision,
            "ask_oracle": self.ask_oracle,
            "rule_target": self.rule_target,
            "case_origin": self.case_origin,
            "binding_status": self.binding_status,
            "benchmark": self.benchmark.to_dict(),
            "policy_overlay": dict(self.policy_overlay),
            "notes": self.notes,
        }


def _require(raw: Mapping[str, Any], key: str, path: str) -> Any:
    if key not in raw:
        raise CaseValidationError(f"{path}: missing required field {key!r}")
    return raw[key]


def _criterion(raw: Any, path: str) -> Criterion | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping) or "tool" not in raw:
        raise CaseValidationError(f"{path}: criterion must be a mapping with a 'tool' key")
    return Criterion(tool=str(raw["tool"]), args_contains=dict(raw.get("args_contains", {})))


def parse_case(raw: Mapping[str, Any], *, split: str | None = None,
               source_path: str | None = None) -> Case:
    """Validate one case document."""
    path = source_path or raw.get("case_id", "<case>")
    if not isinstance(raw, Mapping):
        raise CaseValidationError(f"{path}: case must be a mapping")

    case_split = split or raw.get("split")
    if case_split not in SPLITS:
        raise CaseValidationError(f"{path}: split must be one of {SPLITS}, got {case_split!r}")

    family = _require(raw, "family", path)
    if family not in FAMILIES:
        raise CaseValidationError(f"{path}: family must be one of {FAMILIES}, got {family!r}")

    attacked = bool(_require(raw, "attacked", path))
    attacker_goal = _criterion(raw.get("attacker_goal"), path)
    if attacked and attacker_goal is None:
        raise CaseValidationError(f"{path}: an attacked case must declare 'attacker_goal'")
    if not attacked and attacker_goal is not None:
        raise CaseValidationError(f"{path}: a benign case must not declare 'attacker_goal'")

    ask_oracle = raw.get("ask_oracle", "deny")
    if ask_oracle not in {"approve", "deny"}:
        raise CaseValidationError(f"{path}: ask_oracle must be 'approve' or 'deny'")

    expected = raw.get("expected_decision")
    if expected is not None and expected not in {"allow", "block", "ask"}:
        raise CaseValidationError(f"{path}: expected_decision must be allow, block or ask")

    results = []
    for i, r in enumerate(raw.get("tool_results", [])):
        if not isinstance(r, Mapping) or "tool" not in r:
            raise CaseValidationError(f"{path}: tool_results[{i}] must be a mapping with 'tool'")
        results.append(
            ToolResultSpec(
                tool=str(r["tool"]),
                content=str(r.get("content", "")),
                source_id=r.get("source_id"),
                values=[str(v) for v in r.get("values", [])],
                sensitive=r.get("sensitive"),
                trust=r.get("trust"),
            )
        )

    script = []
    for i, c in enumerate(_require(raw, "script", path)):
        if not isinstance(c, Mapping) or "tool" not in c:
            raise CaseValidationError(f"{path}: script[{i}] must be a mapping with 'tool'")
        script.append(
            CallSpec(
                tool=str(c["tool"]),
                args=dict(c.get("args", {})),
                retry_on_block=bool(c.get("retry_on_block", False)),
            )
        )
    if not script:
        raise CaseValidationError(f"{path}: 'script' must contain at least one call")

    rule_target = str(raw.get("rule_target", "none"))
    if rule_target not in RULE_TARGETS:
        raise CaseValidationError(f"{path}: rule_target must be one of {RULE_TARGETS}")

    binding_status = str(raw.get("binding_status", "template"))
    if binding_status not in BINDING_STATES:
        raise CaseValidationError(f"{path}: binding_status must be one of {BINDING_STATES}")
    bench_raw = raw.get("benchmark") or {}
    if not isinstance(bench_raw, Mapping):
        raise CaseValidationError(f"{path}: 'benchmark' must be a mapping")
    benchmark = BenchmarkBinding(
        suite=bench_raw.get("suite"),
        user_task_id=bench_raw.get("user_task_id"),
        injection_task_id=bench_raw.get("injection_task_id"),
        repository=bench_raw.get("repository"),
        commit_read=bench_raw.get("commit_read"),
        retrieved=bench_raw.get("retrieved"),
    )
    if binding_status == "bound_to_base_task":
        missing = [k for k in ("suite", "user_task_id", "repository", "commit_read")
                   if not getattr(benchmark, k)]
        if missing:
            raise CaseValidationError(
                f"{path}: a case bound to a base task must record {missing} so the identifier "
                f"can be traced to the repository it was read from"
            )

    overlay = raw.get("policy_overlay") or {}
    if not isinstance(overlay, Mapping):
        raise CaseValidationError(f"{path}: 'policy_overlay' must be a mapping")
    unknown_overlay = set(overlay) - set(POLICY_OVERLAY_KEYS)
    if unknown_overlay:
        raise CaseValidationError(
            f"{path}: policy_overlay keys {sorted(unknown_overlay)} are not permitted; "
            f"allowed: {list(POLICY_OVERLAY_KEYS)}"
        )
    if "omit_tools" in overlay:
        omit = overlay["omit_tools"]
        if isinstance(omit, str) or not isinstance(omit, (list, tuple)) \
                or not all(isinstance(t, str) for t in omit):
            raise CaseValidationError(
                f"{path}: policy_overlay.omit_tools must be a list of tool names"
            )
        overlay = {"omit_tools": list(omit)}

    return Case(
        case_id=str(_require(raw, "case_id", path)),
        split=case_split,
        family=family,
        suite=str(raw.get("suite", "unspecified")),
        attacked=attacked,
        user_request=str(_require(raw, "user_request", path)),
        template_id=str(raw.get("template_id", raw["case_id"])),
        named_sources=[str(s) for s in raw.get("named_sources", [])],
        trusted_records={str(k): str(v) for k, v in (raw.get("trusted_records") or {}).items()},
        tool_results=results,
        script=script,
        success_criterion=_criterion(raw.get("success_criterion"), path),
        attacker_goal=attacker_goal,
        expected_decision=expected,
        ask_oracle=ask_oracle,
        file_only=bool(raw.get("file_only", False)),
        notes=str(raw.get("notes", "")),
        source_path=source_path,
        rule_target=rule_target,
        case_origin=str(raw.get("case_origin", "constructed_by_authors")),
        binding_status=binding_status,
        benchmark=benchmark,
        policy_overlay=dict(overlay),
    )


def load_case_file(path: str | Path, *, split: str | None = None) -> Case:
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaseValidationError(f"{p}: invalid JSON: {exc}") from exc
    return parse_case(raw, split=split, source_path=str(p))


def load_cases(directory: str | Path, *, split: str | None = None) -> list[Case]:
    """Load every ``*.json`` case in ``directory``.

    ``split`` defaults to the directory name when it is ``design`` or
    ``held_out``, so a case cannot silently claim the wrong split.
    """
    d = Path(directory)
    if not d.is_dir():
        raise CaseValidationError(f"case directory not found: {d}")
    inferred = split or (d.name if d.name in SPLITS else None)
    cases = [load_case_file(p, split=inferred) for p in sorted(d.glob("*.json"))]
    ids = [c.case_id for c in cases]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise CaseValidationError(f"{d}: duplicate case_id values {duplicates}")
    return cases


def unbound(cases: Sequence[Case]) -> list[str]:
    """Case IDs not yet bound to a benchmark base task."""
    return [c.case_id for c in cases if not c.bound]


def coverage(cases: Sequence[Case]) -> dict[str, int]:
    """Counts per rule target, family, split and attack status - reported, not assumed."""
    out: dict[str, int] = {}
    for c in cases:
        for key in (f"rule_{c.rule_target}", f"family_{c.family}", f"split_{c.split}",
                    "attacked" if c.attacked else "benign"):
            out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def partition_check(cases: Sequence[Case]) -> dict[str, list[str]]:
    """Report any attack template appearing in both splits.

    The design/held-out partition is by **template**, not by run: a template
    that leaks across the boundary invalidates the held-out estimate.
    """
    by_template: dict[str, set] = {}
    for c in cases:
        by_template.setdefault(c.template_id, set()).add(c.split)
    leaked = {t: sorted(s) for t, s in by_template.items() if len(s) > 1}
    return leaked

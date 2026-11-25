"""Policy and tool-risk-table loader (FR7, NFR3).

The policy is data, not code: a JSON or YAML document declaring which tools
are low-risk or sensitive, which of their parameters are sensitive
recipients / destinations / amounts, which parameters carry a message body,
and the frozen enforcement knobs (value-matching minimum length, amount
tolerance, retry budget, Rule C routing).

Loading is strict.  Any structural error raises :class:`PolicyError`; the
interceptor turns that into a fail-closed guard rather than an unguarded
agent (NFR3).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .decisions import Decision, RiskClass

_VALID_RISK = {r.value for r in RiskClass}
_RULE_IDS = ("A", "B", "C")


class PolicyError(ValueError):
    """Raised when a policy document is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class ToolSpec:
    """Declared security properties of one tool."""

    name: str
    risk: RiskClass = RiskClass.LOW
    state_changing: bool = False
    sensitive_params: list[str] = field(default_factory=list)
    destination_params: list[str] = field(default_factory=list)
    amount_params: list[str] = field(default_factory=list)
    body_params: list[str] = field(default_factory=list)
    reads_sensitive: bool = False


@dataclass(frozen=True)
class Policy:
    """A frozen, auditable enforcement policy."""

    version: str
    tools: dict[str, ToolSpec] = field(default_factory=dict)
    unlisted_tool_risk: RiskClass = RiskClass.SENSITIVE
    #: What to do with a state-changing call to a tool absent from the risk
    #: table, which therefore has no declared parameters for any rule to check.
    #: ROPE states assumption A3 (the sensitive-tool table is complete); CAGE
    #: treats the omission as an empirical question and routes the unchecked
    #: call to the user, which is measurable, rather than silently allowing it.
    unlisted_tool_unchecked_decision: Decision = Decision.ASK
    rules_enabled: dict[str, bool] = field(default_factory=lambda: {r: True for r in _RULE_IDS})
    rule_c_decision: Decision = Decision.BLOCK
    rule_c_sources: list[str] = field(default_factory=lambda: ["untrusted"])
    min_value_len: int = 3
    amount_tolerance: str = "0.01"
    max_denied_retries: int = 1
    fail_closed_scope: list[str] = field(default_factory=lambda: ["low", "sensitive", "unlisted"])
    source: str | None = None

    # ------------------------------------------------------------- lookups
    def spec(self, tool: str) -> ToolSpec:
        """Return the declared spec for ``tool``, or the unlisted default.

        An unlisted tool defaults to *sensitive* so that an omission from the
        risk table fails closed rather than silently opening a sink — the
        unlisted-tool case the case set probes empirically (ROPE assumption
        A3).
        """
        if tool in self.tools:
            return self.tools[tool]
        return ToolSpec(
            name=tool,
            risk=RiskClass.UNLISTED,
            state_changing=self.unlisted_tool_risk is RiskClass.SENSITIVE,
        )

    def risk_of(self, tool: str) -> RiskClass:
        return self.spec(tool).risk

    def effective_risk(self, tool: str) -> RiskClass:
        """Risk class used for enforcement (unlisted maps to its default)."""
        r = self.risk_of(tool)
        return self.unlisted_tool_risk if r is RiskClass.UNLISTED else r

    def rule_enabled(self, rule_id: str) -> bool:
        return bool(self.rules_enabled.get(rule_id, True))

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "unlisted_tool_risk": self.unlisted_tool_risk.value,
            "unlisted_tool_unchecked_decision": self.unlisted_tool_unchecked_decision.value,
            "rules_enabled": dict(self.rules_enabled),
            "rule_c_decision": self.rule_c_decision.value,
            "rule_c_sources": list(self.rule_c_sources),
            "min_value_len": self.min_value_len,
            "amount_tolerance": self.amount_tolerance,
            "max_denied_retries": self.max_denied_retries,
            "fail_closed_scope": list(self.fail_closed_scope),
            "tools": {
                name: {
                    "risk": s.risk.value,
                    "state_changing": s.state_changing,
                    "sensitive_params": list(s.sensitive_params),
                    "destination_params": list(s.destination_params),
                    "amount_params": list(s.amount_params),
                    "body_params": list(s.body_params),
                    "reads_sensitive": s.reads_sensitive,
                }
                for name, s in self.tools.items()
            },
            "source": self.source,
        }


def _str_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise PolicyError(f"{where}: expected a list of strings, got {type(value).__name__}")
    out = []
    for v in value:
        if not isinstance(v, str):
            raise PolicyError(f"{where}: expected strings, got {type(v).__name__}")
        out.append(v)
    return out


def _parse_tool(name: str, raw: Any) -> ToolSpec:
    if not isinstance(raw, Mapping):
        raise PolicyError(f"tools.{name}: expected a mapping, got {type(raw).__name__}")
    risk = raw.get("risk", "low")
    if risk not in _VALID_RISK:
        raise PolicyError(f"tools.{name}.risk: must be one of {sorted(_VALID_RISK)}, got {risk!r}")
    spec = ToolSpec(
        name=name,
        risk=RiskClass(risk),
        state_changing=bool(raw.get("state_changing", False)),
        sensitive_params=_str_list(raw.get("sensitive_params"), f"tools.{name}.sensitive_params"),
        destination_params=_str_list(raw.get("destination_params"), f"tools.{name}.destination_params"),
        amount_params=_str_list(raw.get("amount_params"), f"tools.{name}.amount_params"),
        body_params=_str_list(raw.get("body_params"), f"tools.{name}.body_params"),
        reads_sensitive=bool(raw.get("reads_sensitive", False)),
    )
    unknown = set(raw) - {
        "risk", "state_changing", "sensitive_params", "destination_params",
        "amount_params", "body_params", "reads_sensitive", "description",
    }
    if unknown:
        raise PolicyError(f"tools.{name}: unknown keys {sorted(unknown)}")
    return spec


def parse_policy(raw: Any, source: str | None = None) -> Policy:
    """Validate a policy mapping and return a frozen :class:`Policy`."""
    if not isinstance(raw, Mapping):
        raise PolicyError(f"policy root must be a mapping, got {type(raw).__name__}")
    if "version" not in raw:
        raise PolicyError("policy is missing the required 'version' field")
    tools_raw = raw.get("tools", {})
    if not isinstance(tools_raw, Mapping):
        raise PolicyError("'tools' must be a mapping of tool name to spec")
    tools = {name: _parse_tool(name, spec) for name, spec in tools_raw.items()}

    unlisted = raw.get("unlisted_tool_risk", "sensitive")
    if unlisted not in {"low", "sensitive"}:
        raise PolicyError("'unlisted_tool_risk' must be 'low' or 'sensitive'")

    rules_enabled = {r: True for r in _RULE_IDS}
    for key, val in (raw.get("rules_enabled") or {}).items():
        if key not in _RULE_IDS:
            raise PolicyError(f"rules_enabled: unknown rule {key!r}")
        rules_enabled[key] = bool(val)

    unchecked = raw.get("unlisted_tool_unchecked_decision", "ask")
    if unchecked not in {"allow", "block", "ask"}:
        raise PolicyError("'unlisted_tool_unchecked_decision' must be 'allow', 'block' or 'ask'")

    rule_c_decision = raw.get("rule_c_decision", "block")
    if rule_c_decision not in {"block", "ask"}:
        raise PolicyError("'rule_c_decision' must be 'block' or 'ask'")

    rule_c_sources = _str_list(raw.get("rule_c_sources", ["untrusted"]), "rule_c_sources")
    bad = set(rule_c_sources) - {"untrusted", "declared_trusted"}
    if bad:
        raise PolicyError(f"rule_c_sources: unknown trust levels {sorted(bad)}")

    try:
        min_len = int(raw.get("min_value_len", 3))
        retries = int(raw.get("max_denied_retries", 1))
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"integer policy field is not an integer: {exc}") from exc
    if min_len < 1:
        raise PolicyError("'min_value_len' must be >= 1")
    if retries < 0:
        raise PolicyError("'max_denied_retries' must be >= 0")

    scope = _str_list(raw.get("fail_closed_scope", ["low", "sensitive", "unlisted"]), "fail_closed_scope")
    bad_scope = set(scope) - _VALID_RISK
    if bad_scope:
        raise PolicyError(f"fail_closed_scope: unknown risk classes {sorted(bad_scope)}")

    return Policy(
        version=str(raw["version"]),
        tools=tools,
        unlisted_tool_risk=RiskClass(unlisted),
        unlisted_tool_unchecked_decision=Decision(unchecked),
        rules_enabled=rules_enabled,
        rule_c_decision=Decision(rule_c_decision),
        rule_c_sources=rule_c_sources,
        min_value_len=min_len,
        amount_tolerance=str(raw.get("amount_tolerance", "0.01")),
        max_denied_retries=retries,
        fail_closed_scope=scope,
        source=source,
    )


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy from a ``.json``, ``.yaml`` or ``.yml`` file."""
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"policy file not found: {p}")
    text = p.read_text(encoding="utf-8")
    try:
        if p.suffix.lower() in {".yaml", ".yml"}:
            import yaml  # imported lazily so JSON policies need no dependency

            raw = yaml.safe_load(text)
        else:
            raw = json.loads(text)
    except Exception as exc:  # malformed document -> fail closed upstream
        raise PolicyError(f"could not parse policy {p}: {exc}") from exc
    return parse_policy(raw, source=str(p))

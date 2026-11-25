"""CAGE-Guard — Composition-Aware Guard Evaluation for Agentic AI.

A runtime reference monitor that intercepts every tool call an LLM agent
proposes and returns one of three decisions: ``allow``, ``block`` or ``ask``
(FR1, FR2).  The guard is deterministic and in-process: it invokes no model,
so its decision latency is measurable independently of agent inference
(NFR1).

Public surface:

    CAGEGuard           tool-call interceptor and decision entry point
    Decision            allow / block / ask
    TrustLevel          trusted / declared_trusted / untrusted
    RiskClass           low / sensitive / unlisted
    GuardDecision       immutable decision record
    CallHistoryStore    per-run record of reads and calls
    TrustedRequest      the user request and the sources it names
    DecisionLogger      JSONL decision log (one record per intercepted call)
    load_policy         policy and tool-risk-table loader (fails closed)
    PolicyError         raised on an invalid or unloadable policy
"""

from .decisions import Decision, GuardDecision, RiskClass, TrustLevel
from .history_store import CallHistoryStore, ToolResultRecord, TrustedRequest
from .interceptor import BlockedCallError, CAGEGuard
from .logger import DecisionLogger
from .policy_loader import Policy, PolicyError, load_policy

__version__ = "1.0.0"
GUARD_VERSION = __version__

__all__ = [
    "BlockedCallError",
    "CAGEGuard",
    "CallHistoryStore",
    "Decision",
    "DecisionLogger",
    "GuardDecision",
    "Policy",
    "PolicyError",
    "RiskClass",
    "ToolResultRecord",
    "TrustLevel",
    "TrustedRequest",
    "load_policy",
    "GUARD_VERSION",
    "__version__",
]

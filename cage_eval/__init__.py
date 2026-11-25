"""CAGE-Eval — controlled evaluation harness for conditions C0-C3 (FR9-FR11).

The harness runs identical attack and benign cases under each condition,
classifies every trace into one of the five declared classes, computes the
mandated metric pairs with Wilson intervals, and exports
``metrics_summary.csv`` and ``per_case_results.json``.

Two properties are structural rather than conventional:

* **A condition whose defense is unavailable is skipped, never zero-filled.**
  Progent and ROPE integration is conditional on the compatibility pilot, so
  their adapters raise :class:`DefenseUnavailable` until a real
  implementation is supplied.  No metric is ever computed over a condition
  that did not run.
* **Security and usability metrics travel together.**  Every exported row
  carries attack success alongside utility and false denials, and
  :func:`cage_eval.metrics.assert_paired` refuses to export a table that
  breaks the pairing.
"""

from .cases import Case, CaseValidationError, load_case_file, load_cases
from .classifier import BaselineIndex, TraceClass, classify, classify_all
from .defenses import (
    CONDITIONS,
    ConditionSpec,
    DefenseUnavailable,
    build_condition,
)
from .metrics import (
    ConditionMetrics,
    Rate,
    assert_paired,
    compute_metrics,
    wilson_interval,
)
from .runner import RunResult, run_case, run_experiment

__all__ = [
    "BaselineIndex",
    "CONDITIONS",
    "Case",
    "CaseValidationError",
    "ConditionMetrics",
    "ConditionSpec",
    "DefenseUnavailable",
    "Rate",
    "RunResult",
    "TraceClass",
    "assert_paired",
    "build_condition",
    "classify",
    "classify_all",
    "compute_metrics",
    "load_case_file",
    "load_cases",
    "run_case",
    "run_experiment",
    "wilson_interval",
]

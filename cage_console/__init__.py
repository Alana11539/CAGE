"""CAGE Console — decision-inspection dashboard (FR12-FR15, D3).

The Console is **strictly a consumer**.  It reads the JSONL decision logs that
CAGE-Guard writes and the JSON results that CAGE-Eval exports, and it computes
no metric of its own: the metrics screen renders the ``metrics`` block of
``per_case_results.json`` verbatim, so it cannot disagree with CAGE-Eval
output (D3).  Nothing in this package imports the rule engine, and no result
in the paper depends on the Console.
"""

from .app import create_app
from .logs import LogStore, RunSummary

__all__ = ["LogStore", "RunSummary", "create_app"]

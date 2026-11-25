"""FastAPI application for the CAGE Console (FR12-FR15).

Endpoints
---------
``GET /``                     the dashboard (static, no build step)
``GET /api/health``           liveness plus the directories being read
``GET /api/runs``             every run found in the log directory
``GET /api/runs/{run_id}``    one run's tool-call timeline with decisions,
                              rules, reasons and ask resolutions (FR12, FR15)
``GET /api/metrics``          the metrics block of each CAGE-Eval export,
                              rendered verbatim (FR13, D3)
``GET /api/demo``             C0 and CAGE runs of the same case, paired for
                              the side-by-side demonstration (FR14)

The application holds no enforcement state and recomputes no metric.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .logs import LogStore

STATIC_DIR = Path(__file__).resolve().parent / "static"

#: Conditions that enforce the CAGE rules, for pairing in the demo view.
CAGE_CONDITION_HINTS = ("CAGE", "C3")


def create_app(
    logs_dir: str | Path = "runs",
    results_dir: str | Path = "results",
    *,
    title: str = "CAGE Console",
) -> FastAPI:
    """Build the application over a log directory and a results directory."""
    store = LogStore(logs_dir, results_dir)
    app = FastAPI(
        title=title,
        version="1.0.0",
        description="Decision-inspection dashboard for CAGE-Guard. Read-only: it "
                    "displays the JSON logs and the CAGE-Eval exports and computes "
                    "no metric of its own.",
    )
    app.state.store = store

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "logs_dir": str(store.logs_dir),
            "results_dir": str(store.results_dir) if store.results_dir else None,
            "n_log_files": len(store.log_files()),
            "n_exports": len(store.result_files()),
            "computes_metrics": False,
        }

    @app.get("/api/runs")
    def list_runs(condition: str | None = None, case_id: str | None = None,
                  split: str | None = None) -> dict[str, Any]:
        runs = store.runs()
        if condition:
            runs = [r for r in runs if r.condition == condition]
        if case_id:
            runs = [r for r in runs if r.case_id == case_id]
        if split:
            runs = [r for r in runs if r.split == split]
        return {
            "n_runs": len(runs),
            "conditions": sorted({r.condition for r in runs}),
            "cases": sorted({r.case_id for r in runs}),
            "runs": [r.to_dict() for r in runs],
        }

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        run = store.run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"no log found for run {run_id!r}")
        return run

    @app.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        exports = store.exports()
        return {
            "n_exports": len(exports),
            "source": "cage_eval exports; values are rendered verbatim and not recomputed",
            "exports": exports,
        }

    @app.get("/api/demo")
    def demo(case_id: str | None = None) -> dict[str, Any]:
        """Pair an undefended run with a guarded run of the same case (FR14)."""
        runs = store.runs()
        pairs: list[dict[str, Any]] = []
        by_case: dict[str, list[Any]] = {}
        for r in runs:
            by_case.setdefault(r.case_id, []).append(r)
        for cid, group in sorted(by_case.items()):
            if case_id and cid != case_id:
                continue
            undefended = [r for r in group if "no defense" in r.condition.lower()
                          or r.condition == "C0"]
            guarded = [r for r in group
                       if any(h.lower() in r.condition.lower() for h in CAGE_CONDITION_HINTS)]
            if undefended and guarded:
                pairs.append(
                    {
                        "case_id": cid,
                        "undefended": undefended[0].to_dict(),
                        "guarded": guarded[0].to_dict(),
                    }
                )
        return {"n_pairs": len(pairs), "pairs": pairs}

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(str(STATIC_DIR / "index.html"))
    else:  # pragma: no cover - only when the package is installed without assets
        @app.get("/")
        def index_missing() -> JSONResponse:
            return JSONResponse({"detail": "static assets not installed"}, status_code=404)

    return app


app = create_app()

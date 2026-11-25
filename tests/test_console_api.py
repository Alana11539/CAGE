"""CAGE Console API: read-only views over the logs and the CAGE-Eval exports."""

from __future__ import annotations

import json
import time

import pytest

fastapi = pytest.importorskip("fastapi")
from conftest import FIXTURES  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from cage_console import create_app  # noqa: E402
from cage_eval import load_cases, run_experiment  # noqa: E402
from cage_eval.classifier import classify_all  # noqa: E402
from cage_eval.export import write_per_case_results_json  # noqa: E402
from cage_eval.metrics import compute_metrics  # noqa: E402


@pytest.fixture(scope="module")
def console(policy, tmp_path_factory):
    """A console over a freshly generated self-test run."""
    root = tmp_path_factory.mktemp("console")
    logs, results = root / "runs", root / "results"
    cases = load_cases(FIXTURES, split="design")
    runs, skipped = run_experiment(
        cases, ["C0", "C1", "C3_cage_only"], [11], policy=policy, logs_dir=logs
    )
    traces = classify_all(runs)
    metrics = compute_metrics(runs, traces, split="design")
    write_per_case_results_json(
        runs, traces, results / "per_case_results.json", metrics=metrics,
        skipped=skipped, policy_version=policy.version,
    )
    client = TestClient(create_app(logs, results))
    return client, runs, metrics, results


def test_health_declares_the_directories_and_that_it_computes_nothing(console):
    client, runs, _, _ = console
    h = client.get("/api/health").json()
    assert h["status"] == "ok"
    assert h["n_log_files"] == len(runs)
    assert h["n_exports"] == 1
    assert h["computes_metrics"] is False


def test_runs_endpoint_summarises_every_log(console):
    client, runs, _, _ = console
    data = client.get("/api/runs").json()
    assert data["n_runs"] == len(runs)
    assert "C0 (no defense)" in data["conditions"]
    guarded = [r for r in data["runs"] if "CAGE" in r["condition"]]
    assert guarded and all(r["guard_version"] for r in guarded)
    exfil = next(r for r in guarded if r["case_id"] == "t_exfil_attacked")
    assert exfil["decision_counts"]["block"] == 1
    assert exfil["rules_fired"]["A"] == 1


def test_run_timeline_carries_decision_rule_reason_and_ask_resolution(console):
    client, runs, _, _ = console
    delegated = next(r for r in runs
                     if r.case_id == "t_delegated_benign" and r.condition == "C3_cage_only")
    run = client.get(f"/api/runs/{delegated.run_id}").json()
    step = run["timeline"][0]
    assert step["decision"] == "ask"
    assert step["rule"] == "B"
    assert step["evidence"]["class"] == "delegated_parameter"
    assert step["reason"]
    assert step["ask_resolution"]["approved"] is True
    assert run["metadata"][0]["record_type"] == "run_metadata"


def test_unknown_run_is_a_404(console):
    client, _, _, _ = console
    assert client.get("/api/runs/does-not-exist").status_code == 404


def test_metrics_endpoint_matches_the_export_byte_for_byte(console):
    client, _, metrics, results = console
    payload = client.get("/api/metrics").json()
    assert payload["n_exports"] == 1
    served = payload["exports"][0]["metrics"]
    on_disk = json.loads(
        (results / "per_case_results.json").read_text(encoding="utf-8"))["metrics"]
    assert served == on_disk
    # and it matches what CAGE-Eval computed in-process (D3)
    for cond, m in metrics.items():
        assert served[cond]["attack_success_rate_formatted"] == \
            str(m.attack_success_rate)
        assert served[cond]["false_denial_rate_task_formatted"] == \
            str(m.false_denial_rate_task)


def test_metrics_endpoint_exposes_provenance_and_skipped_conditions(console):
    client, _, _, _ = console
    prov = client.get("/api/metrics").json()["exports"][0]["provenance"]
    assert prov["is_benchmark_run"] is False
    assert [s["condition"] for s in prov["skipped_conditions"]] == ["C1"]
    assert set(prov["trace_classes"]["bookkeeping"]) == {"nominal"}


def test_demo_pairs_undefended_and_guarded_runs(console):
    client, _, _, _ = console
    demo = client.get("/api/demo").json()
    assert demo["n_pairs"] >= 1
    pair = next(p for p in demo["pairs"] if p["case_id"] == "t_exfil_attacked")
    assert pair["undefended"]["decision_counts"] == {}
    assert pair["guarded"]["decision_counts"]["block"] == 1
    one = client.get("/api/demo?case_id=t_exfil_attacked").json()
    assert one["n_pairs"] == 1


def test_dashboard_is_served(console):
    client, _, _, _ = console
    page = client.get("/")
    assert page.status_code == 200
    assert "CAGE Console" in page.text
    assert client.get("/static/app.js").status_code == 200


def test_timeline_response_is_fast_for_a_long_run(console, tmp_path):
    """NFR2 bound check: a 200-call log must not be slow to serve.

    This is a regression bound on the API, not a reported page-load measurement.
    """
    logs = tmp_path / "runs"
    logs.mkdir()
    records = [
        {"schema": "cage-log-1", "record_type": "decision", "run_id": "long", "step_index": i,
         "condition": "C3 (Progent + CAGE rules)", "case_id": "synthetic", "seed": 11,
         "tool": "send_money", "arguments": {"recipient": "DE1", "amount": i},
         "risk_class": "sensitive", "decision": "allow", "rule": None, "reason": "ok",
         "evidence": {}, "latency_ms": 0.2, "fail_closed": False,
         "guard_version": "1.0.0", "policy_version": "cage-policy-1.0.0"}
        for i in range(1, 201)
    ]
    (logs / "long.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    client = TestClient(create_app(logs, tmp_path / "results"))
    start = time.perf_counter()
    run = client.get("/api/runs/long").json()
    elapsed = time.perf_counter() - start
    assert len(run["timeline"]) == 200
    assert elapsed < 3.0


def test_truncated_final_line_does_not_break_a_run_view(console, tmp_path):
    logs = tmp_path / "runs2"
    logs.mkdir()
    good = {"schema": "cage-log-1", "record_type": "decision", "run_id": "partial",
            "condition": "C0 (no defense)", "case_id": "c", "seed": 1, "step_index": 1,
            "tool": "read_file", "arguments": {}, "risk_class": "low", "decision": "allow",
            "rule": None, "reason": "", "evidence": {}, "latency_ms": 0.1,
            "fail_closed": False}
    (logs / "partial.jsonl").write_text(
        json.dumps(good) + "\n" + '{"record_type": "decis', encoding="utf-8")
    client = TestClient(create_app(logs, tmp_path / "results"))
    assert len(client.get("/api/runs/partial").json()["timeline"]) == 1

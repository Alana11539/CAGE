"use strict";
// CAGE Console front end. No build step, no framework, no computation:
// every number shown here is read from the API, which reads the logs and the
// CAGE-Eval exports.

const api = (path) => fetch(path).then((r) => {
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
});

const el = (id) => document.getElementById(id);
const fmt = (v) => (v === null || v === undefined || v === "" ? "\u2014" : v);

function show(view) {
  document.querySelectorAll(".view").forEach((s) => s.classList.add("hidden"));
  el("view-" + view).classList.remove("hidden");
  document.querySelectorAll("nav button").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === view));
  if (view === "timeline") loadTimelineOptions();
  if (view === "metrics") loadMetrics();
  if (view === "demo") loadDemo();
}

document.querySelectorAll("nav button").forEach((b) =>
  b.addEventListener("click", () => show(b.dataset.view)));

let RUNS = [];

async function loadHealth() {
  const h = await api("/api/health");
  el("health").textContent =
    `logs: ${h.logs_dir} (${h.n_log_files} files) \u00b7 results: ${h.results_dir} ` +
    `(${h.n_exports} exports) \u00b7 console computes metrics: ${h.computes_metrics}`;
}

async function loadRuns() {
  const data = await api("/api/runs");
  RUNS = data.runs;
  const conds = el("filter-condition"), cases = el("filter-case");
  conds.innerHTML = '<option value="">all</option>' +
    data.conditions.map((c) => `<option>${c}</option>`).join("");
  cases.innerHTML = '<option value="">all</option>' +
    data.cases.map((c) => `<option>${c}</option>`).join("");
  renderRuns();
}

function renderRuns() {
  const cond = el("filter-condition").value, cse = el("filter-case").value;
  const rows = RUNS.filter((r) => (!cond || r.condition === cond) &&
                                  (!cse || r.case_id === cse));
  el("runs-table").querySelector("tbody").innerHTML = rows.map((r) => {
    const d = r.decision_counts || {};
    const rules = Object.entries(r.rules_fired || {})
      .map(([k, v]) => `<span class="badge rule">${k}\u00d7${v}</span>`).join(" ");
    return `<tr data-run="${r.run_id}">
      <td>${r.run_id}</td><td>${r.condition}</td><td>${r.case_id}</td>
      <td>${fmt(r.seed)}</td><td>${r.n_decisions}</td>
      <td>${d.allow || 0}</td><td>${d.block || 0}</td><td>${d.ask || 0}</td>
      <td>${r.asks_approved}</td><td>${r.asks_denied}</td>
      <td>${rules || "\u2014"}</td>
      <td>${r.fail_closed_events ? '<span class="warn">' + r.fail_closed_events +
          "</span>" : 0}</td></tr>`;
  }).join("");
  el("runs-table").querySelectorAll("tr[data-run]").forEach((tr) =>
    tr.addEventListener("click", () => {
      el("timeline-run").value = tr.dataset.run;
      show("timeline");
      loadTimeline(tr.dataset.run);
    }));
}

el("filter-condition").addEventListener("change", renderRuns);
el("filter-case").addEventListener("change", renderRuns);

function loadTimelineOptions() {
  const sel = el("timeline-run");
  const current = sel.value;
  sel.innerHTML = RUNS.map((r) => `<option>${r.run_id}</option>`).join("");
  if (current) sel.value = current;
  if (sel.value) loadTimeline(sel.value);
}
el("timeline-run").addEventListener("change", (e) => loadTimeline(e.target.value));

async function loadTimeline(runId) {
  if (!runId) return;
  const run = await api("/api/runs/" + encodeURIComponent(runId));
  el("timeline").innerHTML = run.timeline.map((s, i) => {
    const ask = s.ask_resolution
      ? `<span class="badge ${s.ask_resolution.approved ? "allow" : "block"}">user ${
          s.ask_resolution.approved ? "approved" : "declined"}</span>` : "";
    return `<div class="step ${s.decision}" data-i="${i}">
      <h4>step ${fmt(s.step_index)} &middot; ${s.tool}
        <span class="badge ${s.decision}">${s.decision}</span>
        ${s.rule ? `<span class="badge rule">rule ${s.rule}</span>` : ""}
        ${ask}
        <span class="badge rule">${Number(s.latency_ms).toFixed(3)} ms</span></h4>
      <div class="reason">${fmt(s.reason)}</div></div>`;
  }).join("") || "<p class='note'>No decisions in this log.</p>";
  el("decision-detail").textContent = JSON.stringify(run.metadata, null, 2);
  el("timeline").querySelectorAll(".step").forEach((d) =>
    d.addEventListener("click", () => {
      el("decision-detail").textContent =
        JSON.stringify(run.timeline[Number(d.dataset.i)], null, 2);
    }));
}

const RATES = [
  ["attack_success_rate", "Attack success"],
  ["clean_task_utility", "Clean utility"],
  ["utility_under_attack", "Utility under attack"],
  ["false_denial_rate_task", "False denial (task)"],
  ["false_denial_rate_call", "False denial (call)"],
  ["false_denial_rate_file_only", "False denial (file-only)"],
  ["prevention_rate", "Prevention"],
  ["ask_rate", "Ask rate"],
  ["ask_recovery_rate", "Ask recovery"],
  ["confirmation_attributable_attack_success", "Confirmation-attributable success"],
];

async function loadMetrics() {
  const data = await api("/api/metrics");
  if (!data.n_exports) {
    el("metrics-tables").innerHTML =
      "<p class='note'>No CAGE-Eval export found. Run <code>python scripts/selftest_eval.py</code>" +
      " or an experiment first.</p>";
    el("metrics-provenance").innerHTML = "";
    return;
  }
  const e = data.exports[0];
  const p = e.provenance || {};
  const tc = p.trace_classes || {};
  el("metrics-provenance").innerHTML = `<div class="prov">
    <strong>${e.name}</strong> &middot; generated ${fmt(p.generated)} &middot;
    policy ${fmt(p.policy_version)}<br/>
    agent ${JSON.stringify(p.agent)} &middot; environment ${JSON.stringify(p.environment)} &middot;
    <strong class="${p.is_benchmark_run ? "" : "warn"}">is_benchmark_run:
      ${String(p.is_benchmark_run)}</strong><br/>
    ${(p.skipped_conditions || []).length
      ? "skipped conditions: " + p.skipped_conditions.map((s) => s.condition).join(", ")
      : "no conditions skipped"}<br/>
    ${tc.declared ? "declared classes " + JSON.stringify(tc.declared) +
      " &middot; bookkeeping " + JSON.stringify(tc.bookkeeping) : ""}
  </div>`;
  const metrics = e.metrics || {};
  const conds = Object.keys(metrics);
  el("metrics-tables").innerHTML = `<table><thead><tr><th>metric</th>${
    conds.map((c) => `<th>${metrics[c].condition_label || c}</th>`).join("")
  }</tr></thead><tbody>${
    RATES.map(([key, label]) => `<tr><td>${label}</td>${conds.map((c) => {
      const row = metrics[c];
      const lo = row[key + "_ci95_low"], hi = row[key + "_ci95_high"];
      const ci = (lo === null || lo === undefined || lo === "")
        ? "" : `<br/><span class="reason">95% CI ${lo}\u2013${hi}%</span>`;
      return `<td>${fmt(row[key + "_formatted"])}${ci}</td>`;
    }).join("")}</tr>`).join("")
  }<tr><td>Guard latency mean / p95 (ms)</td>${conds.map((c) => {
      const r = metrics[c];
      return `<td>${fmt(r.guard_latency_mean_ms)} / ${fmt(r.guard_latency_p95_ms)}
        <br/><span class="reason">n=${fmt(r.guard_decisions_measured)} decisions</span></td>`;
    }).join("")}</tr>
    <tr><td>End-to-end mean (s) / overhead vs C0</td>${conds.map((c) => {
      const r = metrics[c];
      return `<td>${fmt(r.end_to_end_mean_s)} / ${fmt(r.runtime_overhead_vs_c0)}</td>`;
    }).join("")}</tr>
    <tr><td>Model calls / tokens</td>${conds.map((c) => {
      const r = metrics[c];
      return `<td>${fmt(r.model_calls_total)} / ${fmt(r.tokens_total)}</td>`;
    }).join("")}</tr>
    <tr><td>Nominal (bookkeeping, not reported)</td>${conds.map((c) =>
      `<td>${fmt(metrics[c].class_nominal)}</td>`).join("")}</tr></tbody></table>`;
}

async function loadDemo() {
  const data = await api("/api/demo");
  el("demo-pairs").innerHTML = data.n_pairs ? data.pairs.map((p) => {
    const card = (r, title) => {
      const d = r.decision_counts || {};
      return `<div class="card"><h4>${title}</h4>
        <div class="reason">${r.condition} &middot; run ${r.run_id}</div>
        <p>allow ${d.allow || 0} &middot;
           <span class="badge block">block ${d.block || 0}</span> &middot;
           <span class="badge ask">ask ${d.ask || 0}</span></p>
        <p class="reason">rules fired: ${
          Object.entries(r.rules_fired || {}).map(([k, v]) => k + "\u00d7" + v).join(", ")
          || "none"}</p></div>`;
    };
    return `<h3>${p.case_id}</h3><div class="pair">
      ${card(p.undefended, "No defense")}${card(p.guarded, "CAGE rules")}</div>`;
  }).join("") : "<p class='note'>No paired runs found yet.</p>";
}

loadHealth().then(loadRuns).catch((e) => {
  el("health").textContent = "API unavailable: " + e.message;
});

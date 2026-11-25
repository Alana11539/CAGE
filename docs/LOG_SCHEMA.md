# Log and export schemas

Logs are the single source of truth: CAGE-Eval computes every metric from them
and the Console displays them. Both are append-only JSON Lines, so a run that
is interrupted leaves a parseable file.

## Decision log — `runs/<run_id>.jsonl`

Every record carries `schema`, `timestamp`, `guard_version`, `policy_version`
and the run context (`run_id`, `condition`, `case_id`, `seed`, `model_id`, plus
any extra context fields such as `split`, `family`, `attacked`, `agent`,
`environment`).

### `record_type: "decision"` — one per intercepted call

| Field | Meaning |
|---|---|
| `step_index` | position of the call in the run (reads and calls share the counter) |
| `tool` | tool name as proposed by the agent |
| `arguments` | the intercepted arguments, verbatim |
| `risk_class` | `low` / `sensitive` / `unlisted` from the tool-risk table |
| `decision` | `allow` / `block` / `ask` |
| `rule` | `A`, `B`, `C`, `A3` (unlisted tool), `B2` (retry budget), `NFR3` (fail-closed), or `null` |
| `reason` | human-readable justification, shown in the Console |
| `matched_param` | the parameter the decision turned on |
| `evidence` | machine-readable grounds: origins and their trust levels, the matched value prefix, the destination, `class` (e.g. `delegated_parameter`, `unlisted_tool`), `heuristic`, `matching` |
| `latency_ms` | guard decision latency, excluding all model time |
| `fail_closed` | `true` when the decision came from the fail-closed path |

### `record_type: "ask_resolution"`

`step_index` (joins to the decision), `tool`, `approved`, `resolver`, `reason`.
Kept distinct from the decision because an approved ask on a benign case is a
recovered task, while an approved ask on an attacked case is a
**confirmation-attributable attack success**.

### `record_type: "run_metadata"`

`metadata` holds the agent, environment adapter, condition label, seed, status
and policy version recorded at the end of the run (NFR4).

## Case documents — `cases/<split>/*.json`

`case_id`, `template_id`, `split`, `family`, `suite`, `attacked`, `file_only`,
`user_request`, `named_sources`, `trusted_records`, `tool_results[]`
(`tool`, `source_id`, `content`, `values`, `sensitive`, `trust`), `script[]`
(`tool`, `args`, `retry_on_block`), `success_criterion`, `attacker_goal`,
`expected_decision`, `ask_oracle`, `notes`. Criteria are matched with the
guard's own value semantics, so a scoring rule and an enforcement rule cannot
disagree about whether two values are the same.

## Exports — `results/**/`

`metrics_summary.csv` — one row per condition. Each rate contributes six
columns: `_n`, `_d`, `_pct`, `_ci95_low`, `_ci95_high`, `_formatted`. Class
counts (`class_prevention` … `class_invalid_run`, plus `class_nominal`),
latency, end-to-end time, overhead, model calls, tokens, fail-closed events and
the agent / environment labels follow. A sidecar
`*_skipped_conditions.csv` lists any condition that could not be run.

`per_case_results.json` — `provenance` (schema, generation time, policy
version, agent, environment, `is_benchmark_run`, skipped conditions, and a
`trace_classes` block separating the five declared classes from the `nominal`
bookkeeping count), `metrics` (the exported rows), and `runs` (every run with
its classification and rationale).

`per_case_results.csv` — one row per run, so every aggregate can be traced to
the cases that produced it (D6).

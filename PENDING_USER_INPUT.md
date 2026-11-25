# Pending user input

Every item the project cannot supply for itself, in one table. Nothing here
is invented, estimated, or filled with a placeholder that could be mistaken
for a real value. `scripts/check_gate.py` is the authority on what blocks the
main experimental runs; this file explains each item and where it is used.

**Gate status at the time of writing:** `python scripts/check_gate.py` exits 1
with **8 blocking items**. Case-set checks pass: 24 cases, 12 design / 12
held-out, no template leakage, all bound to verified base tasks.

## Blocking the main experimental runs

| # | Missing value | Why it is required | Where it is used | Blocks runs |
|---|---|---|---|---|
| 1 | `configuration_gate.agent_model.revision` — the exact Hugging Face revision hash for `Qwen/Qwen2.5-7B-Instruct` | A model name without a revision does not identify the weights; NFR4 reproducibility and the paper's methodology section both need it | `config/experiment_config.yaml`; stamped into every run's `run_metadata`; Methodology §4 | Yes |
| 2 | `configuration_gate.benchmark.commit` — the AgentDojo commit to pin | Results are only reproducible against a fixed benchmark revision | `config/experiment_config.yaml`; `scripts/reproduce_all.sh`; Methodology §4 | Yes |
| 3 | `configuration_gate.benchmark.task_ids` — which tasks are in scope | Defines the evaluated population and therefore every denominator | Case bindings; Methodology §4; Results denominators | Yes |
| 4 | `configuration_gate.defenses.progent.commit` | C1 and C3 are Progent conditions; without the commit neither is reproducible, and C3 cannot be built at all | `cage_eval/defenses.py` registration; Methodology §4 | Yes |
| 5 | `configuration_gate.defenses.rope.repository` and `.commit` | Determines whether C2 is ROPE or the strictly-labelled `C2 (ROPE-inspired)` fallback | Condition registry; every table, caption and sentence that names C2 | Yes |
| 6 | `configuration_gate.adjudication.primary_coder` — the named team member who codes traces | The adjudication protocol requires a named primary coder, 20% double coding and a reported Cohen's kappa | Methodology §4; CRediT statement | Yes |
| 7 | `configuration_gate.ethics.departmental_approval_status` | The paper needs one factual line on approval status; it cannot be written from the project's own assumptions | Ethics statement; Methodology §4 | Yes |

(Items 5 counts as two keys in `check_gate.py`, which is why it reports eight.)

### Information already gathered, awaiting your decision

These were read from the AgentDojo repository on 25 November 2026 and are
offered as **candidates**; none has been written into the configuration as an
approved pin.

| Value | What was read | Where it already appears |
|---|---|---|
| Commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | the repository state the tool names, parameter names, task identifiers and attacker constants were read from | `policies/default_policy.json` → `benchmark_provenance.commit_read`; every case's `benchmark.commit_read`; `cases/schemas/agentdojo_task_ids.json` |
| Latest release tag `v0.1.35` (`a75aba7631`) | the most recent tagged release, if you prefer pinning a release over a commit | nowhere yet — offered for item 2 |
| 16 banking user tasks, 9 banking injection tasks, 17 Slack user tasks, 5 Slack injection tasks | the task identifier inventory | `cases/schemas/agentdojo_task_ids.json`; each case binds to one base task |
| 22 registered tools across the two suites, with verified parameter names | the suites' own `TOOLS` lists and function signatures | `policies/default_policy.json` v1.1.0 |

## Blocking archival and the manuscript, but not the runs

| # | Missing value | Why it is required | Where it is used | Blocks runs |
|---|---|---|---|---|
| 8 | ~~GitHub organisation / repository URL~~ **RESOLVED 25 Nov 2026**: https://github.com/Alana11539/CAGE (verified against the GitHub API: public, default branch `main`) | — | `CITATION.cff`, `README.md`, `docs/ZENODO_ARCHIVAL.md`, `cases/schemas/case.schema.json` | No |
| 9 | Zenodo **Version DOI** for release v1.0.0 | The Data and Code Availability statement must cite the version DOI, not the concept DOI | `CITATION.cff`; manuscript back matter | No |
| 10 | Corresponding author and institutional e-mail | Elsevier submission requires one | Manuscript title page | No |
| 11 | CRediT role allocation per author | The CRediT statement must reflect who did what | Manuscript back matter | No |
| 12 | Ethics approval reference number, if one was issued | Cited alongside the approval status | Ethics statement | No |

## What happens when you supply them

1. The values go into `config/experiment_config.yaml` with a `change_log`
   entry recording the version bump, the date and who approved it — the same
   audit trail used for approved deviation D-1.
2. `python scripts/check_gate.py` must exit 0; `scripts/reproduce_all.sh`
   then proceeds past the gate instead of stopping.
3. Progent and ROPE adapters are registered in `cage_eval/defenses.py`; until
   a defense is registered its condition is skipped with a reason rather than
   zero-filled.
4. The 24 cases are re-bound to the pinned commit, and the held-out split is
   executed for the first time.
5. The manuscript's Results section is written from the exported
   `metrics_summary.csv` and `per_case_results.json`, replacing the sections
   currently marked PENDING.

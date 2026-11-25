# CAGE v1.0.0 — release notes (prepared, not published)

**Status: draft. Do not publish until the repository contents have been
reviewed and publication is approved.** Publishing this release is also the
event Zenodo archives, so the Zenodo integration must be switched on *before*
it is published (see `docs/ZENODO_ARCHIVAL.md`).

CAGE (Composition-Aware Guard Evaluation for Agentic AI) is a runtime
reference monitor and controlled-evaluation harness for tool-calling LLM
agents.

## What this release contains

- **CAGE-Guard** — a deterministic in-process guard that intercepts every
  proposed tool call and returns `allow`, `block` or `ask`. Rule A tracks
  sensitive reads to unauthorised sinks, Rule B checks sensitive arguments and
  routes single-origin delegated parameters from user-named sources to human
  confirmation, Rule C inspects outgoing message bodies. Value matching is
  whole-value with token-boundary handling. An invalid policy or a runtime
  fault fails closed.
- **CAGE-Eval** — a condition runner (C0–C3), a five-class trace classifier
  with C0 baseline subtraction and an approved `nominal` bookkeeping class,
  paired security/usability metrics with Wilson intervals, and CSV/JSON
  exports with a provenance block.
- **CAGE Console** — a read-only FastAPI dashboard over the JSON decision logs
  and the exported metrics; it recomputes nothing.
- **Case set** — 24 cases, 12 design / 12 held-out, partitioned by attack
  template: 14 attack templates across Rules A, B and C, 5 benign
  delegated-parameter tasks, 1 verified-value control, 2 benign linked-body
  cases and 2 unlisted-tool cases. Every case is constructed by the authors
  against a named AgentDojo base task and records the repository and commit
  the identifier was read from.
- **Reproduction package** — frozen configuration with a change log, verified
  tool-risk policy, Docker and compose definitions, GitHub Actions CI,
  configuration-gate check, guard probes, pipeline self-test, secret scan,
  manuscript builder, and the documentation set.

## Verification performed on this tree

| Check | Result |
|---|---|
| Unit tests | 141 passed, 0 failed |
| Coverage (`cage_guard`, `cage_eval`, `cage_console`) | 91.62%, 80% gate enforced |
| Lint (`ruff`) | clean |
| Guard behavioural probes | 18/18 checks passed |
| Pipeline self-test | completed; exports stamped `is_benchmark_run: false` |
| Secret scan | 141 files, 0 findings |
| Design-case expected decisions | 12/12 matched observed guard behaviour |

Not executed in the preparation environment, and therefore not claimed: the
Docker image build and the GitHub Actions workflow run. Both are defined in
this release and run on first use.

## What this release does **not** contain

- **No experimental results.** The configuration gate is closed on eight items
  (model revision, benchmark commit and task IDs, Progent commit, ROPE
  repository and commit, primary trace coder, ethics approval status), so no
  benchmark run has been executed. The only exports present are synthetic
  pipeline self-test outputs, labelled as such.
- **No Zenodo DOI.** None has been minted; no DOI is cited anywhere.
- **No published manuscript results.** The manuscript draft carries its
  Results section as explicit PENDING table skeletons.

## Approved amendments

Deviation **D-1** (a sixth, non-reportable `nominal` trace class) was approved
on 25 November 2026 under five conditions and is recorded in
`config/experiment_config.yaml` v1.1.0 with a change-log entry, and in
`docs/DEVIATIONS.md`. The five required adjudication classes are unchanged.

## Licence and citation

Apache-2.0 (`LICENSE`, `NOTICE`). Cite via `CITATION.cff`; the software
citation in the manuscript is reference [21] and its DOI line is filled only
once the Zenodo Version DOI exists.

# Archiving release v1.0.0 on Zenodo

The manuscript's Data and Code Availability statement must cite a **Version
DOI** (the one that resolves to this exact release), not the concept DOI that
resolves to "the latest version".

## Before tagging

1. `bash scripts/reproduce_all.sh` completes: tests, guard probes and the
   pipeline self-test all pass.
2. `git ls-files | grep -E '(^|/)(\.env|.*\.key|.*\.pem)$'` returns nothing,
   and `.gitignore` still excludes `.env*`, `*.key`, `*.pem`, `secrets/` and
   `config/local_*.yaml`. The CI `secrets` job enforces this.
3. `git status` is clean and `runs/` and `results/` contain nothing that is
   mislabelled: any file produced by the scripted agent must carry
   `is_benchmark_run: false`.
4. `config/experiment_config.yaml` records every amendment in its `change_log`,
   and `docs/DEVIATIONS.md` lists every declared departure with its approval.
5. `CITATION.cff` carries the repository URL (https://github.com/Alana11539/CAGE),
   the author list, and `version: "1.0.0"`. Verified 25 November 2026: the
   repository exists, is public, and its default branch is `main`.

## Linking GitHub to Zenodo

1. Sign in to <https://zenodo.org> with the GitHub account that owns the
   repository and authorise the Zenodo GitHub integration.
2. In Zenodo, open **GitHub** → find the repository → switch the toggle **On**.
   Zenodo archives releases created *after* the toggle is enabled, so enable it
   before tagging.
3. Tag and publish the release:

   ```bash
   git tag -a v1.0.0 -m "CAGE v1.0.0 - guard, evaluation harness and console"
   git push origin v1.0.0
   ```

   Then publish a GitHub Release for the tag (Zenodo responds to the release
   event, not to the bare tag).
4. Zenodo creates a deposition and mints two DOIs: a **concept DOI** for all
   versions and a **Version DOI** for v1.0.0. Record the Version DOI.
5. Check the deposition metadata against `CITATION.cff` — Zenodo reads it, but
   verify the author order, affiliations, licence (Apache-2.0) and title.

## After minting

1. Uncomment and fill the `doi:` line in `CITATION.cff` with the Version DOI
   and commit it (this commit is intentionally *after* the archived release; it
   changes no code).
2. Add the DOI badge to `README.md`.
3. Use the Version DOI in the manuscript's Data and Code Availability
   statement, alongside the GitHub release tag `v1.0.0`, the Docker setup, the
   case templates and the raw JSON logs.

## What is not archived here

The agent model weights, the AgentDojo benchmark, Progent and ROPE are not
redistributed; the archive records their pinned commits and setup instructions
only, under `config/experiment_config.yaml`.

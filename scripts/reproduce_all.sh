#!/usr/bin/env bash
# Reproduce every artefact this repository can currently produce.
#
# Order matters: the configuration gate is checked first, and the main
# experimental runs are reached only when every blocking identifier and the
# ethics approval status have been supplied. Until then the script completes
# the unit tests, the guard probes and the pipeline self-test, and stops.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. unit tests =============================================="
python -m pytest -q

echo "== 2. guard behavioural probes ================================"
python scripts/verify_guard_core.py

echo "== 3. pipeline self-test (synthetic, not an experiment) ======="
python scripts/selftest_eval.py

echo "== 4. configuration gate ======================================"
if python scripts/check_gate.py; then
  echo "== 5. main experimental runs =================================="
  echo "Gate open. Register the Progent and ROPE adapters, then run:"
  echo "  python -m cage_eval.runner --config config/experiment_config.yaml"
  echo "(the CLI entry point lands with the AgentDojo adapter)"
else
  echo
  echo "Gate closed: the main experimental runs are intentionally not started."
  echo "Resolve the PENDING items in config/experiment_config.yaml first."
  exit 0
fi

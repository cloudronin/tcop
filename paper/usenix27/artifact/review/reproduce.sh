#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$script_dir/../scripts/paperlib.py" ]; then
  paper_dir="$(cd "$script_dir/.." && pwd)"
elif [ -f "$script_dir/../../scripts/paperlib.py" ]; then
  paper_dir="$(cd "$script_dir/../.." && pwd)"
else
  echo "this compact reviewer package requires the accompanying TCOP source-and-artifact archive" >&2
  exit 2
fi
cd "$paper_dir"

run_tier_zero() {
  python3 scripts/verify_sources.py
  python3 scripts/extract_results.py
  python3 scripts/paperlib.py inventory
  python3 scripts/generate_macros.py
  python3 scripts/generate_tables.py
  MPLCONFIGDIR=.matplotlib-cache python3 scripts/generate_figures.py
  scripts/build_paper.sh
  python3 scripts/verify_claims.py
  python3 scripts/verify_manuscript_numbers.py
  python3 scripts/verify_anonymity.py
}

if [ "$#" -eq 0 ]; then
  arg=default
else
  arg="$1"
fi

case "$arg" in
  --verify-only)
    run_tier_zero
    ;;
  --deterministic)
    python3 scripts/paperlib.py reproduce --deterministic
    ;;
  --agent-replay)
    python3 scripts/paperlib.py reproduce
    ;;
  --gateway-smoke)
    if [ -z "${TCOP_GATEWAY_SOURCE:-}" ]; then
      echo "set TCOP_GATEWAY_SOURCE to the pinned reference-gateway Git checkout" >&2
      exit 2
    fi
    PYTHONPATH=../../src python3 -m tcop.cli study agent gateway verify --source "$TCOP_GATEWAY_SOURCE" --format json
    ;;
  --all-no-credentials|default)
    run_tier_zero
    python3 scripts/paperlib.py reproduce --deterministic
    python3 scripts/paperlib.py reproduce
    ;;
  *)
    echo "usage: reproduce.sh [--verify-only|--deterministic|--agent-replay|--gateway-smoke|--all-no-credentials]" >&2
    exit 2
    ;;
esac

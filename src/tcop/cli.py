"""Small CLI for validating the deterministic TCF milestone."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .benchmark import BASELINES, SCENARIO_BY_ID, SCENARIOS, BenchmarkRunner, verify


def main() -> None:
    parser = argparse.ArgumentParser(prog="tcop")
    commands = parser.add_subparsers(dest="command", required=True)
    benchmark = commands.add_parser("benchmark", help="run deterministic benchmark scenarios")
    benchmark.add_argument("--scenario", choices=sorted(SCENARIO_BY_ID))
    benchmark.add_argument("--all", action="store_true")
    benchmark.add_argument("--baseline", choices=BASELINES, default="tcx")
    benchmark.add_argument("--seed", type=int, default=42)
    benchmark.add_argument("--output", type=Path, default=Path("artifacts/benchmark"))
    verify_parser = commands.add_parser("verify", help="run all benchmark baselines and reproducibility check")
    verify_parser.add_argument("--output", type=Path, default=Path("artifacts/verify"))
    verify_parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.command == "verify":
        print(json.dumps(verify(args.output, seed=args.seed), indent=2, sort_keys=True))
        return
    identifiers = [scenario.scenario_id for scenario in SCENARIOS] if args.all else [args.scenario]
    if not all(identifiers):
        parser.error("provide --scenario or --all")
    runner = BenchmarkRunner()
    summaries = [runner.run(identifier, baseline=args.baseline, seed=args.seed, output=args.output) for identifier in identifiers]
    print(json.dumps(summaries, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()


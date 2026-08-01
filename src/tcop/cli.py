"""Small CLI for validating the deterministic TCF milestone."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .benchmark import BASELINES, SCENARIO_BY_ID, SCENARIOS, BenchmarkRunner, verify
from .experiments import run_deterministic_experiments
from .regression import run_v01_regression
from .witness_benchmark import WITNESS_BASELINES, WITNESS_SCENARIO_BY_ID, WITNESS_SCENARIOS, WitnessBenchmarkRunner, run_witness_experiments, run_witness_suite


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
    experiments = commands.add_parser("experiments", help="run deterministic timing, topology, and failure-mode sweeps")
    experiments.add_argument("--output", type=Path, default=Path("artifacts/experiments"))
    regression = commands.add_parser("regression", help="reproduce the frozen v0.1 deterministic corpus")
    regression.add_argument("--output", type=Path, default=Path("artifacts/regression-v0.1"))
    witness = commands.add_parser("witness", help="run the deterministic v0.2 witness and patrol suite")
    witness.add_argument("--scenario", choices=sorted(WITNESS_SCENARIO_BY_ID))
    witness.add_argument("--all", action="store_true")
    witness.add_argument("--baseline", choices=WITNESS_BASELINES)
    witness.add_argument("--output", type=Path, default=Path("artifacts/witness-v0.2"))
    witness.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.command == "verify":
        print(json.dumps(verify(args.output, seed=args.seed), indent=2, sort_keys=True))
        return
    if args.command == "experiments":
        result = run_deterministic_experiments(args.output)
        print(json.dumps({"summary": result["summary"], "architecture_controls": result["architecture_controls"]}, indent=2, sort_keys=True))
        return
    if args.command == "regression":
        print(json.dumps(run_v01_regression(args.output), indent=2, sort_keys=True))
        return
    if args.command == "witness":
        if args.scenario:
            baselines = [args.baseline] if args.baseline else list(WITNESS_BASELINES)
            runner = WitnessBenchmarkRunner()
            summaries = [runner.run(args.scenario, baseline=baseline, output=args.output, seed=args.seed) for baseline in baselines]
            print(json.dumps(summaries, indent=2, sort_keys=True))
            return
        if args.all:
            result = run_witness_suite(args.output, seed=args.seed)
            result["experiments"] = run_witness_experiments(args.output / "experiments")
            print(json.dumps({"runs": result["runs"], "same_seed_digest": result["same_seed_digest"]}, indent=2, sort_keys=True))
            return
        result = run_witness_suite(args.output, seed=args.seed)
        result["experiments"] = run_witness_experiments(args.output / "experiments")
        print(json.dumps({"runs": result["runs"], "same_seed_digest": result["same_seed_digest"]}, indent=2, sort_keys=True))
        return
    identifiers = [scenario.scenario_id for scenario in SCENARIOS] if args.all else [args.scenario]
    if not all(identifiers):
        parser.error("provide --scenario or --all")
    runner = BenchmarkRunner()
    summaries = [runner.run(identifier, baseline=args.baseline, seed=args.seed, output=args.output) for identifier in identifiers]
    print(json.dumps(summaries, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

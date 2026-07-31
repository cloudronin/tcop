"""Deterministic aggregation of TCBench summary records."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

BASELINE_ORDER = ("no_runtime_defense", "policy_only", "local_only", "central_monitor", "tcx")


def write_analysis(output: Path, summaries: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [dict(summary) for summary in summaries]
    by_scenario: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    by_baseline: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_scenario[row["scenario_id"]][row["baseline"]] = row
        by_baseline[row["baseline"]].append(row)

    aggregates: dict[str, dict[str, float]] = {}
    for baseline, records in by_baseline.items():
        attack_records = [record for record in records if record["scenario_id"] != "B-001"]
        aggregates[baseline] = {
            "mean_attack_success_rate": _mean(record["metrics"]["attack_success_rate"] for record in attack_records),
            "mean_false_containment_rate": _mean(record["metrics"]["false_containment_rate"] for record in records),
            "mean_cross_domain_blast_radius": _mean(record["metrics"]["cross_domain_blast_radius"] for record in attack_records),
            "mean_protocol_overhead_events": _mean(record["metrics"]["protocol_overhead_events"] for record in records),
        }

    result = {
        "analysis_version": "0.1",
        "runs": len(rows),
        "by_scenario": by_scenario,
        "by_baseline": aggregates,
        "interpretation": "Deterministic synthetic reference results; not a claim of production security efficacy.",
    }
    (output / "benchmark-analysis.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "benchmark-report.md").write_text(_markdown_report(by_scenario, aggregates), encoding="utf-8")
    return result


def _markdown_report(
    by_scenario: Mapping[str, Mapping[str, Mapping[str, Any]]], aggregates: Mapping[str, Mapping[str, float]]
) -> str:
    lines = [
        "# Deterministic TCBench v0.1 Results",
        "",
        "This report is generated from the deterministic synthetic reference harness. It verifies mechanism behavior; it does not establish real-world security efficacy.",
        "",
        "## Scenario outcome matrix",
        "",
        "Each cell is `ASR / CBR / accepted observations`.",
        "",
        "| Scenario | No runtime | Policy only | Local only | Central monitor | TCX |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for scenario_id in sorted(by_scenario):
        cells = []
        for baseline in BASELINE_ORDER:
            record = by_scenario[scenario_id].get(baseline)
            if not record:
                cells.append("—")
                continue
            metrics = record["metrics"]
            cells.append(
                f"{metrics['attack_success_rate']:.1f} / {metrics['cross_domain_blast_radius']} / {metrics['protocol_accepted']}"
            )
        lines.append(f"| {scenario_id} | " + " | ".join(cells) + " |")
    lines.extend(
        [
            "",
            "## Aggregate synthetic indicators",
            "",
            "| Baseline | Mean ASR | Mean false containment | Mean CBR | Mean protocol events |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for baseline in BASELINE_ORDER:
        values = aggregates[baseline]
        lines.append(
            f"| {baseline} | {values['mean_attack_success_rate']:.3f} | "
            f"{values['mean_false_containment_rate']:.3f} | {values['mean_cross_domain_blast_radius']:.3f} | "
            f"{values['mean_protocol_overhead_events']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation guardrail",
            "",
            "The matrix is intentionally deterministic and scenario-authored. Its proper use is regression detection, conformance evidence, and comparison of controlled mechanism changes—not a security-performance claim for live autonomous systems.",
        ]
    )
    return "\n".join(lines) + "\n"


def _mean(values: Iterable[float]) -> float:
    numbers = list(values)
    return sum(numbers) / len(numbers) if numbers else 0.0


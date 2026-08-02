"""The singular operational and research command-line interface for TCOP."""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from .agent_eval.plan import STUDY_PLAN as AGENT_STUDY_PLAN
from .agent_eval.runner import AgentStudy, SELECTIONS as AGENT_SELECTIONS
from .agent_eval.local_api import LocalAuthorizationEndpoint, serve_local_authorization
from .agent_eval.origin_api import serve_origin_federation
from .agent_eval.gateway_candidate import build_gateway_image, verify_gateway_source
from .agent_eval.live_stack import probe_reference_gateway
from .agent_eval.tool_service import serve_synthetic_mcp_tool_service
from .agent_eval.trace_replay import create_fixture, receiver_for_fixture, scripted_trace
from .benchmark import BASELINES, SCENARIO_BY_ID, SCENARIOS, BenchmarkRunner, verify
from .cli_artifact import compare_artifacts, inspect_artifact, verify_artifact
from .cli_context import create_context, inspect_context, relay_context, sign_context, verify_context, verify_receipt
from .cli_strategy import certify_strategies, inspect_strategy, list_strategies, verify_strategy
from .cli_support import (
    EXIT_ARTIFACT,
    EXIT_FROZEN_INPUT,
    EXIT_INVARIANT,
    EXIT_REPLAY,
    EXIT_STRATEGY,
    TCOPCommandError,
    diagnostic,
    emit,
    load_config,
)
from .confirmation_benchmark import (
    CONFIRMATION_BASELINES,
    CONFIRMATION_SCENARIO_BY_ID,
    ConfirmationBenchmarkRunner,
    run_confirmation_experiments,
    run_confirmation_suite,
)
from .context_comparator import EVIDENCE_ROOT as COMPARATOR_ROOT, run_context_comparator, verify_context_comparator
from .validation_value import ROOT as VALIDATION_VALUE_ROOT, run_validation_value, verify_validation_value
from .external_adaptive_crosshost import (
    ROOT as EXTERNAL_ADAPTIVE_ROOT,
    report_external_adaptive,
    run_external_adaptive,
    verify_external_adaptive,
)
from .external_acquisition import DEFAULT_BUNDLE as EXTERNAL_INPUT_BUNDLE, seal_acquisition_bundle
from .adaptive_agent_authorization import ROOT as ADAPTIVE_AUTH_ROOT, run_adaptive_authorization, verify_adaptive_authorization, report_adaptive_authorization
from .independent_warning_admission import ROOT as INDEPENDENT_WARNING_ROOT, acquire_independent, run_independent_warning, verify_independent_warning, report_independent_warning
from .experiments import run_deterministic_experiments
from .evidence_round import DEFAULT_SOURCE as EVIDENCE_SOURCE, SELECTIONS as EVIDENCE_SELECTIONS, EvidenceRound, evidence_selection_matrix, run_evidence_study
from .federation import (
    FROZEN_ROOT,
    ARCHITECTURES,
    NETWORKS,
    OBSERVERS,
    SCENARIOS as FEDERATED_SCENARIOS,
    TOPOLOGIES,
    FederatedRun,
    FrozenStrategyAdapter,
    MatrixCell,
    UPSTREAM_DIGESTS,
    _cell_id,
    _write_json,
    artifact_root_digest,
    build_reports,
    generate_matrix,
    run_federated_study,
    verify_frozen_inputs,
)
from .minimality_runner import run_minimality_study
from .minimality_validation import run_minimality_validation
from .regression import run_v01_regression, run_v02_regression, run_v03_regression, run_v04_regression
from .reliability_benchmark import (
    RELIABILITY_BASELINES,
    RELIABILITY_SCENARIO_BY_ID,
    ReliabilityBenchmarkRunner,
    run_reliability_experiments,
    run_reliability_suite,
)
from .runtime_services import admin_query, run_service, service_description
from .witness_benchmark import (
    WITNESS_BASELINES,
    WITNESS_SCENARIO_BY_ID,
    WitnessBenchmarkRunner,
    run_witness_experiments,
    run_witness_suite,
)


VERSION = "TCOP CLI 0.6.0"


def _format(parser: argparse.ArgumentParser, default: str = "json") -> None:
    parser.add_argument("--format", "--output-format", choices=("text", "json", "jsonl"), default=default, help="structured stdout format")


def _source(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", type=Path, default=FROZEN_ROOT, help="frozen v0.5 validation artifact root")


def _study_plan(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", type=Path, default=Path("benchmark/studies/v0.6-federated.yaml"), help="declarative v0.6 study plan")


def _require_plan(path: Path) -> str:
    if not path.is_file():
        raise TCOPCommandError(f"study plan not found: {path}")
    plan = load_config(path)
    if plan.get("study_kind") == "evidence_round":
        required = {"study", "study_kind", "source_study", "source_artifact", "frozen_inputs", "selections", "source_streams", "pair_key_fields", "invariants", "artifact_root"}
        if not required <= set(plan):
            raise TCOPCommandError(f"evidence study plan is incomplete: missing {', '.join(sorted(required - set(plan)))}")
        expected = {key.replace(".", "_"): digest for key, digest in UPSTREAM_DIGESTS.items()}
        if not isinstance(plan.get("frozen_inputs"), dict) or any(plan["frozen_inputs"].get(key) != digest for key, digest in expected.items()):
            raise TCOPCommandError("evidence study plan frozen-input digests differ from admitted v0.6 inputs", EXIT_FROZEN_INPUT)
        if set(plan["selections"]) != EVIDENCE_SELECTIONS:
            raise TCOPCommandError("evidence study plan selections differ from the registered evidence round")
        return "evidence"
    required = {"study", "frozen_inputs", "phases", "information_streams", "architectures", "selection_rule", "artifact_root"}
    if not required <= set(plan):
        missing = ", ".join(sorted(required - set(plan)))
        raise TCOPCommandError(f"study plan is incomplete: missing {missing}")
    frozen = plan.get("frozen_inputs")
    expected = {key.replace(".", "_"): digest for key, digest in UPSTREAM_DIGESTS.items()}
    if not isinstance(frozen, dict) or any(frozen.get(key) != digest for key, digest in expected.items()):
        raise TCOPCommandError("study plan frozen-input digests differ from the admitted v0.6 inputs", EXIT_FROZEN_INPUT)
    if plan.get("information_streams") != ["authored_facts", "benchmark_truth", "produced_observations", "transport_faults", "derived_decisions"]:
        raise TCOPCommandError("study plan must preserve the five registered information streams")
    if set(plan.get("architectures", {})) != set(ARCHITECTURES):
        raise TCOPCommandError("study plan architectures differ from the registered v0.6 matrix")
    return "federated"


def _add_strategy(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    strategy = commands.add_parser("strategy", help="inspect and certify frozen v0.5 strategy compatibility")
    nested = strategy.add_subparsers(dest="strategy_command", required=True)
    list_parser = nested.add_parser("list", help="list admitted frozen strategies")
    _source(list_parser); _format(list_parser)
    inspect_parser = nested.add_parser("inspect", help="inspect one frozen strategy")
    inspect_parser.add_argument("strategy_id", choices=("containment-first", "balanced", "utility-preserving", "forensic-oriented")); _source(inspect_parser); _format(inspect_parser)
    verify_parser = nested.add_parser("verify", help="fail closed if a frozen strategy differs")
    verify_parser.add_argument("strategy_id", choices=("containment-first", "balanced", "utility-preserving", "forensic-oriented")); verify_parser.add_argument("--manifest", type=Path); _source(verify_parser); _format(verify_parser)
    certify = nested.add_parser("certify", help="certify one or every admitted frozen strategy")
    certify.add_argument("--all", action="store_true", help="certify every admitted strategy")
    certify.add_argument("--strategy", choices=("containment-first", "balanced", "utility-preserving", "forensic-oriented"))
    certify.add_argument("--manifest", type=Path); _source(certify); _format(certify)


def _add_context(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    context = commands.add_parser("context", help="create, sign, verify, inspect, and relay TCX context")
    nested = context.add_subparsers(dest="context_command", required=True)
    create = nested.add_parser("create", help="create a deterministic signed TCX context fixture")
    create.add_argument("--version", choices=("0.1", "0.2"), default="0.2")
    create.add_argument("--observer", required=True); create.add_argument("--trust-domain", required=True)
    create.add_argument("--subject", required=True); create.add_argument("--scope", required=True)
    create.add_argument("--type", default="tool.prohibited_export"); create.add_argument("--now", type=int, default=2_200_000_000)
    create.add_argument("--ttl", type=int, default=60); create.add_argument("--severity", default="high")
    create.add_argument("--write", type=Path, help="write the signed context JSON")
    create.add_argument("--receipt-write", type=Path, help="write the v0.2 interaction receipt JSON")
    _format(create)
    sign = nested.add_parser("sign", help="re-sign a context with a deterministic development identity")
    sign.add_argument("context", type=Path); sign.add_argument("--observer", required=True); sign.add_argument("--trust-domain", required=True); sign.add_argument("--write", type=Path); _format(sign)
    verify_parser = nested.add_parser("verify", help="verify a signed TCX context using the shared validator")
    verify_parser.add_argument("context", type=Path); verify_parser.add_argument("--now", type=int); verify_parser.add_argument("--receipt", type=Path); verify_parser.add_argument("--trust-store", type=Path, help="JSON public-identity and control-group trust store"); _format(verify_parser)
    inspect = nested.add_parser("inspect", help="inspect a context without changing it")
    inspect.add_argument("context", type=Path); inspect.add_argument("--output", choices=("text", "json", "jsonl"), default="json"); inspect.add_argument("--format", dest="format", choices=("text", "json", "jsonl"), help=argparse.SUPPRESS)
    relay = nested.add_parser("relay", help="make a provenance-preserving v0.2 relay record")
    relay.add_argument("context", type=Path); relay.add_argument("--relay", required=True); relay.add_argument("--trust-domain", required=True); relay.add_argument("--now", type=int, default=2_200_000_000); relay.add_argument("--write", type=Path); _format(relay)
    receipt = commands.add_parser("receipt", help="verify an interaction receipt")
    receipt_nested = receipt.add_subparsers(dest="receipt_command", required=True)
    receipt_verify = receipt_nested.add_parser("verify", help="verify an immutable interaction receipt")
    receipt_verify.add_argument("receipt", type=Path); receipt_verify.add_argument("--context", type=Path); receipt_verify.add_argument("--trust-store", type=Path); _format(receipt_verify)


def _add_service_and_admin(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    service = commands.add_parser("service", help="run a safe local TCOP runtime service")
    nested = service.add_subparsers(dest="service_command", required=True)
    for component in ("domain", "gateway", "resolver", "observer", "enforcement"):
        parser = nested.add_parser(component, help=f"run {component} with declarative v0.6 configuration")
        parser.add_argument("--config", type=Path, required=True); parser.add_argument("--listen")
        parser.add_argument("--state-dir", type=Path); parser.add_argument("--transport", choices=("https", "http", "loopback", "deterministic-network"))
        parser.add_argument("--metrics-listen"); parser.add_argument("--health-listen")
        parser.add_argument("--log-format", choices=("text", "json"), default="text"); parser.add_argument("--log-level", default="info")
        parser.add_argument("--dry-run", action="store_true"); _format(parser)
    admin = commands.add_parser("admin", help="observational diagnostics for a local TCOP service")
    admin_nested = admin.add_subparsers(dest="admin_command", required=True)
    for resource in ("status", "peers", "health", "strategy", "contexts", "decisions", "metrics"):
        parser = admin_nested.add_parser(resource, help=f"read {resource} from a TCOP service")
        parser.add_argument("--endpoint", default="http://127.0.0.1:8443")
        parser.add_argument("--domain"); parser.add_argument("--since"); parser.add_argument("--scope")
        _format(parser)


def _add_study_and_artifact(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    study = commands.add_parser("study", help="deterministic research reproduction and review")
    nested = study.add_subparsers(dest="study_command", required=True)
    verify_inputs = nested.add_parser("verify-inputs", help="reproduce frozen upstream checks and certify strategies")
    _study_plan(verify_inputs); _source(verify_inputs); verify_inputs.add_argument("--source-artifact", type=Path, default=EVIDENCE_SOURCE); _format(verify_inputs)
    matrix = nested.add_parser("matrix", help="write the declarative included experiment matrix")
    selections = ("smoke", "core", "primary", "full", *sorted(EVIDENCE_SELECTIONS - {"smoke", "full"}))
    _study_plan(matrix); matrix.add_argument("--selection", choices=selections, default="full"); matrix.add_argument("--output", type=Path, required=True); _format(matrix)
    reproduce = nested.add_parser("reproduce", help="run the atomic v0.6 reproduction sequence")
    _study_plan(reproduce); _source(reproduce); reproduce.add_argument("--source-artifact", type=Path, default=EVIDENCE_SOURCE); reproduce.add_argument("--selection", choices=selections, default="core"); reproduce.add_argument("--output", type=Path, default=Path("artifacts/federated-domain-v0.6")); reproduce.add_argument("--dry-run", action="store_true"); reproduce.add_argument("--fail-fast", action="store_true", default=True); reproduce.add_argument("--no-fail-fast", dest="fail_fast", action="store_false"); _format(reproduce)
    run = nested.add_parser("run", help="execute an included selection or one explicit matrix cell")
    _study_plan(run); _source(run); run.add_argument("--source-artifact", type=Path, default=EVIDENCE_SOURCE); run.add_argument("--selection", choices=selections); run.add_argument("--artifact-dir", type=Path, default=Path("artifacts/federated-domain-v0.6")); run.add_argument("--scenario", choices=sorted(FEDERATED_SCENARIOS)); run.add_argument("--architecture", choices=sorted(ARCHITECTURES)); run.add_argument("--strategy", choices=("containment-first", "balanced", "utility-preserving", "forensic-oriented")); run.add_argument("--topology", choices=sorted(TOPOLOGIES), default="T1"); run.add_argument("--observer", choices=sorted(OBSERVERS), default="O1"); run.add_argument("--network", choices=sorted(NETWORKS), default="N0"); run.add_argument("--seed", type=int, default=42); _format(run)
    replay = nested.add_parser("replay", help="exactly replay one saved deterministic run")
    replay.add_argument("--run", type=Path, required=True); _source(replay); _format(replay)
    validate = nested.add_parser("validate", help="verify an existing study artifact without rerunning it")
    validate.add_argument("--artifact-dir", type=Path, required=True); _format(validate)
    report = nested.add_parser("report", help="rebuild reports from existing run summaries only")
    report.add_argument("--artifact-dir", type=Path, required=True); _format(report)
    agent = nested.add_parser("agent", help="run the isolated v0.6 agent-based external-validation study")
    agent_nested = agent.add_subparsers(dest="agent_command", required=True)
    def _agent_plan(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--plan", type=Path, default=AGENT_STUDY_PLAN, help="admitted v0.6 agent-validation study plan")
    agent_prepare = agent_nested.add_parser("prepare", help="fail closed unless the admitted source artifacts and frozen strategies verify")
    _agent_plan(agent_prepare); _format(agent_prepare)
    agent_generate = agent_nested.add_parser("generate-traces", help="capture eligible agent tool traces without changing protocol behavior")
    _agent_plan(agent_generate); agent_generate.add_argument("--scenario", choices=("RA-01", "RA-02", "RA-03"), required=True); agent_generate.add_argument("--driver", choices=("scripted", "replay", "llm"), required=True); agent_generate.add_argument("--runtime-config", type=Path, help="provider-neutral LLM and gateway configuration; required for --driver llm"); agent_generate.add_argument("--output", type=Path, default=Path("artifacts/v0.6-agent-validation")); _format(agent_generate)
    agent_replay = agent_nested.add_parser("replay", help="strictly replay identical captured traces through local-only and TCOP treatments")
    _agent_plan(agent_replay); agent_replay.add_argument("--selection", choices=sorted(AGENT_SELECTIONS), default="causal-core"); agent_replay.add_argument("--output", type=Path, default=Path("artifacts/v0.6-agent-validation")); _format(agent_replay)
    agent_live = agent_nested.add_parser("run-live", help="execute configured live-agent trials after trace capture is eligible")
    _agent_plan(agent_live); agent_live.add_argument("--selection", choices=("end-to-end",), default="end-to-end"); agent_live.add_argument("--runtime-config", type=Path, required=True, help="provider-neutral LLM and gateway configuration"); agent_live.add_argument("--output", type=Path, default=Path("artifacts/v0.6-agent-validation-live")); _format(agent_live)
    agent_freeze_live = agent_nested.add_parser("freeze-live", help="preregister and freeze live runtime inputs before any provider request")
    _agent_plan(agent_freeze_live); agent_freeze_live.add_argument("--runtime-config", type=Path, required=True); agent_freeze_live.add_argument("--output", type=Path, default=Path("artifacts/v0.6-agent-validation-live")); _format(agent_freeze_live)
    agent_finalize_live = agent_nested.add_parser("finalize-live", help="certify a verified live artifact after a documented artifact-gate correction")
    agent_finalize_live.add_argument("--source", type=Path, required=True); agent_finalize_live.add_argument("--output", type=Path, required=True); _format(agent_finalize_live)
    agent_reconcile_live = agent_nested.add_parser("reconcile-live", help="reconcile a derived live utility metric from verified immutable replay rows")
    agent_reconcile_live.add_argument("--source", type=Path, required=True); agent_reconcile_live.add_argument("--output", type=Path, required=True); _format(agent_reconcile_live)
    agent_origin_live = agent_nested.add_parser("revalidate-origin-path", help="run tcopd-a to tcopd-b real-gateway arms over frozen live traces without model sampling")
    agent_origin_live.add_argument("--source", type=Path, required=True); agent_origin_live.add_argument("--output", type=Path, required=True); agent_origin_live.add_argument("--runtime-config", type=Path, required=True); _format(agent_origin_live)
    agent_benchmark = agent_nested.add_parser("benchmark", help="measure separately predeclared gateway overhead settings")
    _agent_plan(agent_benchmark); agent_benchmark.add_argument("--selection", choices=("gateway-overhead",), default="gateway-overhead"); agent_benchmark.add_argument("--output", type=Path, default=Path("artifacts/v0.6-agent-validation")); _format(agent_benchmark)
    agent_report = agent_nested.add_parser("report", help="read existing agent-study reports without rerunning traces")
    agent_report.add_argument("--artifact-dir", type=Path, required=True); _format(agent_report)
    agent_reproduce = agent_nested.add_parser("reproduce", help="run the credential-free scripted smoke reproduction")
    _agent_plan(agent_reproduce); agent_reproduce.add_argument("--selection", choices=("smoke",), default="smoke"); agent_reproduce.add_argument("--driver", choices=("scripted",), default="scripted"); agent_reproduce.add_argument("--output", type=Path, default=Path("artifacts/v0.6-agent-validation")); _format(agent_reproduce)
    agent_evaluator = agent_nested.add_parser("serve-evaluator", help="run the receiver-local evaluator for the pinned reference gateway")
    agent_evaluator.add_argument("--scenario", choices=("RA-01", "RA-02", "RA-03"), default="RA-01"); agent_evaluator.add_argument("--host", default="127.0.0.1"); agent_evaluator.add_argument("--port", type=int, default=8091)
    agent_tools = agent_nested.add_parser("serve-tool-service", help="run the stateful synthetic MCP tool service")
    agent_tools.add_argument("--host", default="127.0.0.1"); agent_tools.add_argument("--port", type=int, default=8092)
    agent_origin = agent_nested.add_parser("serve-origin-relay", help="run tcopd-a's origin signing and federation relay for the live reference path")
    agent_origin.add_argument("--host", default="127.0.0.1"); agent_origin.add_argument("--port", type=int, default=8090)
    agent_gateway = agent_nested.add_parser("gateway", help="verify or build the pinned reference MCP gateway")
    agent_gateway_nested = agent_gateway.add_subparsers(dest="agent_gateway_command", required=True)
    agent_gateway_verify = agent_gateway_nested.add_parser("verify", help="verify source revision, license, and clean generic-hook patch application")
    agent_gateway_verify.add_argument("--source", type=Path, required=True); _format(agent_gateway_verify)
    agent_gateway_build = agent_gateway_nested.add_parser("build", help="build a local image from a verified pinned source and generic hook patch")
    agent_gateway_build.add_argument("--source", type=Path, required=True); agent_gateway_build.add_argument("--tag", required=True); _format(agent_gateway_build)
    agent_probe = agent_nested.add_parser("probe-gateway", help="exercise real reference-gateway allow/context/receiver-local-deny wiring")
    agent_probe.add_argument("--gateway-endpoint", required=True); agent_probe.add_argument("--receiver-endpoint", required=True); agent_probe.add_argument("--token", required=True); agent_probe.add_argument("--artifact-dir", type=Path, help="record a passed probe in an existing agent-validation artifact"); _format(agent_probe)
    comparator = nested.add_parser("comparator", help="run or verify the separately rooted context-value comparator")
    comparator_nested = comparator.add_subparsers(dest="comparator_command", required=True)
    comparator_run = comparator_nested.add_parser("run", help="run C0 through C3 against frozen deterministic and replay inputs")
    comparator_run.add_argument("--output", type=Path, default=COMPARATOR_ROOT); _format(comparator_run)
    comparator_verify = comparator_nested.add_parser("verify", help="verify a sealed context-value comparator artifact")
    comparator_verify.add_argument("--artifact-dir", type=Path, default=COMPARATOR_ROOT); _format(comparator_verify)
    validation_value = nested.add_parser("validation-value", help="run or verify the separately rooted TCX validation-value v2 study")
    validation_nested = validation_value.add_subparsers(dest="validation_value_command", required=True)
    validation_run = validation_nested.add_parser("run", help="run the deterministic v2 mixed-action, hostile-peer, correlation, and protocol-assurance workstreams")
    validation_run.add_argument("--plan", type=Path, default=Path("benchmark/studies/tcx-validation-value-v2.yaml")); validation_run.add_argument("--output", type=Path, default=VALIDATION_VALUE_ROOT); _format(validation_run)
    validation_verify = validation_nested.add_parser("verify", help="verify a sealed TCX validation-value v2 artifact")
    validation_verify.add_argument("--artifact-dir", type=Path, default=VALIDATION_VALUE_ROOT); _format(validation_verify)
    external_adaptive = nested.add_parser("external-adaptive", help="run or verify the external-warning adaptive-attacker cross-host study")
    external_nested = external_adaptive.add_subparsers(dest="external_adaptive_command", required=True)
    external_acquire = external_nested.add_parser("acquire", help="seal already acquired external inputs and their file manifests")
    external_acquire.add_argument("--plan", type=Path, default=Path("benchmark/studies/external-warning-adaptive-crosshost-v1.yaml")); external_acquire.add_argument("--bundle", type=Path, default=EXTERNAL_INPUT_BUNDLE); _format(external_acquire)
    external_run = external_nested.add_parser("run", help="perform the required external-study preflight and run only when every gate passes")
    external_run.add_argument("--plan", type=Path, default=Path("benchmark/studies/external-warning-adaptive-crosshost-v1.yaml")); external_run.add_argument("--output", type=Path, default=EXTERNAL_ADAPTIVE_ROOT); _format(external_run)
    external_verify = external_nested.add_parser("verify", help="verify an external-warning study artifact, including a sealed BLOCKED preflight")
    external_verify.add_argument("--artifact-dir", type=Path, default=EXTERNAL_ADAPTIVE_ROOT); _format(external_verify)
    external_report = external_nested.add_parser("report", help="report the study status and supported claims")
    external_report.add_argument("--artifact-dir", type=Path, default=EXTERNAL_ADAPTIVE_ROOT); _format(external_report)
    adaptive_authorization = nested.add_parser("adaptive-authorization", help="run the separately rooted adaptive agent authorization study")
    adaptive_nested = adaptive_authorization.add_subparsers(dest="adaptive_authorization_command", required=True)
    for name, help_text in (("run", "run the 100-episode strict replay and 12 bounded runtime episodes"), ("verify", "verify the sealed adaptive authorization study"), ("report", "read its reports")):
        parser = adaptive_nested.add_parser(name, help=help_text); parser.add_argument("--artifact-dir" if name != "run" else "--output", type=Path, default=ADAPTIVE_AUTH_ROOT); parser.add_argument("--plan", type=Path, default=Path("benchmark/studies/adaptive-agent-authorization-v1.yaml")) if name == "run" else None; _format(parser)
    independent_warning = nested.add_parser("independent-warning", help="run the independently authored warning admission study")
    independent_nested = independent_warning.add_subparsers(dest="independent_warning_command", required=True)
    independent_acquire = independent_nested.add_parser("acquire", help="verify and seal admitted AgentDojo and Prompt Guard inputs"); independent_acquire.add_argument("--output", type=Path, default=Path("artifacts/independent-warning-admission-v1-inputs")); independent_acquire.add_argument("--plan", type=Path, default=Path("benchmark/studies/independent-warning-admission-v1.yaml")); _format(independent_acquire)
    independent_run = independent_nested.add_parser("run", help="run the held-out warning admission frontier"); independent_run.add_argument("--output", type=Path, default=INDEPENDENT_WARNING_ROOT); independent_run.add_argument("--plan", type=Path, default=Path("benchmark/studies/independent-warning-admission-v1.yaml")); _format(independent_run)
    for name in ("verify", "report"):
        parser=independent_nested.add_parser(name, help=f"{name} the sealed independent warning study"); parser.add_argument("--artifact-dir", type=Path, default=INDEPENDENT_WARNING_ROOT); _format(parser)
    artifact = commands.add_parser("artifact", help="read-only artifact verification, inspection, and comparison")
    artifact_nested = artifact.add_subparsers(dest="artifact_command", required=True)
    artifact_verify = artifact_nested.add_parser("verify", help="verify an already-created artifact root")
    artifact_verify.add_argument("artifact_dir", type=Path); artifact_verify.add_argument("--require-complete", action="store_true"); artifact_verify.add_argument("--require-replayable", action="store_true"); _format(artifact_verify)
    artifact_inspect = artifact_nested.add_parser("inspect", help="inspect artifact metadata and reports")
    artifact_inspect.add_argument("artifact_dir", type=Path); _format(artifact_inspect)
    artifact_manifest = artifact_nested.add_parser("manifest", help="print an artifact manifest")
    artifact_manifest.add_argument("artifact_dir", type=Path); _format(artifact_manifest)
    artifact_compare = artifact_nested.add_parser("compare", help="compare two artifact roots without rerunning either")
    artifact_compare.add_argument("left", type=Path); artifact_compare.add_argument("right", type=Path); _format(artifact_compare)


def _add_legacy(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Preserve previous deterministic commands while documented CLI groups lead."""
    benchmark = commands.add_parser("benchmark", help="compatibility: run v0.1 deterministic benchmark scenarios")
    benchmark.add_argument("--scenario", choices=sorted(SCENARIO_BY_ID)); benchmark.add_argument("--all", action="store_true"); benchmark.add_argument("--baseline", choices=BASELINES, default="tcx"); benchmark.add_argument("--seed", type=int, default=42); benchmark.add_argument("--artifact-dir", type=Path, default=Path("artifacts/benchmark")); _format(benchmark)
    verify = commands.add_parser("verify", help="compatibility: verify v0.1 benchmark reproduction")
    verify.add_argument("--artifact-dir", type=Path, default=Path("artifacts/verify")); verify.add_argument("--seed", type=int, default=42); _format(verify)
    experiments = commands.add_parser("experiments", help="compatibility: run deterministic experiments")
    experiments.add_argument("--artifact-dir", type=Path, default=Path("artifacts/experiments")); _format(experiments)
    regression = commands.add_parser("regression", help="compatibility: reproduce frozen v0.1 corpus")
    regression.add_argument("--artifact-dir", type=Path, default=Path("artifacts/regression-v0.1")); _format(regression)
    witness = commands.add_parser("witness", help="compatibility: run v0.2 witness suite")
    witness.add_argument("--scenario", choices=sorted(WITNESS_SCENARIO_BY_ID)); witness.add_argument("--all", action="store_true"); witness.add_argument("--baseline", choices=WITNESS_BASELINES); witness.add_argument("--artifact-dir", type=Path, default=Path("artifacts/witness-v0.2")); witness.add_argument("--seed", type=int, default=42); _format(witness)
    reliability = commands.add_parser("reliability", help="compatibility: run v0.3 reliability suite")
    reliability.add_argument("--scenario", choices=sorted(RELIABILITY_SCENARIO_BY_ID)); reliability.add_argument("--all", action="store_true"); reliability.add_argument("--baseline", choices=RELIABILITY_BASELINES); reliability.add_argument("--artifact-dir", type=Path, default=Path("artifacts/reliability-v0.3")); reliability.add_argument("--seed", type=int, default=42); _format(reliability)
    confirmation = commands.add_parser("confirmation", help="compatibility: run v0.4 confirmation suite")
    confirmation.add_argument("--scenario", choices=sorted(CONFIRMATION_SCENARIO_BY_ID)); confirmation.add_argument("--all", action="store_true"); confirmation.add_argument("--baseline", choices=CONFIRMATION_BASELINES); confirmation.add_argument("--artifact-dir", type=Path, default=Path("artifacts/confirmation-v0.4")); confirmation.add_argument("--seed", type=int, default=42); _format(confirmation)
    minimality = commands.add_parser("minimality", help="compatibility: run v0.5 study")
    minimality.add_argument("--stage", choices=("core", "combinations", "all"), default="all"); minimality.add_argument("--artifact-dir", type=Path, default=Path("artifacts/minimality-v0.5")); _format(minimality)
    validation = commands.add_parser("minimality-validation", help="compatibility: validate v0.5 study")
    validation.add_argument("--source", type=Path, default=Path("artifacts/minimality-v0.5")); validation.add_argument("--artifact-dir", type=Path, default=Path("artifacts/minimality-v0.5-validation")); _format(validation)
    federated = commands.add_parser("federated", help="compatibility: run the v0.6 federation study")
    federated.add_argument("--stage", choices=("smoke", "core", "full"), default="full"); federated.add_argument("--source", type=Path, default=FROZEN_ROOT); federated.add_argument("--artifact-dir", type=Path, default=Path("artifacts/federated-domain-v0.6")); _format(federated)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tcop", description="TCOP protocol, runtime, study, and artifact interface")
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    _add_strategy(commands); _add_context(commands); _add_service_and_admin(commands); _add_study_and_artifact(commands); _add_legacy(commands)
    return parser


def _single_cell(args: argparse.Namespace) -> dict[str, Any]:
    if not (args.scenario and args.architecture):
        raise TCOPCommandError("an explicit cell requires --scenario and --architecture")
    strategy = args.strategy if args.architecture == "A2" else "none"
    if args.architecture == "A2" and not strategy:
        raise TCOPCommandError("A2 requires a frozen --strategy", EXIT_STRATEGY)
    values = {"topology_id": args.topology, "scenario_id": args.scenario, "observer_id": args.observer, "network_id": args.network, "architecture_id": args.architecture, "strategy_id": strategy, "seed": args.seed}
    cell = MatrixCell(_cell_id(values), **values, classification="mechanism_probe", reason="explicit reviewer-selected deterministic cell")
    adapter = FrozenStrategyAdapter(args.source)
    adapter.certify_all()
    run = FederatedRun(cell, adapter)
    summary = run.run()
    run.write(args.artifact_dir, summary)
    return summary


def _selection(value: str) -> str:
    """Keep the published ``primary`` alias stable without duplicating a matrix."""

    return "core" if value == "primary" else value


def _replay_run(path: Path, source: Path) -> dict[str, Any]:
    summary_path = path / "summary.json"
    if not summary_path.is_file():
        raise TCOPCommandError(f"run summary not found: {summary_path}", EXIT_REPLAY)
    previous = json.loads(summary_path.read_text(encoding="utf-8"))
    try:
        cell = MatrixCell(**previous["cell"])
    except (KeyError, TypeError) as exc:
        raise TCOPCommandError(f"invalid run summary: {exc}", EXIT_REPLAY) from exc
    adapter = FrozenStrategyAdapter(source); adapter.certify_all()
    current = FederatedRun(cell, adapter).run()
    passed = previous.get("stream_digest") == current.get("stream_digest")
    result = {"run": str(path), "expected_stream_digest": previous.get("stream_digest"), "replayed_stream_digest": current.get("stream_digest"), "passed": passed}
    if not passed:
        raise TCOPCommandError(json.dumps(result, sort_keys=True), EXIT_REPLAY)
    return result


def _rebuild_report(root: Path) -> dict[str, Any]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    matrix_path = root / "matrix" / f"{manifest['stage']}-matrix.json"
    cells = [MatrixCell(**item) for item in json.loads(matrix_path.read_text(encoding="utf-8"))]
    summaries = [json.loads((root / "runs" / cell.cell_id / "summary.json").read_text(encoding="utf-8")) for cell in cells]
    report = build_reports(root, summaries, cells)
    digest = artifact_root_digest(root)
    _write_json(root / "artifact-root-digest.json", digest)
    return {
        "artifact_dir": str(root), "run_count": len(summaries),
        "aggregate_record_count": len(report["aggregate"]), "comparison_record_count": len(report["differences"]),
        "pareto_record_count": len(report["pareto"]), "artifact_root_digest": digest["artifact_root_digest"],
    }


def _study_summary(result: Mapping[str, Any], output: Path) -> dict[str, Any]:
    """Keep CLI stdout bounded; detailed result data lives in the artifact."""

    manifest = result["manifest"]
    report = result["report"]
    digest = result["artifact_root_digest"]
    return {
        "study": "TCOP v0.6 federated-domain",
        "artifact_dir": str(output),
        "stage": manifest["stage"],
        "passed": bool(manifest["passed"]),
        "matrix_cell_count": manifest["matrix_cell_count"],
        "frozen_inputs_verified": True,
        "strategies_certified": 4,
        "harness_conformance": bool(result["conformance"]["passed"]),
        "replay_verified": True,
        "aggregate_record_count": len(report["aggregate"]),
        "artifact_root_digest": digest["artifact_root_digest"],
    }


def _evidence_summary(result: Mapping[str, Any], output: Path) -> dict[str, Any]:
    manifest, readiness = result["manifest"], result["readiness"]
    return {
        "study": "TCOP v0.6 missing-evidence round", "artifact_dir": str(output), "selection": manifest["selection"],
        "passed": bool(manifest["passed"]), "source_run_count": manifest["source_run_count"],
        "diagnostic_run_count": manifest["diagnostic_run_count"], "cohort_count": result["cohort_count"],
        "pair_count": result["pair_count"], "replay_verified": bool(result["replay"]["passed"]),
        "paper_core_claim_ready": bool(readiness["paper_core_claim_ready"]),
        "artifact_root_digest": result["artifact_root_digest"]["artifact_root_digest"],
    }


def _legacy(args: argparse.Namespace) -> Any:
    if args.command == "verify":
        return verify(args.artifact_dir, seed=args.seed)
    if args.command == "experiments":
        result = run_deterministic_experiments(args.artifact_dir)
        return {"summary": result["summary"], "architecture_controls": result["architecture_controls"]}
    if args.command == "regression":
        return run_v01_regression(args.artifact_dir)
    if args.command == "witness":
        if args.scenario:
            baselines = [args.baseline] if args.baseline else list(WITNESS_BASELINES)
            return [WitnessBenchmarkRunner().run(args.scenario, baseline=baseline, output=args.artifact_dir, seed=args.seed) for baseline in baselines]
        result = run_witness_suite(args.artifact_dir, seed=args.seed); result["experiments"] = run_witness_experiments(args.artifact_dir / "experiments")
        return result
    if args.command == "reliability":
        if args.scenario:
            baselines = [args.baseline] if args.baseline else list(RELIABILITY_BASELINES)
            return [ReliabilityBenchmarkRunner().run(args.scenario, baseline=baseline, output=args.artifact_dir, seed=args.seed) for baseline in baselines]
        with tempfile.TemporaryDirectory() as temporary:
            check = Path(temporary); upstream = {"v0.1": run_v01_regression(check / "v0.1", seed=args.seed), "v0.2": run_v02_regression(check / "v0.2", seed=args.seed)}
        result = run_reliability_suite(args.artifact_dir, seed=args.seed); result["experiments"] = run_reliability_experiments(args.artifact_dir / "experiments", seed=args.seed); result["upstream_regressions"] = upstream
        return result
    if args.command == "confirmation":
        if args.scenario:
            baselines = [args.baseline] if args.baseline else list(CONFIRMATION_BASELINES)
            return [ConfirmationBenchmarkRunner().run(args.scenario, baseline=baseline, output=args.artifact_dir, seed=args.seed) for baseline in baselines]
        with tempfile.TemporaryDirectory() as temporary:
            check = Path(temporary); upstream = {"v0.1": run_v01_regression(check / "v0.1", seed=args.seed), "v0.2": run_v02_regression(check / "v0.2", seed=args.seed), "v0.3": run_v03_regression(check / "v0.3", seed=args.seed)}
        result = run_confirmation_suite(args.artifact_dir, seed=args.seed); result["experiments"] = run_confirmation_experiments(args.artifact_dir / "experiments", seed=args.seed); result["upstream_regressions"] = upstream
        return result
    if args.command == "minimality":
        with tempfile.TemporaryDirectory() as temporary:
            check = Path(temporary); upstream = {"v0.1": run_v01_regression(check / "v0.1"), "v0.2": run_v02_regression(check / "v0.2"), "v0.3": run_v03_regression(check / "v0.3"), "v0.4": run_v04_regression(check / "v0.4")}
        result = run_minimality_study(args.artifact_dir, stage=args.stage); result["upstream_regressions"] = upstream
        return result
    if args.command == "minimality-validation":
        return run_minimality_validation(args.source, args.artifact_dir)
    if args.command == "federated":
        return run_federated_study(args.artifact_dir, stage=args.stage, source_root=args.source)
    if args.command == "benchmark":
        identifiers = [scenario.scenario_id for scenario in SCENARIOS] if args.all else [args.scenario]
        if not all(identifiers):
            raise TCOPCommandError("provide --scenario or --all")
        runner = BenchmarkRunner()
        return [runner.run(identifier, baseline=args.baseline, seed=args.seed, output=args.artifact_dir) for identifier in identifiers]
    raise TCOPCommandError(f"unsupported compatibility command: {args.command}")


def dispatch(args: argparse.Namespace) -> tuple[Any, str]:
    if args.command == "strategy":
        if args.strategy_command == "list": return list_strategies(args.source), args.format
        if args.strategy_command == "inspect": return inspect_strategy(args.strategy_id, args.source), args.format
        if args.strategy_command == "verify": return verify_strategy(args.strategy_id, source=args.source, manifest=args.manifest), args.format
        if args.strategy_command == "certify":
            if not args.all and not args.strategy: raise TCOPCommandError("provide --all or --strategy")
            return certify_strategies(source=args.source, strategy_id=args.strategy, manifest=args.manifest), args.format
    if args.command == "context":
        if args.context_command == "create": return create_context(version=args.version, observer_id=args.observer, trust_domain=args.trust_domain, subject_id=args.subject, scope=args.scope, observation_type=args.type, now=args.now, ttl=args.ttl, severity=args.severity, write=args.write, receipt_write=args.receipt_write), args.format
        if args.context_command == "sign": return sign_context(args.context, observer_id=args.observer, trust_domain=args.trust_domain, write=args.write), args.format
        if args.context_command == "verify": return verify_context(args.context, now=args.now, receipt=args.receipt, trust_store=args.trust_store), args.format
        if args.context_command == "inspect": return inspect_context(args.context), args.format or args.output
        if args.context_command == "relay": return relay_context(args.context, relay_id=args.relay, trust_domain=args.trust_domain, now=args.now, write=args.write), args.format
    if args.command == "receipt":
        return verify_receipt(args.receipt, context=args.context, trust_store=args.trust_store), args.format
    if args.command == "service":
        value = run_service(
            args.config, component=args.service_command, listen=args.listen, state_dir=args.state_dir,
            transport=args.transport, metrics_listen=args.metrics_listen, health_listen=args.health_listen,
            dry_run=args.dry_run,
        )
        return value, args.format
    if args.command == "admin":
        return admin_query(args.endpoint, args.admin_command, domain=args.domain, since=args.since, scope=args.scope), args.format
    if args.command == "study":
        if args.study_command == "comparator":
            if args.comparator_command == "run": return run_context_comparator(args.output), args.format
            if args.comparator_command == "verify": return verify_context_comparator(args.artifact_dir), args.format
        if args.study_command == "validation-value":
            if args.validation_value_command == "run": return run_validation_value(args.output, args.plan), args.format
            if args.validation_value_command == "verify": return verify_validation_value(args.artifact_dir), args.format
        if args.study_command == "external-adaptive":
            if args.external_adaptive_command == "acquire": return seal_acquisition_bundle(args.bundle, args.plan), args.format
            if args.external_adaptive_command == "run": return run_external_adaptive(args.output, args.plan), args.format
            if args.external_adaptive_command == "verify": return verify_external_adaptive(args.artifact_dir), args.format
            if args.external_adaptive_command == "report": return report_external_adaptive(args.artifact_dir), args.format
        if args.study_command == "adaptive-authorization":
            if args.adaptive_authorization_command == "run": return run_adaptive_authorization(args.output, args.plan), args.format
            if args.adaptive_authorization_command == "verify": return verify_adaptive_authorization(args.artifact_dir), args.format
            if args.adaptive_authorization_command == "report": return report_adaptive_authorization(args.artifact_dir), args.format
        if args.study_command == "independent-warning":
            if args.independent_warning_command == "acquire": return acquire_independent(args.output, args.plan), args.format
            if args.independent_warning_command == "run": return run_independent_warning(args.output, args.plan), args.format
            if args.independent_warning_command == "verify": return verify_independent_warning(args.artifact_dir), args.format
            if args.independent_warning_command == "report": return report_independent_warning(args.artifact_dir), args.format
        if args.study_command == "agent":
            study = AgentStudy(args.plan) if hasattr(args, "plan") else AgentStudy()
            if args.agent_command == "prepare": return study.prepare(), args.format
            if args.agent_command == "generate-traces": return study.generate_traces(args.output, scenario=args.scenario, driver=args.driver, runtime_config=args.runtime_config), args.format
            if args.agent_command == "replay": return study.replay(args.output, selection=args.selection), args.format
            if args.agent_command == "benchmark": return study.replay(args.output, selection=args.selection), args.format
            if args.agent_command == "reproduce": return study.replay(args.output, selection=args.selection), args.format
            if args.agent_command == "report": return study.report(args.artifact_dir), args.format
            if args.agent_command == "serve-evaluator":
                fixture = create_fixture(args.scenario, scripted_trace(args.scenario))
                serve_local_authorization(LocalAuthorizationEndpoint(receiver_for_fixture(fixture)), host=args.host, port=args.port)
                return {"served": True}, "json"
            if args.agent_command == "serve-tool-service":
                serve_synthetic_mcp_tool_service(host=args.host, port=args.port)
                return {"served": True}, "json"
            if args.agent_command == "serve-origin-relay":
                serve_origin_federation(host=args.host, port=args.port)
                return {"served": True}, "json"
            if args.agent_command == "gateway":
                if args.agent_gateway_command == "verify": return verify_gateway_source(args.source), args.format
                if args.agent_gateway_command == "build": return build_gateway_image(args.source, tag=args.tag), args.format
            if args.agent_command == "probe-gateway":
                probe = probe_reference_gateway(gateway_endpoint=args.gateway_endpoint, receiver_endpoint=args.receiver_endpoint, token=args.token)
                if args.artifact_dir:
                    return {"probe": probe, "artifact": study.record_gateway_probe(args.artifact_dir, probe)}, args.format
                return probe, args.format
            if args.agent_command == "run-live":
                return study.run_live(args.output, runtime_config=args.runtime_config, selection=args.selection), args.format
            if args.agent_command == "freeze-live":
                return study.freeze_live(args.output, runtime_config=args.runtime_config), args.format
            if args.agent_command == "finalize-live":
                return study.finalize_live(args.source, args.output), args.format
            if args.agent_command == "reconcile-live":
                return study.reconcile_live_metrics(args.source, args.output), args.format
            if args.agent_command == "revalidate-origin-path":
                return study.revalidate_live_origin_path(args.source, args.output, runtime_config=args.runtime_config), args.format
        plan_kind = _require_plan(args.plan) if hasattr(args, "plan") else "federated"
        if args.study_command == "verify-inputs":
            if plan_kind == "evidence":
                try:
                    with tempfile.TemporaryDirectory() as temporary:
                        result = EvidenceRound(args.source_artifact, Path(temporary), args.source).verify_source()
                    return {"source_artifact_verified": True, "source_run_count": result["source_run_count"], "frozen_strategy_digests": result["frozen_strategy_digests"]}, args.format
                except (AssertionError, OSError, ValueError) as exc:
                    raise TCOPCommandError(str(exc), EXIT_FROZEN_INPUT) from exc
            try: return verify_frozen_inputs(args.source), args.format
            except (AssertionError, OSError, ValueError) as exc: raise TCOPCommandError(str(exc), EXIT_FROZEN_INPUT) from exc
        if args.study_command == "matrix":
            if plan_kind == "evidence":
                selection = "full" if args.selection in {"core", "primary"} else args.selection
                cells = evidence_selection_matrix(selection)
                _write_json(args.output, cells)
                return {"plan": str(args.plan), "selection": selection, "cell_count": len(cells), "matrix": str(args.output)}, args.format
            cells = [asdict(item) for item in generate_matrix(_selection(args.selection))]
            _write_json(args.output, cells)
            return {"plan": str(args.plan), "selection": args.selection, "cell_count": len(cells), "matrix": str(args.output)}, args.format
        if args.study_command == "reproduce":
            if plan_kind == "evidence":
                selection = "full" if args.selection in {"core", "primary"} else args.selection
                if args.dry_run:
                    return {"dry_run": True, "plan": str(args.plan), "selection": selection, "source_artifact": str(args.source_artifact), "output": str(args.output), "workstreams": evidence_selection_matrix(selection)}, args.format
                result = run_evidence_study(args.output, selection=selection, source_artifact=args.source_artifact, frozen_root=args.source)
                return _evidence_summary(result, args.output), args.format
            selection = _selection(args.selection)
            if args.dry_run:
                return {"dry_run": True, "plan": str(args.plan), "selection": args.selection, "output": str(args.output), "cell_count": len(generate_matrix(selection)), "stages": ["verify-inputs", "certify-strategies", "validate-harness", "run-smoke", "verify-replay", "run-selection", "validate", "report", "digest"]}, args.format
            result = run_federated_study(args.output, stage=selection, source_root=args.source, study_plan=args.plan)
            return _study_summary(result, args.output), args.format
        if args.study_command == "run":
            if args.selection and args.scenario:
                raise TCOPCommandError("use --selection or explicit --scenario/--architecture, not both")
            if args.selection:
                if plan_kind == "evidence":
                    selection = "full" if args.selection in {"core", "primary"} else args.selection
                    result = run_evidence_study(args.artifact_dir, selection=selection, source_artifact=args.source_artifact, frozen_root=args.source)
                    return _evidence_summary(result, args.artifact_dir), args.format
                result = run_federated_study(args.artifact_dir, stage=_selection(args.selection), source_root=args.source, study_plan=args.plan)
                return _study_summary(result, args.artifact_dir), args.format
            return _single_cell(args), args.format
        if args.study_command == "replay": return _replay_run(args.run, args.source), args.format
        if args.study_command == "validate": return verify_artifact(args.artifact_dir, require_complete=True, require_replayable=True), args.format
        if args.study_command == "report":
            manifest = json.loads((args.artifact_dir / "manifest.json").read_text(encoding="utf-8"))
            if manifest.get("artifact_type") == "evidence-round":
                verified = verify_artifact(args.artifact_dir, require_replayable=True)
                return {"artifact_dir": str(args.artifact_dir), "report_regeneration": "content-addressed report set verified without changing its digest", "artifact_root_digest": verified["artifact_root_digest"], "valid": verified["valid"]}, args.format
            return _rebuild_report(args.artifact_dir), args.format
    if args.command == "artifact":
        if args.artifact_command == "verify": return verify_artifact(args.artifact_dir, require_complete=args.require_complete, require_replayable=args.require_replayable), args.format
        if args.artifact_command == "inspect": return inspect_artifact(args.artifact_dir), args.format
        if args.artifact_command == "manifest": return json.loads((args.artifact_dir / "manifest.json").read_text(encoding="utf-8")), args.format
        if args.artifact_command == "compare": return compare_artifacts(args.left, args.right), args.format
    return _legacy(args), args.format


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        value, output = dispatch(args)
        emit(value, output)
    except TCOPCommandError as exc:
        diagnostic(str(exc))
        raise SystemExit(exc.code) from exc
    except (AssertionError, OSError, ValueError) as exc:
        diagnostic(str(exc))
        raise SystemExit(EXIT_INVARIANT) from exc


if __name__ == "__main__":
    main()

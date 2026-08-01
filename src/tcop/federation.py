"""Deterministic TCOP v0.6 federated-domain evaluation harness.

This module is deliberately an *outer* harness.  It neither changes a TCX
wire record nor adds a resolver state: it creates signed v0.2 observations,
passes them to the frozen validators/resolvers, and records the consequences
of different observation architectures.  The five input/output streams are
kept structurally separate so that only the oracle can read benchmark truth.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections import defaultdict
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Mapping

from .canonical import canonical_bytes
from .confirmation import ConfirmationProfile, ConfirmationResolver
from .confirmation_benchmark import _profile_for
from .identity import AuthorityRegistry, KeyMaterial
from .reliability import Influence, ReliabilityLedger, ReliabilityProfile, WeightedResolver
from .responses import OperatingEnvelope, SimulatedResponseAdapter
from .regression import run_v01_regression, run_v02_regression, run_v03_regression, run_v04_regression
from .store import write_jsonl
from .trust import ReferenceResolver
from .witness import ControlGroupRegistry, Principal, WitnessValidator, make_interaction_receipt, make_v02_observation, receipt_hash


VERSION = "tcop.federated-domain/0.6"
PHASES = {
    "authored_telemetry": 0,
    "local_observation": 1,
    "frozen_batch_evaluation": 2,
    "context_publication": 3,
    "network_delivery": 4,
    "context_validation": 5,
    "resolution": 6,
    "enforcement": 7,
    "autonomous_action": 8,
    "metrics": 9,
}
UPSTREAM_DIGESTS = {
    "v0.1": "34e5a45bc6561a61b8001ce24206b481c2d01ae344fb81c311274824e2995cfa",
    "v0.2": "a9c5926fa97d3f19dad206aa1557957eca0385de3d771ccdf5ddfc0b63a3e2f0",
    "v0.3": "d0b23f5c54167d7b6d01c0bfeb6621f43e6113e6dc2d05dea9363ce700b0da94",
    "v0.4": "16849be9aca4405849f2a87e9e1ab2d5f726125e6a72e5440265f82ab424a127",
}
FROZEN_ROOT = Path("artifacts/minimality-v0.5-validation")
STUDY_PLAN = Path("benchmark/studies/v0.6-federated.yaml")
FROZEN_INDEX = "frozen-v0.6-profile-manifests.json"
SEED_PANEL = (42, 101, 211, 503, 997)


def _digest(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


@dataclass(frozen=True)
class StrategyBinding:
    strategy_id: str
    profile_name: str
    profile_id: str
    content_digest: str
    validator_entrypoint: str
    resolver_entrypoint: str
    fixture_corpus: tuple[str, ...]
    expected_decision_digest: str
    expected_outcome_digest: str


_BINDINGS = {
    "containment-first": StrategyBinding(
        "containment-first", "containment-first", "P2",
        "60a4c97851d19c6bcf09d24a063b480e9a29a49dca7e0665ead9013eaf8d2691",
        "tcop.witness.WitnessValidator", "tcop.trust.ReferenceResolver",
        ("B-001..B-070 × [42,101,211,503,997]",), "f8d735838bdab2cb35687dde615a3fccff94764f8ae0f236ab17fd958bd3377c", "29e02d59516657e450d31adc38f2a64abbc9b3261429d195b91acfabe3700833",
    ),
    "balanced": StrategyBinding(
        "balanced", "balanced", "V05_CONSOLIDATION_REDUCED",
        "4b2dfb385d71ee4ef3e8c598cf7cac4da80fdb62ed8d22d7ad241918c9e69890",
        "tcop.witness.WitnessValidator", "tcop.confirmation.ConfirmationResolver",
        ("B-001..B-070 × [42,101,211,503,997]",), "089682bc7455207d35f5a866196914f2a21934a6dbe543625361fa72d17e8bc1", "e346dd539f6ea15d39338168707663d356ce0152a1d50875df53cf01d48b8f7e",
    ),
    "utility-preserving": StrategyBinding(
        "utility-preserving", "utility-preserving", "F-10110000",
        "7cf402995d0b4c0e6473aaad4cca7b420abcccf35b7844b65935d07ee9db8940",
        "tcop.witness.WitnessValidator", "tcop.confirmation.ConfirmationResolver",
        ("B-001..B-070 × [42,101,211,503,997]",), "ee18c33d75c7cd1ba89f5d77c6b42b0674aa2555b31305611de1dc92b81080cd", "43220a2f88a6b570ed7e1bdcd71454a62b05c3c0ce0e44943e7305ab31e8e069",
    ),
    "forensic-oriented": StrategyBinding(
        "forensic-oriented", "forensic-extension", "P7",
        "e30ded1303d08c6067a5030d9e1741183bf30af96d218c2143bc1e21db237d96",
        "tcop.witness.WitnessValidator", "tcop.confirmation.ConfirmationResolver",
        ("B-001..B-070 × [42,101,211,503,997]",), "52a44ac8aa7b6c2ed9af92247163738628e87ae0b0aa56dc478e70430b8353dc", "9500f7e6fc34c0525935ba155a7703e6b8ed9ba7821fe5db5ec0bc1c27de03e0",
    ),
}
_MANIFEST_FIELDS = {
    "complexity_measurements", "content_digest", "dependencies", "enabled_features", "equivalence_classifications",
    "forensic_disposition", "frozen_profile_version", "known_failure_modes", "objective", "policy_parameters",
    "preventive_disposition", "profile_id", "profile_name", "selection_explanation", "selection_status",
    "supporting_artifacts", "v0.6_admission_scope",
}
_RUNTIME_CONFIGURATIONS = {
    # These fixed choices are a compatibility map from the frozen feature
    # closures; they are not scenario inputs or tunable v0.6 parameters.
    "containment-first": {"reliability": "not_applicable", "confirmation": "not_applicable"},
    "balanced": {"reliability": "frozen-v0.5-balanced-no-decay-or-hysteresis", "confirmation": "full_v0_4"},
    "utility-preserving": {"reliability": "frozen-v0.5-utility-no-decay-or-hysteresis", "confirmation": "provisional_no_campaign_grouping"},
    "forensic-oriented": {"reliability": "full_v0_3", "confirmation": "full_v0_4", "configuration_kind": "runtime_distinct_not_overlay"},
}


class FrozenStrategyAdapter:
    """Fail-closed certification binding immutable v0.5 records to v0.6.

    A binding intentionally has no setter for profile parameters.  Strategy
    selection is the only operation available to an architecture cell; all
    scenario material is supplied as immutable signed evidence after the
    strategy has been certified.
    """

    def __init__(self, source_root: Path = FROZEN_ROOT) -> None:
        self.source_root = source_root
        self.certified: dict[str, dict[str, Any]] = {}

    def _fixture_digests(self, binding: StrategyBinding) -> tuple[str, str, int]:
        """Check the declared historic fixture corpus, not a new v0.6 run."""

        freeze_path = self.source_root / "source-v0.5-freeze-manifest.json"
        if not freeze_path.is_file():
            raise ValueError("missing v0.5 source freeze manifest")
        freeze = _read_json(freeze_path)
        source_value = Path(str(freeze.get("source_artifact_root", "")))
        source_root = source_value if source_value.is_absolute() else Path.cwd() / source_value
        metric_path = source_root / "per-run-metrics.jsonl"
        if not metric_path.is_file():
            raise ValueError("missing frozen v0.5 fixture corpus")
        expected_file_digest = freeze.get("source_files", {}).get("per-run-metrics.jsonl")
        if expected_file_digest and sha256(metric_path.read_bytes()).hexdigest() != expected_file_digest:
            raise ValueError("frozen v0.5 fixture corpus digest mismatch")
        if binding.profile_id == "V05_CONSOLIDATION_REDUCED":
            metric_path = self.source_root / "consolidation-candidate-per-run-metrics.jsonl"
            if not metric_path.is_file():
                raise ValueError("missing consolidated frozen fixture corpus")
        decision_rows: list[dict[str, Any]] = []
        outcome_rows: list[dict[str, Any]] = []
        with metric_path.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                if row.get("profile_id") != binding.profile_id:
                    continue
                decision_rows.append({"scenario_id": row["scenario_id"], "seed": row["seed"], "native_decision_digest": row["native_decision_digest"]})
                outcome_rows.append({key: row[key] for key in ("scenario_id", "seed", "security_loss", "utility_loss", "operational_cost", "severity_weighted_harm")})
        decision_rows.sort(key=lambda item: (item["scenario_id"], item["seed"]))
        outcome_rows.sort(key=lambda item: (item["scenario_id"], item["seed"]))
        if len(decision_rows) != 350:
            raise ValueError(f"incomplete frozen fixture corpus: {binding.strategy_id}")
        return _digest(decision_rows), _digest(outcome_rows), len(decision_rows)

    def certify_all(self) -> dict[str, dict[str, Any]]:
        index_path = self.source_root / FROZEN_INDEX
        if not index_path.is_file():
            raise ValueError("missing frozen v0.5 profile index")
        index = _read_json(index_path)
        if index.get("frozen_profile_index_version") != "tcop.v0.5-validation-frozen-profile-index/0.1":
            raise ValueError("unsupported frozen profile index")
        indexed = {str(item.get("profile_name")): dict(item) for item in index.get("profiles", ())}
        certified: dict[str, dict[str, Any]] = {}
        for strategy_id, binding in sorted(_BINDINGS.items()):
            indexed_item = indexed.get(binding.profile_name)
            if indexed_item is None:
                raise ValueError(f"frozen profile missing: {binding.profile_name}")
            if set(indexed_item) != {"content_digest", "path", "profile_id", "profile_name"}:
                raise ValueError("unknown or incomplete frozen profile index fields")
            if indexed_item["profile_id"] != binding.profile_id or indexed_item["content_digest"] != binding.content_digest:
                raise ValueError(f"frozen binding mismatch: {strategy_id}")
            path = self.source_root / str(indexed_item["path"])
            payload = _read_json(path)
            if set(payload) - _MANIFEST_FIELDS or not {"content_digest", "enabled_features", "profile_id", "profile_name", "frozen_profile_version"} <= set(payload):
                raise ValueError(f"unknown or missing manifest fields: {strategy_id}")
            declared_digest = str(payload.get("content_digest"))
            recomputed = _digest({key: value for key, value in payload.items() if key != "content_digest"})
            if declared_digest != recomputed or declared_digest != binding.content_digest:
                raise ValueError(f"manifest content digest mismatch: {strategy_id}")
            if payload["profile_id"] != binding.profile_id or payload["profile_name"] != binding.profile_name:
                raise ValueError(f"manifest identifier mismatch: {strategy_id}")
            enabled = tuple(sorted(str(item) for item in payload["enabled_features"]))
            if len(enabled) != len(set(enabled)) or not enabled:
                raise ValueError(f"invalid feature closure: {strategy_id}")
            decision_digest, outcome_digest, fixture_count = self._fixture_digests(binding)
            if decision_digest != binding.expected_decision_digest or outcome_digest != binding.expected_outcome_digest:
                raise ValueError(f"frozen fixture result mismatch: {strategy_id}")
            # The profile payload is content-addressed above; this explicit
            # closure digest makes inclusion/exclusion auditable in every run.
            certified[strategy_id] = {
                "certification_version": "tcop.frozen-strategy-certification/0.1",
                "strategy_id": strategy_id,
                "canonical_manifest": binding.profile_id,
                "manifest_digest": binding.content_digest,
                "validator_entrypoint": binding.validator_entrypoint,
                "resolver_entrypoint": binding.resolver_entrypoint,
                "required_feature_closure": list(enabled),
                "required_feature_closure_digest": _digest(list(enabled)),
                "fixture_corpus": list(binding.fixture_corpus),
                "fixture_record_count": fixture_count,
                "expected_decision_digest": binding.expected_decision_digest,
                "expected_outcome_digest": binding.expected_outcome_digest,
                "fixed_runtime_compatibility_configuration": _RUNTIME_CONFIGURATIONS[strategy_id],
                "fixture_semantics": "frozen v0.5 native digest corpus; federation inputs cannot override profile parameters",
            }
        self.certified = certified
        return _copy_json(certified)

    def require(self, strategy_id: str) -> dict[str, Any]:
        if not self.certified:
            self.certify_all()
        if strategy_id not in self.certified:
            raise ValueError(f"uncertified frozen strategy: {strategy_id}")
        return _copy_json(self.certified[strategy_id])


@dataclass(frozen=True)
class Topology:
    topology_id: str
    domains: tuple[str, ...]
    trust_model: str


@dataclass(frozen=True)
class ObserverProfile:
    observer_id: str
    local_detection_delay: int
    coverage: str
    availability: str


@dataclass(frozen=True)
class NetworkProfile:
    network_id: str
    delay: int
    partition: tuple[int, int] | None = None
    drop: bool = False
    central_unavailable: bool = False


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    family: str
    malicious: bool
    origin_index: int = 0
    receiver_index: int = 1
    crosses_domain: bool = True
    origin_observation_at: int = 1
    receiver_observation_at: int = 5
    harmful_at: tuple[int, ...] = (4, 6)
    observed: bool = True
    receiver_capability: str = "tool:data.export"
    severity: str = "critical"
    false_warning: bool = False
    colluders: int = 1
    tampered: bool = False
    replay: bool = False
    sender_unavailable: bool = False
    disclosure: str = "hashes-only"
    central_outage: bool = False
    extra_receiver: bool = False


TOPOLOGIES = {
    "T1": Topology("T1", ("enterprise-us", "enterprise-eu", "enterprise-apac"), "intra_enterprise"),
    "T2": Topology("T2", ("provider", "platform", "downstream"), "partner_federation"),
    "T3": Topology("T3", ("internal-core", "internal-data", "external-partner"), "hybrid"),
}
OBSERVERS = {
    "O1": ObserverProfile("O1", 4, "strong_local", "available"),
    "O2": ObserverProfile("O2", 7, "partial_coverage", "available"),
    "O3": ObserverProfile("O3", 10, "degraded_coverage", "intermittent"),
}
NETWORKS = {
    "N0": NetworkProfile("N0", 1),
    "N1": NetworkProfile("N1", 3),
    "N2": NetworkProfile("N2", 7),
    "N3": NetworkProfile("N3", 2, partition=(2, 6)),
    "N4": NetworkProfile("N4", 3, drop=True, central_unavailable=True),
}
ARCHITECTURES = {
    "A0": "no_defense",
    "A1": "isolated_local",
    "A2": "federated_tcop",
    "A3": "bounded_central",
    "A4": "full_telemetry_upper_bound",
    "A5": "truth_oracle_upper_bound",
}
SCENARIOS = {
    "S01": Scenario("S01", "Origin prompt injection crosses to receiver", "opportunity", True),
    "S02": Scenario("S02", "Origin memory contamination crosses to receiver", "opportunity", True, receiver_capability="memory.write"),
    "S03": Scenario("S03", "Credential abuse reaches downstream", "opportunity", True, receiver_capability="financial.transfer"),
    "S04": Scenario("S04", "Multi-hop propagation", "opportunity", True, extra_receiver=True),
    "S05": Scenario("S05", "Fragmented warning evidence", "opportunity", True, colluders=2),
    "S06": Scenario("S06", "Receiver detects first", "negative_control", True, origin_observation_at=5, receiver_observation_at=1),
    "S07": Scenario("S07", "No cross-domain propagation", "negative_control", True, crosses_domain=False),
    "S08": Scenario("S08", "False external warning", "negative_control", False, false_warning=True),
    "S09": Scenario("S09", "Colluding external warnings", "adversarial", False, false_warning=True, colluders=3),
    "S10": Scenario("S10", "Conflicting clean and threat evidence", "adversarial", True, colluders=2),
    "S11": Scenario("S11", "Delayed imported warning", "timing", True, harmful_at=(3, 5, 7)),
    "S12": Scenario("S12", "Partition then synchronization after heal", "resilience", True, harmful_at=(4, 7, 9)),
    "S13": Scenario("S13", "Central observer outage", "resilience", True, central_outage=True),
    "S14": Scenario("S14", "Sender local observer unavailable", "resilience", True, sender_unavailable=True),
    "S15": Scenario("S15", "Bounded disclosure", "privacy", True, disclosure="hashes-only"),
    "S16": Scenario("S16", "Benign high-volume workflow", "utility", False, false_warning=True, colluders=2),
    "S17": Scenario("S17", "Fast cross-domain campaign", "timing", True, harmful_at=(2, 3, 4), extra_receiver=True),
    "S18": Scenario("S18", "Tampered and replayed imported evidence", "adversarial", True, tampered=True, replay=True),
}


@dataclass(frozen=True)
class MatrixCell:
    cell_id: str
    topology_id: str
    scenario_id: str
    observer_id: str
    network_id: str
    architecture_id: str
    strategy_id: str | None
    seed: int
    classification: str
    disposition: str = "scheduled"
    reason: str = ""


def _cell_id(values: Mapping[str, Any]) -> str:
    return "-".join(str(values[key]) for key in ("topology_id", "scenario_id", "observer_id", "network_id", "architecture_id", "strategy_id", "seed"))


def generate_matrix(stage: str = "full") -> list[MatrixCell]:
    """Return a pre-registered, explicit complete/deployment matrix.

    Full execution keeps the primary set compact but complete.  Sensitivity and
    upper-bound cells are deliberately labelled so they cannot enter a
    deployment Pareto frontier by accident.
    """

    cells: list[MatrixCell] = []
    primary_scenarios = tuple(SCENARIOS)
    topologies = tuple(TOPOLOGIES)
    for topology_id in topologies:
        for scenario_id in primary_scenarios:
            for architecture_id in ("A0", "A1", "A3"):
                values = {"topology_id": topology_id, "scenario_id": scenario_id, "observer_id": "O1", "network_id": "N0", "architecture_id": architecture_id, "strategy_id": "none", "seed": 42}
                classification = "negative_control" if SCENARIOS[scenario_id].family in {"negative_control", "adversarial", "utility"} else "primary_deployment_cell"
                cells.append(MatrixCell(_cell_id(values), **values, classification=classification))
            for strategy_id in ("containment-first", "balanced", "utility-preserving"):
                values = {"topology_id": topology_id, "scenario_id": scenario_id, "observer_id": "O1", "network_id": "N0", "architecture_id": "A2", "strategy_id": strategy_id, "seed": 42}
                classification = "negative_control" if SCENARIOS[scenario_id].family in {"negative_control", "adversarial", "utility"} else "primary_deployment_cell"
                cells.append(MatrixCell(_cell_id(values), **values, classification=classification))
    # Time sensitivity, observer sensitivity, and failure conditions.
    for topology_id in topologies:
        for scenario_id, observer_id, network_id, seed in (("S11", "O1", "N1", 42), ("S11", "O1", "N2", 101), ("S12", "O2", "N3", 211), ("S13", "O2", "N4", 503), ("S17", "O3", "N2", 997)):
            for architecture_id in ("A1", "A2", "A3"):
                strategy_id = "balanced" if architecture_id == "A2" else "none"
                values = {"topology_id": topology_id, "scenario_id": scenario_id, "observer_id": observer_id, "network_id": network_id, "architecture_id": architecture_id, "strategy_id": strategy_id, "seed": seed}
                cells.append(MatrixCell(_cell_id(values), **values, classification="sensitivity_cell"))
    # Explicitly separated upper bounds and P7 forensic evaluation.
    for topology_id in topologies:
        for scenario_id in ("S01", "S04", "S11", "S15", "S17"):
            for architecture_id in ("A4", "A5"):
                values = {"topology_id": topology_id, "scenario_id": scenario_id, "observer_id": "O1", "network_id": "N0", "architecture_id": architecture_id, "strategy_id": "none", "seed": 42}
                cells.append(MatrixCell(_cell_id(values), **values, classification="upper_bound"))
            values = {"topology_id": topology_id, "scenario_id": scenario_id, "observer_id": "O1", "network_id": "N0", "architecture_id": "A2", "strategy_id": "forensic-oriented", "seed": 42}
            cells.append(MatrixCell(_cell_id(values), **values, classification="forensic_cell"))
    # Include specific no-value controls with no deployment-selection status.
    for topology_id in topologies:
        for scenario_id in ("S06", "S07", "S08", "S09", "S16"):
            values = {"topology_id": topology_id, "scenario_id": scenario_id, "observer_id": "O1", "network_id": "N0", "architecture_id": "A2", "strategy_id": "balanced", "seed": 42}
            cells.append(MatrixCell(_cell_id(values), **values, classification="negative_control"))
    unique = {cell.cell_id: cell for cell in cells}
    selected = [unique[key] for key in sorted(unique)]
    if stage == "smoke":
        requested = ("S01", "S06", "S08", "S11", "S12", "S18")
        selected = [item for item in selected if item.scenario_id in requested and item.topology_id == "T1"]
    elif stage == "core":
        selected = [
            item
            for item in selected
            if item.classification == "primary_deployment_cell"
            and item.observer_id == "O1"
            and item.network_id == "N0"
            and item.seed == 42
            and item.architecture_id in {"A0", "A1", "A2", "A3"}
        ]
    return selected


class _StrategyRuntime:
    """Receiver-local frozen processing surface; never sees benchmark truth."""

    def __init__(self, domain_id: str, strategy_id: str, identities: AuthorityRegistry, groups: ControlGroupRegistry, receipts: Mapping[str, Mapping[str, Any]]) -> None:
        self.domain_id, self.strategy_id = domain_id, strategy_id
        self.validator = WitnessValidator(identities, groups, receipts, {}, {})
        self.observations: dict[str, dict[str, Any]] = {}
        self.validation_events: list[dict[str, Any]] = []
        self.decision_events: list[dict[str, Any]] = []
        self.responses = SimulatedResponseAdapter()
        self.envelope = OperatingEnvelope("unknown", actions=("observe",), reasons=("no current evidence",))
        self.reference = ReferenceResolver() if strategy_id == "containment-first" else None
        ledger_profile = ReliabilityProfile()
        if strategy_id == "balanced":
            ledger_profile = replace(ledger_profile, profile_id="frozen-v0.5-balanced", reliability_decay=False, hysteresis=False)
        elif strategy_id == "utility-preserving":
            ledger_profile = replace(ledger_profile, profile_id="frozen-v0.5-utility-preserving", reliability_decay=False, hysteresis=False)
        elif strategy_id == "forensic-oriented":
            ledger_profile = replace(ledger_profile, profile_id="frozen-v0.5-forensic-oriented")
        self.ledger = ReliabilityLedger(domain_id, ledger_profile) if strategy_id != "containment-first" else None
        self.weighted = WeightedResolver(domain_id, self.ledger) if self.ledger else None
        if strategy_id == "utility-preserving":
            profile = _profile_for("provisional_no_campaign_grouping")
        else:
            profile = ConfirmationProfile()
        self.confirmation = ConfirmationResolver(domain_id, profile) if strategy_id != "containment-first" else None

    def receive(self, observation: Mapping[str, Any], at: int, *, source: str, direct_local: bool) -> bool:
        result = self.validator.validate(observation, at)
        event = {
            "stream": "produced_observations", "event_type": "observation_validated", "at": at,
            "receiver_domain": self.domain_id, "source": source, "observation_id": observation.get("observation_id"),
            "accepted": result.accepted, "code": result.code, "effective_evidence_class": result.effective_evidence_class,
            "receipt_verified": result.receipt_verified,
        }
        self.validation_events.append(event)
        if not result.accepted:
            return False
        observation_id = str(observation["observation_id"])
        if observation_id in self.observations:
            self.validation_events.append({**event, "event_type": "observation_rejected", "accepted": False, "code": "replay_detected"})
            return False
        stored = deepcopy(dict(observation))
        stored.update({"effective_evidence_class": result.effective_evidence_class, "receipt_verified": result.receipt_verified, "direct_local": direct_local})
        self.observations[observation_id] = stored
        return True

    def resolve(self, subject_id: str, at: int) -> OperatingEnvelope:
        if self.reference is not None:
            envelope = self.reference.resolve(subject_id, self.observations.values(), at)
            explanation: Mapping[str, Any] = {"resolver": "ReferenceResolver", "observation_count": len(self.observations)}
        else:
            assert self.weighted is not None and self.confirmation is not None
            influences = {item_id: self.weighted.evaluate(item, at) for item_id, item in self.observations.items()}
            outcomes = self.confirmation.process_batch(self.observations.values(), influences, at)
            envelope = outcomes.get(subject_id)
            if envelope is None:
                envelope, explanation = self.weighted.resolve(subject_id, self.observations.values(), at)
            else:
                explanation = {"resolver": "ConfirmationResolver", "influences": [item.as_dict() for item in influences.values()]}
        changed = envelope != self.envelope
        self.envelope = envelope
        self.responses.apply(subject_id, envelope, at, source="frozen_local_strategy")
        self.decision_events.append({
            "stream": "derived_decisions", "event_type": "local_resolution", "at": at, "domain_id": self.domain_id,
            "strategy_id": self.strategy_id, "state": envelope.state, "changed": changed,
            "envelope": envelope.to_dict(), "explanation": dict(explanation),
        })
        return envelope


class FederatedRun:
    """One phase-ordered deterministic architecture run over five streams."""

    def __init__(
        self,
        cell: MatrixCell,
        adapter: FrozenStrategyAdapter,
        *,
        diagnostic_central_strategy: str | None = None,
        diagnostic_local_fallback: bool = False,
        diagnostic_network: NetworkProfile | None = None,
    ) -> None:
        self.cell = cell
        self.topology = TOPOLOGIES[cell.topology_id]
        self.scenario = SCENARIOS[cell.scenario_id]
        self.observer = OBSERVERS[cell.observer_id]
        self.network = NETWORKS[cell.network_id]
        self.adapter = adapter
        self.events: dict[str, list[dict[str, Any]]] = {name: [] for name in ("authored_facts", "benchmark_truth", "produced_observations", "transport_faults", "derived_decisions")}
        self.identities = AuthorityRegistry()
        self.groups = ControlGroupRegistry()
        self.keys: dict[str, KeyMaterial] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.runtimes: dict[str, _StrategyRuntime] = {}
        self.pending: list[dict[str, Any]] = []
        self.a2_exports: list[dict[str, Any]] = []
        self.a3_inputs: list[dict[str, Any]] = []
        self.harm: list[dict[str, Any]] = []
        self._sequence: dict[str, int] = defaultdict(int)
        self._event_sequence = 0
        self._phase = PHASES["authored_telemetry"]
        self.diagnostic_central_strategy = diagnostic_central_strategy
        self.diagnostic_local_fallback = diagnostic_local_fallback
        if diagnostic_network is not None:
            self.network = diagnostic_network
        self._setup_universe()

    @property
    def _authored_input_id(self) -> str:
        """Architecture-independent identity for authored telemetry/evidence."""
        return "::".join((self.cell.topology_id, self.cell.scenario_id, self.cell.observer_id, self.cell.network_id, str(self.cell.seed)))

    def _setup_universe(self) -> None:
        for domain_id in self.topology.domains:
            observer_id = f"observer::{domain_id}"
            self._register(observer_id, domain_id, f"control::{domain_id}", "peer")
        self._register("subject::workflow", "workflow", "control::workflow", "subject")
        strategy = self.cell.strategy_id if self.cell.strategy_id not in {None, "none"} else "containment-first"
        if self.cell.architecture_id in {"A1", "A2"}:
            for domain_id in self.topology.domains:
                self.runtimes[domain_id] = _StrategyRuntime(domain_id, strategy, self.identities, self.groups, self.receipts)
        elif self.cell.architecture_id == "A3":
            self.runtimes["central"] = _StrategyRuntime("central", "containment-first", self.identities, self.groups, self.receipts)
            if self.diagnostic_central_strategy:
                self.runtimes["central"] = _StrategyRuntime("central", self.diagnostic_central_strategy, self.identities, self.groups, self.receipts)
            if self.diagnostic_local_fallback:
                for domain_id in self.topology.domains:
                    self.runtimes[f"fallback::{domain_id}"] = _StrategyRuntime(domain_id, "containment-first", self.identities, self.groups, self.receipts)
        elif self.cell.architecture_id == "A4":
            self.runtimes["full-telemetry"] = _StrategyRuntime("full-telemetry", "containment-first", self.identities, self.groups, self.receipts)

    def _register(self, principal_id: str, domain_id: str, group_id: str, role: str) -> None:
        key = KeyMaterial.deterministic(principal_id, domain_id)
        self.keys[principal_id] = key
        self.identities.register(key.identity)
        self.groups.register(Principal(principal_id, domain_id, group_id, role))

    @property
    def origin(self) -> str:
        return self.topology.domains[self.scenario.origin_index % len(self.topology.domains)]

    @property
    def receiver(self) -> str:
        return self.topology.domains[self.scenario.receiver_index % len(self.topology.domains)]

    def _event(self, stream: str, event_type: str, at: int, **values: Any) -> None:
        phase_name = next(name for name, value in PHASES.items() if value == self._phase)
        domain = str(values.get("domain") or values.get("source_domain") or values.get("receiver_domain") or values.get("target") or values.get("enforcement_domain") or values.get("decision_authority") or "")
        topology_order = self.topology.domains.index(domain) if domain in self.topology.domains else len(self.topology.domains)
        self._event_sequence += 1
        self.events[stream].append({"stream": stream, "event_type": event_type, "at": at, "phase": self._phase, "phase_name": phase_name, "topology_order": topology_order, "sequence": self._event_sequence, **values})

    def _observation(self, domain_id: str, at: int, sequence_salt: int = 0) -> dict[str, Any]:
        observer_id = f"observer::{domain_id}"
        self._sequence[observer_id] += 1
        key = self.keys[observer_id]
        receipt = make_interaction_receipt(
            key, self.keys["subject::workflow"], self.groups,
            interaction_id=f"interaction::{self._authored_input_id}::{domain_id}::{at}::{sequence_salt}",
            capability=self.scenario.receiver_capability, now=at,
        )
        receipt_digest = receipt_hash(receipt)
        self.receipts[receipt_digest] = receipt
        observation = make_v02_observation(
            key, self.groups, subject_id="subject::workflow", observation_type="tool.prohibited_export" if self.scenario.receiver_capability != "memory.write" else "memory.contamination",
            scope=(self.scenario.receiver_capability,), now=at, sequence_number=self._sequence[observer_id], ttl=8,
            severity=self.scenario.severity, declared_evidence_class="independent_peer", observation_mode="passive",
            interaction_id=receipt["interaction_id"], interaction_receipt_hash=receipt_digest, receipt_mode=receipt["receipt_mode"],
            privacy_profile=self.scenario.disclosure,
        )
        return observation

    def _in_partition(self, at: int) -> bool:
        return bool(self.network.partition and self.network.partition[0] <= at <= self.network.partition[1])

    def _publish(self, observation: Mapping[str, Any], at: int) -> None:
        prior_phase = self._phase
        self._phase = PHASES["context_publication"]
        if self.cell.architecture_id not in {"A2", "A3"}:
            self._phase = prior_phase
            return
        if self.scenario.sender_unavailable:
            self._event("transport_faults", "context_not_published_sender_unavailable", at, observation_id=observation["observation_id"])
            self._phase = prior_phase
            return
        exported = _copy_json(observation)
        record = {"observation": exported, "published_at": at, "origin_domain": self.origin, "export_digest": _digest(exported)}
        self.a2_exports.append(record)
        self._event("transport_faults", "context_published", at, observation_id=exported["observation_id"], export_digest=record["export_digest"])
        if self.cell.architecture_id == "A3":
            self.a3_inputs.append(_copy_json(record))
            target, route = "central", "bounded_central_copy"
        else:
            target, route = self.receiver, "tcop_gateway"
        delivery_at = at + self.network.delay
        if self._in_partition(delivery_at):
            if self.network.partition:
                delivery_at = self.network.partition[1] + 1 + self.network.delay
                self._event("transport_faults", "delivery_deferred_by_partition", at, observation_id=exported["observation_id"], rescheduled_at=delivery_at)
        if self.network.drop:
            self._event("transport_faults", "delivery_dropped", at, observation_id=exported["observation_id"], route=route)
            self._phase = prior_phase
            return
        self.pending.append({"at": delivery_at, "target": target, "route": route, "observation": exported, "export_digest": record["export_digest"]})
        if self.scenario.tampered:
            tampered = _copy_json(exported)
            tampered["severity"] = "low"  # transport corruption invalidates the original signature.
            self.pending.append({"at": delivery_at + 1, "target": target, "route": route, "observation": tampered, "export_digest": record["export_digest"], "tampered": True})
        if self.scenario.replay:
            self.pending.append({"at": delivery_at + 2, "target": target, "route": route, "observation": _copy_json(exported), "export_digest": record["export_digest"], "replay": True})
        self._phase = prior_phase

    def _local_observe(self, domain_id: str, at: int, *, source: str) -> None:
        observation = self._observation(domain_id, at)
        self._event("produced_observations", "signed_observation_produced", at, source_domain=domain_id, observation=observation, source=source)
        if self.cell.architecture_id in {"A1", "A2"} or (self.cell.architecture_id == "A3" and self.diagnostic_local_fallback):
            runtime_key = domain_id if self.cell.architecture_id in {"A1", "A2"} else f"fallback::{domain_id}"
            self.runtimes[runtime_key].receive(observation, at, source="local_observer", direct_local=True)
            self._event("produced_observations", "observation_validated", at, **{key: value for key, value in self.runtimes[runtime_key].validation_events[-1].items() if key not in {"stream", "event_type", "at"}})
        elif self.cell.architecture_id == "A4":
            self.runtimes["full-telemetry"].receive(observation, at, source="full_telemetry", direct_local=True)
            self._event("produced_observations", "observation_validated", at, **{key: value for key, value in self.runtimes["full-telemetry"].validation_events[-1].items() if key not in {"stream", "event_type", "at"}})
        self._publish(observation, at)
        if self.scenario.colluders > 1:
            for index in range(1, self.scenario.colluders):
                colluder = self.topology.domains[(self.scenario.origin_index + index) % len(self.topology.domains)]
                additional = self._observation(colluder, at, index)
                self._event("produced_observations", "signed_observation_produced", at, source_domain=colluder, observation=additional, source="colluding_observer")
                if self.cell.architecture_id in {"A1", "A2"} or (self.cell.architecture_id == "A3" and self.diagnostic_local_fallback):
                    runtime_key = colluder if self.cell.architecture_id in {"A1", "A2"} else f"fallback::{colluder}"
                    self.runtimes[runtime_key].receive(additional, at, source="local_observer", direct_local=True)
                    self._event("produced_observations", "observation_validated", at, **{key: value for key, value in self.runtimes[runtime_key].validation_events[-1].items() if key not in {"stream", "event_type", "at"}})
                elif self.cell.architecture_id == "A4":
                    self.runtimes["full-telemetry"].receive(additional, at, source="full_telemetry", direct_local=True)
                    self._event("produced_observations", "observation_validated", at, **{key: value for key, value in self.runtimes["full-telemetry"].validation_events[-1].items() if key not in {"stream", "event_type", "at"}})
                self._publish(additional, at)

    def _deliver(self, at: int) -> None:
        deliveries = sorted((item for item in self.pending if item["at"] == at), key=lambda item: (item["target"], item.get("replay", False), item["export_digest"]))
        for item in deliveries:
            target = str(item["target"])
            prior_phase = self._phase
            self._phase = PHASES["context_validation"]
            result = self.runtimes[target].receive(item["observation"], at, source=str(item["route"]), direct_local=False)
            self._event("produced_observations", "observation_validated", at, **{key: value for key, value in self.runtimes[target].validation_events[-1].items() if key not in {"stream", "event_type", "at"}})
            self._phase = prior_phase
            self._event("transport_faults", "context_delivered" if result else "context_rejected", at, target=target, observation_id=item["observation"]["observation_id"], route=item["route"], replay=bool(item.get("replay")), export_digest=item["export_digest"])

    def _resolve(self, at: int) -> dict[str, OperatingEnvelope]:
        outcomes: dict[str, OperatingEnvelope] = {}
        if self.cell.architecture_id in {"A1", "A2"}:
            for domain_id, runtime in sorted(self.runtimes.items()):
                outcomes[domain_id] = runtime.resolve("subject::workflow", at)
        elif self.cell.architecture_id == "A3":
            if self.scenario.central_outage or self.network.central_unavailable:
                self._event("transport_faults", "central_unavailable", at, architecture="A3")
            else:
                outcomes["central"] = self.runtimes["central"].resolve("subject::workflow", at)
            if self.diagnostic_local_fallback:
                for domain_id in self.topology.domains:
                    outcomes[f"fallback::{domain_id}"] = self.runtimes[f"fallback::{domain_id}"].resolve("subject::workflow", at)
        elif self.cell.architecture_id == "A4":
            outcomes["full-telemetry"] = self.runtimes["full-telemetry"].resolve("subject::workflow", at)
        elif self.cell.architecture_id == "A5":
            state = "oracle_quarantine" if self.scenario.malicious else "healthy"
            outcomes["oracle"] = OperatingEnvelope(state, denied_capabilities=("*",) if self.scenario.malicious else (), actions=("quarantine",) if self.scenario.malicious else ("allow",), reasons=("benchmark_truth_oracle",))
            self._event("derived_decisions", "oracle_resolution", at, state=state, truth_accessed=True)
        for authority, envelope in outcomes.items():
            self._event("derived_decisions", "architecture_resolution", at, decision_authority=authority, state=envelope.state, envelope=envelope.to_dict())
        self._phase = PHASES["enforcement"]
        for authority, envelope in outcomes.items():
            fallback = authority.startswith("fallback::")
            enforcement_domain = authority.removeprefix("fallback::") if fallback else (self.receiver if self.cell.architecture_id in {"A1", "A2"} else authority)
            self._event("derived_decisions", "enforcement_intent", at, decision_authority=authority, enforcement_domain=enforcement_domain, remote_enforcement=False if (self.cell.architecture_id == "A2" or fallback) else self.cell.architecture_id == "A3", state=envelope.state, envelope=envelope.to_dict())
        return outcomes

    @staticmethod
    def _protective(envelope: OperatingEnvelope | None, capability: str) -> bool:
        if envelope is None:
            return False
        return envelope.state in {"quarantined", "confirmed_quarantine", "constrained", "provisionally_constrained", "oracle_quarantine"} or capability in envelope.denied_capabilities or "*" in envelope.denied_capabilities

    def _receiver_envelope(self, outcomes: Mapping[str, OperatingEnvelope]) -> OperatingEnvelope | None:
        if self.cell.architecture_id in {"A1", "A2"}:
            return outcomes.get(self.receiver)
        if self.cell.architecture_id == "A3":
            if self.diagnostic_local_fallback:
                return outcomes.get(f"fallback::{self.receiver}")
            return outcomes.get("central")
        if self.cell.architecture_id == "A4":
            return outcomes.get("full-telemetry")
        return outcomes.get("oracle")

    def run(self) -> dict[str, Any]:
        # Truth is emitted exclusively here and never passed to a runtime.
        self._phase = PHASES["authored_telemetry"]
        self._event("authored_facts", "scenario_authored", 0, scenario_id=self.scenario.scenario_id, topology_id=self.topology.topology_id, observer_profile=self.observer.observer_id, network_profile=self.network.network_id)
        self._event("benchmark_truth", "ground_truth", 0, malicious=self.scenario.malicious, intended_harm_ticks=list(self.scenario.harmful_at), allowed_reader="A5_only")
        max_tick = max((*self.scenario.harmful_at, self.scenario.origin_observation_at, self.scenario.receiver_observation_at, 10)) + 2
        outcomes: dict[str, OperatingEnvelope] = {}
        local_detection = self.scenario.receiver_observation_at if self.scenario.observed else 10_000
        if self.observer.observer_id == "O2":
            local_detection += 2
        elif self.observer.observer_id == "O3":
            local_detection += 5
        for at in range(max_tick + 1):
            # Phase 0 authored telemetry records conditions only.
            self._phase = PHASES["authored_telemetry"]
            if at in {self.scenario.origin_observation_at, local_detection}:
                self._event("authored_facts", "telemetry_available", at, domain=self.origin if at == self.scenario.origin_observation_at else self.receiver)
            # Phase 1 observer production is identical across A1/A2.
            self._phase = PHASES["local_observation"]
            if self.cell.architecture_id not in {"A0", "A5"} and self.scenario.observed and at == self.scenario.origin_observation_at and not self.scenario.sender_unavailable:
                self._local_observe(self.origin, at, source="origin")
            if self.cell.architecture_id not in {"A0", "A5"} and self.scenario.observed and at == local_detection and (self.scenario.crosses_domain or self.receiver == self.origin):
                self._local_observe(self.receiver, at, source="receiver")
            # A4 alone receives direct broader telemetry from each remaining
            # domain. It is an information upper bound, not TCOP transport.
            if self.cell.architecture_id == "A4" and self.scenario.observed and at == self.scenario.origin_observation_at:
                for domain_id in self.topology.domains:
                    if domain_id not in {self.origin, self.receiver}:
                        self._local_observe(domain_id, at, source="full_telemetry_additional")
            # Phase 2 is a frozen batch boundary. Existing ledger/resolver
            # classes retain their own snapshot-isolated same-time semantics.
            self._phase = PHASES["frozen_batch_evaluation"]
            self._event("derived_decisions", "frozen_batch_boundary", at)
            # Phase 4/5 delivery/receiver validation.
            self._phase = PHASES["network_delivery"]
            self._deliver(at)
            # Phase 6/7 local or architectural decision/enforcement intent.
            self._phase = PHASES["resolution"]
            outcomes = self._resolve(at)
            # Phase 8 autonomous action uses only architecture decisions.
            self._phase = PHASES["autonomous_action"]
            if at in self.scenario.harmful_at:
                protective = self._protective(self._receiver_envelope(outcomes), self.scenario.receiver_capability)
                occurred = bool(self.scenario.malicious and self.scenario.crosses_domain and not protective)
                harm = {"at": at, "domain": self.receiver, "capability": self.scenario.receiver_capability, "attempted": self.scenario.malicious, "occurred": occurred, "protected": protective}
                self.harm.append(harm)
                self._event("derived_decisions", "autonomous_action", at, **{key: value for key, value in harm.items() if key != "at"})
            self._phase = PHASES["metrics"]
            self._event("derived_decisions", "metrics_tick", at)
        return self._summary()

    def _summary(self) -> dict[str, Any]:
        derived = self.events["derived_decisions"]
        harmful = [item for item in self.harm if item["occurred"]]
        protection_events = [item for item in derived if item["event_type"] == "enforcement_intent" and item["state"] not in {"unknown", "healthy", "suspicious", "monitored"}]
        first_protection = min((item["at"] for item in protection_events), default=None)
        imported = [item for item in self.events["transport_faults"] if item["event_type"] == "context_delivered"]
        first_import = min((item["at"] for item in imported), default=None)
        validation = [item for runtime in self.runtimes.values() for item in runtime.validation_events]
        decisions = [item for runtime in self.runtimes.values() for item in runtime.decision_events]
        streams_digest = _digest(self.events)
        observation_count = sum(1 for item in self.events["produced_observations"] if item["event_type"] == "signed_observation_produced")
        metrics = {
            "harmful_actions": len(harmful),
            "prevented_actions": len(self.scenario.harmful_at) - len(harmful) if self.scenario.malicious else 0,
            "attack_success": bool(harmful),
            "blast_radius_domains": len({item["domain"] for item in harmful}),
            "first_import_at": first_import,
            "first_protection_at": first_protection,
            "early_warning_lead_time": (self.scenario.receiver_observation_at - first_import) if first_import is not None else None,
            "containment_latency": (first_protection - self.scenario.origin_observation_at) if first_protection is not None else None,
            "false_containment": bool(not self.scenario.malicious and first_protection is not None),
            "protocol_observations": observation_count,
            "validated_observations": sum(1 for item in validation if item["accepted"]),
            "rejected_observations": sum(1 for item in validation if not item["accepted"]),
            "forensic_records": len(validation) + len(decisions) + len(self.events["transport_faults"]),
            "utility_restriction_ticks": sum(1 for item in protection_events if not self.scenario.malicious),
        }
        return {
            "run_version": VERSION,
            "cell": asdict(self.cell),
            "topology": asdict(self.topology),
            "scenario": asdict(self.scenario),
            "metrics": metrics,
            "stream_digest": streams_digest,
            "a2_export_digests": [item["export_digest"] for item in self.a2_exports],
            "a3_input_digests": [item["export_digest"] for item in self.a3_inputs],
            "result": "pass",
        }

    def write(self, root: Path, summary: Mapping[str, Any]) -> Path:
        run_root = root / "runs" / self.cell.cell_id
        run_root.mkdir(parents=True, exist_ok=True)
        for stream, records in self.events.items():
            write_jsonl(run_root / f"{stream}.jsonl", sorted(records, key=lambda item: (int(item["at"]), int(item["phase"]), int(item["topology_order"]), int(item["sequence"]))))
        _write_json(run_root / "summary.json", summary)
        _write_json(run_root / "export-stream.json", self.a2_exports)
        _write_json(run_root / "a3-bounded-input-stream.json", self.a3_inputs)
        return run_root


def _non_destructive_prepare(root: Path) -> None:
    """Avoid deleting a user directory: only v0.6-owned generation roots move."""
    root.mkdir(parents=True, exist_ok=True)
    for name in ("runs", "summaries", "reports", "plots", "validation", "matrix", "contracts"):
        target = root / name
        if target.exists():
            shutil.rmtree(target)


def write_experiment_contracts(root: Path, *, study_plan: Path = STUDY_PLAN) -> None:
    """Publish the declarative v0.6 study surface beside, not inside, runs."""

    contracts = root / "contracts"
    _write_json(contracts / "topologies.json", [asdict(item) for item in TOPOLOGIES.values()])
    _write_json(contracts / "observer-profiles.json", [asdict(item) for item in OBSERVERS.values()])
    _write_json(contracts / "network-profiles.json", [asdict(item) for item in NETWORKS.values()])
    _write_json(contracts / "architectures.json", ARCHITECTURES)
    _write_json(contracts / "scenarios.json", [asdict(item) for item in SCENARIOS.values()])
    _write_json(contracts / "phase-order.json", PHASES)
    (root / "experiment-plan.yaml").write_text(study_plan.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "README.md").write_text(
        "# TCOP v0.6 deterministic federated-domain artifacts\n\n"
        "This root contains only v0.6 outputs. Frozen v0.1-v0.5 artifacts are read-only inputs. "
        "The five JSONL streams in each run are authored facts, benchmark truth, produced observations, "
        "transport/fault records, and derived decisions. Only A5 may consume benchmark truth.\n",
        encoding="utf-8",
    )


def verify_frozen_inputs(source_root: Path = FROZEN_ROOT, *, adapter: FrozenStrategyAdapter | None = None) -> dict[str, Any]:
    """Reproduce upstream suites in temporary roots and certify profile inputs."""

    adapter = adapter or FrozenStrategyAdapter(source_root)
    certified = adapter.certify_all()
    with tempfile.TemporaryDirectory() as temporary:
        check = Path(temporary)
        upstream = {
            "v0.1": run_v01_regression(check / "v0.1"),
            "v0.2": run_v02_regression(check / "v0.2"),
            "v0.3": run_v03_regression(check / "v0.3"),
            "v0.4": run_v04_regression(check / "v0.4"),
        }
    if any(not item["passed"] or item["suite_digest"] != UPSTREAM_DIGESTS[version] for version, item in upstream.items()):
        raise AssertionError("frozen v0.1-v0.4 regression mismatch")
    return {"verification_version": "tcop.v0.6-frozen-inputs/0.1", "upstream_frozen_digests": UPSTREAM_DIGESTS, "upstream_regressions": upstream, "strategy_certifications": certified, "passed": True}


def _run_cells(root: Path, cells: Iterable[MatrixCell], adapter: FrozenStrategyAdapter) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for cell in cells:
        if cell.architecture_id == "A2":
            adapter.require(str(cell.strategy_id))
        run = FederatedRun(cell, adapter)
        summary = run.run()
        run.write(root, summary)
        summaries.append(summary)
    return summaries


def _state_by_tick(run_root: Path, domain: str) -> dict[int, str]:
    results: dict[int, str] = {}
    path = run_root / "derived_decisions.jsonl"
    if not path.is_file():
        return results
    for line in path.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        if item.get("event_type") == "enforcement_intent" and item.get("decision_authority") == domain:
            results[int(item["at"])] = str(item["state"])
    return results


def validate_harness(root: Path, smoke_summaries: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Structural v0.6 conformance checks, independent of research outcomes."""
    summaries = [dict(item) for item in smoke_summaries]
    run_map = {item["cell"]["cell_id"]: item for item in summaries}
    checks: list[dict[str, Any]] = []
    # Signed boundary: one A2 S01 run must carry a receipt-verified delivered fact.
    a2 = next(item for item in summaries if item["cell"]["architecture_id"] == "A2" and item["cell"]["scenario_id"] == "S01" and item["cell"]["strategy_id"] == "containment-first")
    a2_root = root / "runs" / a2["cell"]["cell_id"]
    validation = [json.loads(line) for line in (a2_root / "produced_observations.jsonl").read_text(encoding="utf-8").splitlines()]
    signed_cross = any(item.get("event_type") == "observation_validated" and item.get("source") == "tcop_gateway" and item.get("accepted") and item.get("receipt_verified") for item in validation)
    checks.append({"check": "signed_fact_crosses_boundary", "passed": signed_cross})
    # A1/A2 use matching local observation bytes and receiver state before the
    # first imported fact. They differ only after a verified context delivery.
    a1 = next(item for item in summaries if item["cell"]["architecture_id"] == "A1" and item["cell"]["scenario_id"] == "S01")
    a1_root = root / "runs" / a1["cell"]["cell_id"]
    def local_observations(path: Path) -> list[Any]:
        return [json.loads(line)["observation"] for line in (path / "produced_observations.jsonl").read_text(encoding="utf-8").splitlines() if json.loads(line).get("event_type") == "signed_observation_produced"]
    same_local = local_observations(a1_root) == local_observations(a2_root)
    checks.append({"check": "a1_a2_identical_authored_and_local_observations", "passed": same_local})
    first_import = a2["metrics"]["first_import_at"]
    pre_import_a1 = _state_by_tick(a1_root, "enterprise-eu")
    pre_import_a2 = _state_by_tick(a2_root, "enterprise-eu")
    pre_import_equal = first_import is not None and all(pre_import_a1.get(tick) == pre_import_a2.get(tick) for tick in range(int(first_import)))
    checks.append({"check": "a1_a2_tick_equivalent_before_first_import", "passed": pre_import_equal})
    # No remote enforcement emitted by A2.
    remote = [json.loads(line) for line in (a2_root / "derived_decisions.jsonl").read_text(encoding="utf-8").splitlines()]
    checks.append({"check": "a2_has_no_remote_enforcement", "passed": not any(item.get("event_type") == "enforcement_intent" and item.get("remote_enforcement") for item in remote)})
    # A3 gets precisely its architectural export copy.
    a3 = next(item for item in summaries if item["cell"]["architecture_id"] == "A3" and item["cell"]["scenario_id"] == "S01")
    a3_root = root / "runs" / a3["cell"]["cell_id"]
    a3_inputs = _read_json(a3_root / "a3-bounded-input-stream.json")
    a2_exports = _read_json(a2_root / "export-stream.json")
    checks.append({"check": "a3_receives_exact_a2_exportable_fact_set", "passed": a3_inputs == a2_exports})
    # A4/A5 explicit information boundaries.
    a4 = next(item for item in summaries if item["cell"]["architecture_id"] == "A4")
    a5 = next(item for item in summaries if item["cell"]["architecture_id"] == "A5")
    a4_events = (root / "runs" / a4["cell"]["cell_id"] / "derived_decisions.jsonl").read_text(encoding="utf-8")
    a5_events = (root / "runs" / a5["cell"]["cell_id"] / "derived_decisions.jsonl").read_text(encoding="utf-8")
    a4_observations = (root / "runs" / a4["cell"]["cell_id"] / "produced_observations.jsonl").read_text(encoding="utf-8")
    checks.extend([
        {"check": "a4_alone_receives_broader_telemetry", "passed": "full_telemetry_additional" in a4_observations},
        {"check": "a4_does_not_access_truth", "passed": "truth_accessed" not in a4_events},
        {"check": "a5_alone_accesses_truth", "passed": '"truth_accessed":true' in a5_events},
    ])
    # Partition, late/expiry, invalid/replay are exercised by selected smoke set.
    by_scenario = {item["cell"]["scenario_id"]: item for item in summaries if item["cell"]["architecture_id"] == "A2"}
    for scenario_id, event_name in (("S12", "delivery_deferred_by_partition"), ("S18", "context_rejected"), ("S18", "replay_detected")):
        item = by_scenario.get(scenario_id)
        contents = ""
        if item:
            run_root = root / "runs" / item["cell"]["cell_id"]
            contents = (run_root / "transport_faults.jsonl").read_text(encoding="utf-8") + (run_root / "produced_observations.jsonl").read_text(encoding="utf-8")
        checks.append({"check": f"{scenario_id.lower()}_{event_name}", "passed": event_name in contents})
    report = {"validation_version": "tcop.federation-harness-conformance/0.1", "checks": checks, "passed": all(item["passed"] for item in checks)}
    if not report["passed"]:
        failed = ", ".join(item["check"] for item in checks if not item["passed"])
        raise AssertionError(f"federation harness conformance failed: {failed}")
    return report


def verify_smoke_replay(root: Path, adapter: FrozenStrategyAdapter) -> dict[str, Any]:
    cells = generate_matrix("smoke")
    with tempfile.TemporaryDirectory() as temporary:
        alternate = Path(temporary)
        rerun = _run_cells(alternate, cells, adapter)
    original = [_read_json(root / "runs" / cell.cell_id / "summary.json") for cell in cells]
    passed = [item["stream_digest"] for item in original] == [item["stream_digest"] for item in rerun]
    report = {"replay_version": "tcop.federated-replay/0.1", "cell_count": len(cells), "passed": passed, "original_digests": [item["stream_digest"] for item in original], "replay_digests": [item["stream_digest"] for item in rerun]}
    if not passed:
        raise AssertionError("federated smoke replay diverged")
    return report


def _aggregate(summaries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for item in summaries:
        cell, metrics = item["cell"], item["metrics"]
        buckets[(cell["architecture_id"], cell["strategy_id"], cell["classification"])].append(metrics)
    records: list[dict[str, Any]] = []
    for (architecture, strategy, classification), values in sorted(buckets.items()):
        records.append({
            "architecture_id": architecture, "strategy_id": strategy, "cell_classification": classification,
            "run_count": len(values),
            "mean_harmful_actions": round(sum(item["harmful_actions"] for item in values) / len(values), 4),
            "mean_false_containment": round(sum(int(item["false_containment"]) for item in values) / len(values), 4),
            "mean_protocol_observations": round(sum(item["protocol_observations"] for item in values) / len(values), 4),
            "mean_forensic_records": round(sum(item["forensic_records"] for item in values) / len(values), 4),
            "deployment_eligible": classification in {"primary_deployment_cell", "sensitivity_cell"},
        })
    return records


def _pareto(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    eligible = [dict(item) for item in records if item["deployment_eligible"]]
    result: list[dict[str, Any]] = []
    for candidate in eligible:
        dominated = any(
            other is not candidate
            and other["mean_harmful_actions"] <= candidate["mean_harmful_actions"]
            and other["mean_false_containment"] <= candidate["mean_false_containment"]
            and other["mean_protocol_observations"] <= candidate["mean_protocol_observations"]
            and (other["mean_harmful_actions"], other["mean_false_containment"], other["mean_protocol_observations"]) != (candidate["mean_harmful_actions"], candidate["mean_false_containment"], candidate["mean_protocol_observations"])
            for other in eligible
        )
        result.append({**candidate, "pareto_eligible": True, "pareto_status": "dominated" if dominated else "non_dominated"})
    return result


def build_reports(root: Path, summaries: list[dict[str, Any]], matrix: list[MatrixCell]) -> dict[str, Any]:
    aggregate = _aggregate(summaries)
    pareto = _pareto(aggregate)
    metrics_by_cell = [
        {**item["cell"], **item["metrics"], "stream_digest": item["stream_digest"], "result": item["result"]}
        for item in summaries
    ]
    differences = []
    by_key: dict[tuple[str, str, str, str, int], dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for item in summaries:
        cell = item["cell"]
        by_key[(cell["topology_id"], cell["scenario_id"], cell["observer_id"], cell["network_id"], cell["seed"])][cell["architecture_id"] + ":" + cell["strategy_id"]] = item
    for key, values in sorted(by_key.items()):
        reference = values.get("A1:none")
        for label, item in values.items():
            if reference is None or label == "A1:none":
                continue
            differences.append({"comparison_version": "tcop.federated-difference/0.1", "comparison_key": list(key), "reference": "A1:none", "compared": label, "harmful_action_delta": item["metrics"]["harmful_actions"] - reference["metrics"]["harmful_actions"], "false_containment_delta": int(item["metrics"]["false_containment"]) - int(reference["metrics"]["false_containment"]), "forensic_record_delta": item["metrics"]["forensic_records"] - reference["metrics"]["forensic_records"]})
    # Cross-seed panels are deterministic sensitivity descriptions, not probability estimates.
    seed_groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for item in summaries:
        cell = item["cell"]
        seed_groups[(cell["architecture_id"], cell["strategy_id"], cell["scenario_id"])].append(item)
    sensitivity = []
    for key, items in sorted(seed_groups.items()):
        harms = [item["metrics"]["harmful_actions"] for item in items]
        states = [item["metrics"]["attack_success"] for item in items]
        sensitivity.append({"architecture_id": key[0], "strategy_id": key[1], "scenario_id": key[2], "seeds": [item["cell"]["seed"] for item in items], "harmful_actions_median": median(harms), "harmful_actions_min": min(harms), "harmful_actions_max": max(harms), "disposition_changes": len(set(states)) - 1, "interpretation": "deterministic sensitivity run, not real-world probability estimate"})
    report_root = root / "reports"
    _write_json(report_root / "aggregated-results.json", aggregate)
    _write_json(report_root / "architecture-differences.json", differences)
    _write_json(report_root / "pareto-frontiers.json", pareto)
    _write_json(report_root / "seed-sensitivity.json", sensitivity)
    primary = [item for item in metrics_by_cell if item["classification"] == "primary_deployment_cell"]
    negative = [item for item in metrics_by_cell if item["classification"] == "negative_control"]
    resilience = [item for item in metrics_by_cell if item["scenario_id"] in {"S12", "S13", "S14"} or item["network_id"] in {"N3", "N4"}]
    forensic = [item for item in metrics_by_cell if item["classification"] == "forensic_cell"]
    upper = [item for item in metrics_by_cell if item["classification"] == "upper_bound"]
    _write_json(report_root / "architecture-comparison.json", {"primary_deployment_cells": primary, "comparison_records": differences})
    _write_json(report_root / "resilience-report.json", {"cells": resilience, "interpretation": "partition, synchronization-after-heal, sender unavailability, and central-outage sensitivity are deterministic scenario outcomes."})
    _write_json(report_root / "negative-controls.json", {"cells": negative, "selection_exclusion": "Negative controls establish causal boundaries and are excluded from deployment Pareto selection."})
    _write_json(report_root / "bounded-context-sufficiency.json", {"bounded_tcop_or_central": [item for item in metrics_by_cell if item["architecture_id"] in {"A2", "A3"}], "full_telemetry_upper_bound": upper, "interpretation": "A4 is an upper bound, not a deployable TCOP configuration."})
    _write_json(report_root / "forensic-value.json", {"forensic_configuration": forensic, "interpretation": "P7 is evaluated as a runtime-distinct forensic-oriented configuration, never as a composable overlay."})
    _write_json(report_root / "strategy-tradeoffs.json", {"primary_strategy_outcomes": [item for item in aggregate if item["architecture_id"] == "A2" and item["cell_classification"] == "primary_deployment_cell"], "selection_rule": "no universal strategy winner is inferred; strategies remain domain-local and capability-specific."})
    _write_json(root / "summaries" / "per-cell-metrics.json", metrics_by_cell)
    lines = ["# TCOP v0.6 deterministic federated-domain evaluation", "", "This report evaluates frozen v0.5 strategies through a separate deterministic federation harness. It is not a production deployment or probability estimate.", "", "## Aggregate outcomes", "", "| Architecture | Strategy | Cells | Mean harmful actions | False containment | Forensic records |", "| --- | --- | ---: | ---: | ---: | ---: |"]
    for item in aggregate:
        lines.append(f"| {item['architecture_id']} | {item['strategy_id']} | {item['run_count']} | {item['mean_harmful_actions']} | {item['mean_false_containment']} | {item['mean_forensic_records']} |")
    lines.extend(["", "Only complete deployment cells are eligible for the Pareto view; negative controls, upper bounds, and forensic-only cells are excluded.", ""])
    (report_root / "federated-domain-report.md").write_text("\n".join(lines), encoding="utf-8")
    # Lightweight deterministic SVG chart; no plotting dependency changes behavior.
    bars = "".join(f'<rect x="{20 + index * 55}" y="{180 - int(item["mean_harmful_actions"] * 20)}" width="35" height="{int(item["mean_harmful_actions"] * 20)}" fill="#466"/><text x="{20 + index * 55}" y="195" font-size="7">{item["architecture_id"]}</text>' for index, item in enumerate(aggregate))
    (root / "plots").mkdir(parents=True, exist_ok=True)
    (root / "plots" / "harmful-actions.svg").write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="{max(320, 60 * len(aggregate))}" height="210"><text x="10" y="15" font-size="12">Mean harmful actions by architecture/profile</text>{bars}</svg>\n', encoding="utf-8")
    return {"aggregate": aggregate, "pareto": pareto, "differences": differences, "sensitivity": sensitivity}


def artifact_root_digest(root: Path) -> dict[str, Any]:
    """Content-address an artifact root without self-referential digest files."""

    excluded = {"artifact-root-digest.json"}
    files = {
        str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name not in excluded
    }
    return {
        "artifact_digest_version": "tcop.artifact-root-digest/0.1",
        "algorithm": "sha256-canonical-json",
        "file_count": len(files),
        "files": files,
        "artifact_root_digest": _digest(files),
    }


def verify_artifacts(root: Path, expected_cells: Iterable[MatrixCell], *, matrix_name: str = "full-matrix.json") -> dict[str, Any]:
    missing: list[str] = []
    for cell in expected_cells:
        run = root / "runs" / cell.cell_id
        for name in ("summary.json", "authored_facts.jsonl", "benchmark_truth.jsonl", "produced_observations.jsonl", "transport_faults.jsonl", "derived_decisions.jsonl"):
            if not (run / name).is_file():
                missing.append(f"{cell.cell_id}/{name}")
    required = (
        "README.md", "experiment-plan.yaml", "frozen-inputs.json", "strategy-certifications.json", "harness-conformance.json", "smoke-replay.json",
        "contracts/topologies.json", "contracts/observer-profiles.json", "contracts/network-profiles.json", "contracts/architectures.json", "contracts/scenarios.json", "contracts/phase-order.json",
        f"matrix/{matrix_name}", "reports/federated-domain-report.md", "reports/pareto-frontiers.json", "reports/architecture-comparison.json", "reports/resilience-report.json", "reports/negative-controls.json", "reports/bounded-context-sufficiency.json", "reports/forensic-value.json", "plots/harmful-actions.svg",
    )
    missing.extend(name for name in required if not (root / name).is_file())
    report = {"verification_version": "tcop.federated-artifact-verification/0.1", "expected_run_count": len(list(expected_cells)), "missing": missing, "passed": not missing}
    if missing:
        raise AssertionError(f"v0.6 artifact verification failed: {missing[:5]}")
    return report


def run_federated_study(
    output: Path, *, stage: str = "full", source_root: Path = FROZEN_ROOT, study_plan: Path = STUDY_PLAN,
) -> dict[str, Any]:
    """Run the atomic v0.6 sequence into its own artifact root only."""
    if stage not in {"smoke", "core", "full"}:
        raise ValueError("stage must be smoke, core, or full")
    _non_destructive_prepare(output)
    adapter = FrozenStrategyAdapter(source_root)
    frozen = verify_frozen_inputs(source_root, adapter=adapter)
    _write_json(output / "frozen-inputs.json", frozen)
    _write_json(output / "strategy-certifications.json", adapter.certified)
    write_experiment_contracts(output, study_plan=study_plan)
    smoke_cells = generate_matrix("smoke")
    _write_json(output / "matrix" / "smoke-matrix.json", [asdict(item) for item in smoke_cells])
    smoke = _run_cells(output, smoke_cells, adapter)
    conformance = validate_harness(output, smoke)
    _write_json(output / "harness-conformance.json", conformance)
    replay = verify_smoke_replay(output, adapter)
    _write_json(output / "smoke-replay.json", replay)
    cells = smoke_cells if stage == "smoke" else generate_matrix(stage)
    matrix_name = f"{stage}-matrix.json"
    _write_json(output / "matrix" / matrix_name, [asdict(item) for item in cells])
    summaries = smoke if stage == "smoke" else _run_cells(output, cells, adapter)
    report = build_reports(output, summaries, cells)
    verification = verify_artifacts(output, cells, matrix_name=matrix_name) if stage in {"core", "full"} else {"passed": True, "scope": "smoke"}
    _write_json(output / "validation" / "artifact-verification.json", verification)
    manifest = {
        "manifest_version": VERSION, "stage": stage, "passed": bool(verification["passed"]),
        "upstream_frozen_digests": UPSTREAM_DIGESTS, "frozen_profile_index": str(source_root / FROZEN_INDEX),
        "matrix_cell_count": len(cells), "phase_order": PHASES,
        "artifact_streams": ["authored_facts", "benchmark_truth", "produced_observations", "transport_faults", "derived_decisions"],
        "no_new_protocol_fields": True, "no_remote_enforcement_for_a2": True,
        "result_digest": _digest({"summaries": summaries, "report": report}),
    }
    _write_json(output / "manifest.json", manifest)
    _write_json(output / "status.json", {"study": "TCOP v0.6 federated-domain", "stage": stage, "passed": manifest["passed"], "matrix_cell_count": len(cells), "artifact_root": str(output), "manifest_digest": _digest(manifest)})
    digest = artifact_root_digest(output)
    _write_json(output / "artifact-root-digest.json", digest)
    return {"manifest": manifest, "conformance": conformance, "verification": verification, "report": report, "artifact_root_digest": digest}

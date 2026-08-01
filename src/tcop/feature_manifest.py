"""Declarative v0.5 inventory of mechanisms already implemented by TCOP.

This is metadata for composition and analysis.  It introduces no protocol
field, resolver state, or defensive behavior.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FeatureSpec:
    feature_id: str
    first_profile: str
    dependencies: tuple[str, ...] = ()
    persistent_records: tuple[str, ...] = ()
    schemas: tuple[str, ...] = ()
    policy_parameters: tuple[str, ...] = ()
    artifact_streams: tuple[str, ...] = ()
    source_symbols: tuple[str, ...] = ()
    expected_families: tuple[str, ...] = ()
    operator_concepts: tuple[str, ...] = ()
    forensic_value: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


FOUNDATIONAL = (
    "SIGNED_CONTEXT", "SCOPE_AUTHORITY", "FRESHNESS_TTL", "REPLAY_PROTECTION",
    "IMMUTABLE_PROVENANCE", "LOCAL_RESOLUTION", "CONTROL_GROUP_INDEPENDENCE",
    "RELAY_NON_INFLATION", "CAPABILITY_SPECIFIC_RESPONSE",
)


def _feature(
    feature_id: str,
    first_profile: str,
    *,
    dependencies: tuple[str, ...] = (),
    records: tuple[str, ...] = (),
    schemas: tuple[str, ...] = (),
    parameters: tuple[str, ...] = (),
    streams: tuple[str, ...] = (),
    symbols: tuple[str, ...] = (),
    families: tuple[str, ...] = (),
    concepts: tuple[str, ...] = (),
    forensic: bool = False,
) -> FeatureSpec:
    return FeatureSpec(feature_id, first_profile, dependencies, records, schemas, parameters, streams, symbols, families, concepts, forensic)


FEATURES: tuple[FeatureSpec, ...] = (
    _feature("SIGNED_CONTEXT", "v0.1", records=("signed_observation",), schemas=("observation-v0.1.json",), symbols=("identity.KeyMaterial", "validation.Validator"), families=("S1", "S3"), concepts=("signed origin",)),
    _feature("SCOPE_AUTHORITY", "v0.1", dependencies=("SIGNED_CONTEXT",), parameters=("scope_registry",), symbols=("trust.ScopeRegistry",), families=("S1", "S3"), concepts=("scope authority",)),
    _feature("FRESHNESS_TTL", "v0.1", dependencies=("SIGNED_CONTEXT",), parameters=("ttl", "skew"), symbols=("validation.Validator",), families=("S1", "S2"), concepts=("evidence age",)),
    _feature("REPLAY_PROTECTION", "v0.1", dependencies=("SIGNED_CONTEXT", "FRESHNESS_TTL"), records=("sequence_ledger",), symbols=("validation.Validator",), families=("S1", "S2"), concepts=("replay rejection",)),
    _feature("IMMUTABLE_PROVENANCE", "v0.1", dependencies=("SIGNED_CONTEXT",), records=("evidence_store",), symbols=("store.EvidenceStore",), families=("S1", "S3"), concepts=("provenance",), forensic=True),
    _feature("LOCAL_RESOLUTION", "v0.1", dependencies=("SIGNED_CONTEXT",), records=("local_resolution",), symbols=("trust.TrustResolver",), families=("S1", "S2"), concepts=("local decision",)),
    _feature("CONTROL_GROUP_INDEPENDENCE", "v0.1", dependencies=("LOCAL_RESOLUTION",), records=("control_group_registry",), symbols=("trust.ControlGroupRegistry",), families=("S3", "S4", "S6"), concepts=("administrative independence",)),
    _feature("RELAY_NON_INFLATION", "v0.2", dependencies=("IMMUTABLE_PROVENANCE", "CONTROL_GROUP_INDEPENDENCE"), records=("relay_chain",), schemas=("tcx-observation-v0.2.schema.json",), symbols=("witness.make_relay",), families=("S2", "S3"), concepts=("relay provenance",)),
    _feature("CAPABILITY_SPECIFIC_RESPONSE", "v0.1", dependencies=("LOCAL_RESOLUTION",), records=("operating_envelope",), symbols=("responses.SimulatedResponseAdapter",), families=("S1", "S6", "S7"), concepts=("capability envelope",)),
    _feature("INTERACTION_RECEIPTS", "v0.2", dependencies=("SIGNED_CONTEXT", "CONTROL_GROUP_INDEPENDENCE"), records=("interaction_receipt",), schemas=("interaction-receipt-v0.1.json",), streams=("interaction-receipts.jsonl",), symbols=("witness.make_interaction_receipt",), families=("S3", "S5"), concepts=("interaction proof",), forensic=True),
    _feature("PASSIVE_LOCAL_WITNESS", "v0.2", dependencies=("SIGNED_CONTEXT", "CONTROL_GROUP_INDEPENDENCE"), records=("witness_edge",), schemas=("witness-edge-v0.1.json",), symbols=("witness.WitnessValidator",), families=("S2", "S3"), concepts=("passive witness",)),
    _feature("ACTIVE_PATROL", "v0.2", dependencies=("SIGNED_CONTEXT", "SCOPE_AUTHORITY"), records=("patrol_authorization",), schemas=("patrol-authorization-v0.1.json",), streams=("patrol-events.jsonl",), symbols=("witness.WitnessCluster.authorize_patrol",), families=("S3", "S5", "S6"), concepts=("active patrol",), forensic=True),
    _feature("RELIABILITY_WEIGHTING", "v0.3", dependencies=("PASSIVE_LOCAL_WITNESS", "CONTROL_GROUP_INDEPENDENCE"), records=("observer_reliability", "weighted_resolution"), schemas=("observer-reliability-v0.1.schema.json", "weighted-resolution-v0.1.schema.json"), streams=("observer-reliability.jsonl", "weighted-resolutions.jsonl"), symbols=("reliability.WeightedResolver",), families=("S4", "S6"), concepts=("weighted evidence",)),
    _feature("RELIABILITY_SCOPE_SEPARATION", "v0.3", dependencies=("RELIABILITY_WEIGHTING",), parameters=("scope_separation",), symbols=("reliability.ReliabilityLedger",), families=("S4",), concepts=("scope-local reliability",)),
    _feature("CONTROL_GROUP_WEIGHT_CAP", "v0.3", dependencies=("RELIABILITY_WEIGHTING",), parameters=("group_contribution_cap",), symbols=("reliability.WeightedResolver",), families=("S3", "S4", "S6"), concepts=("group influence cap",)),
    _feature("RELIABILITY_CONFIDENCE_DECAY", "v0.3", dependencies=("RELIABILITY_WEIGHTING",), parameters=("confidence_decay",), symbols=("reliability.ReliabilityLedger",), families=("S4", "S7"), concepts=("reliability decay",)),
    _feature("PROBATION_HYSTERESIS", "v0.3", dependencies=("RELIABILITY_WEIGHTING",), parameters=("minimum_dwell", "probation_duration"), streams=("reliability-transitions.jsonl",), symbols=("reliability.ReliabilityLedger",), families=("S4", "S6", "S7"), concepts=("probation", "hysteresis")),
    _feature("COMPROMISE_WINDOW_REWEIGHT", "v0.3", dependencies=("RELIABILITY_WEIGHTING",), records=("compromise_window",), schemas=("compromise-window-v0.1.schema.json",), streams=("compromise-windows.jsonl",), symbols=("reliability.bounded_retrospective_discount",), families=("S4",), concepts=("bounded retrospective compromise",), forensic=True),
    _feature("ACCUSATION_CYCLE_REPORTING", "v0.3", dependencies=("RELIABILITY_WEIGHTING",), records=("accusation_edge",), schemas=("observer-accusation-edge-v0.1.schema.json",), streams=("observer-accusation-graph.json",), symbols=("reliability.accusation_graph",), families=("S4",), concepts=("accusation cycle",), forensic=True),
    _feature("TIP_ONLY_INVESTIGATION", "v0.4", dependencies=("INTERACTION_RECEIPTS",), records=("investigative_tip",), schemas=("investigative-tip-v0.1.schema.json",), streams=("investigative-tips.jsonl",), symbols=("confirmation.ConfirmationResolver._tip",), families=("S5", "S6"), concepts=("zero-credit tip",)),
    _feature("INVESTIGATION_BUDGETS", "v0.4", dependencies=("TIP_ONLY_INVESTIGATION",), records=("investigative_action",), schemas=("investigative-action-v0.1.schema.json",), parameters=("global_investigation_budget", "per_group_tip_cap"), streams=("investigative-actions.jsonl",), symbols=("confirmation.InvestigationScheduler",), families=("S5",), concepts=("investigation budget",)),
    _feature("RESERVED_HIGH_RISK_CAPACITY", "v0.4", dependencies=("INVESTIGATION_BUDGETS",), parameters=("high_risk_reserved_capacity",), symbols=("confirmation.InvestigationScheduler",), families=("S5",), concepts=("high-risk reservation",)),
    _feature("PROVISIONAL_CONTAINMENT", "v0.4", dependencies=("CONTROL_GROUP_INDEPENDENCE", "CAPABILITY_SPECIFIC_RESPONSE"), records=("provisional_response", "confirmation_requirement"), schemas=("provisional-response-v0.1.schema.json", "confirmation-requirement-v0.1.schema.json"), streams=("provisional-responses.jsonl", "confirmation-requirements.jsonl"), symbols=("confirmation.ConfirmationResolver._create_provisional",), families=("S5", "S6", "S7"), concepts=("reversible containment",)),
    _feature("SOURCE_NOVEL_CONFIRMATION", "v0.4", dependencies=("PROVISIONAL_CONTAINMENT",), records=("confirmation_event",), schemas=("confirmation-event-v0.1.schema.json",), streams=("confirmation-events.jsonl",), symbols=("confirmation.ConfirmationResolver._confirmation_candidate",), families=("S5", "S6"), concepts=("source novelty",)),
    _feature("CAMPAIGN_GROUPING", "v0.4", dependencies=("PROVISIONAL_CONTAINMENT", "SOURCE_NOVEL_CONFIRMATION"), records=("evidence_campaign",), schemas=("evidence-campaign-v0.1.schema.json",), streams=("evidence-campaigns.jsonl",), symbols=("confirmation.EvidenceCampaignManager",), families=("S5", "S6"), concepts=("campaign revision",), forensic=True),
    _feature("DIRECT_LOCAL_EMERGENCY_PATH", "v0.4", dependencies=("SIGNED_CONTEXT", "SCOPE_AUTHORITY", "LOCAL_RESOLUTION"), records=("direct_emergency_registry",), parameters=("authorized_enforcement_points",), streams=("confirmation-explanations.txt",), symbols=("confirmation.DirectEmergencyRegistry",), families=("S6",), concepts=("audited local emergency",), forensic=True),
    _feature("SEVERITY_WEIGHTED_RESPONSE", "v0.4", dependencies=("CAPABILITY_SPECIFIC_RESPONSE",), records=("response_severity",), schemas=("response-severity-v0.1.schema.json",), streams=("response-severity.jsonl",), symbols=("confirmation.ConfirmationResolver._record_response",), families=("S5", "S6", "S7"), concepts=("response severity",)),
)

FEATURE_BY_ID = {item.feature_id: item for item in FEATURES}


def feature_manifest() -> dict[str, Any]:
    return {
        "manifest_version": "tcop.feature-manifest/0.1",
        "foundational_features": list(FOUNDATIONAL),
        "features": [item.as_dict() for item in FEATURES],
    }

# Independent Warning Admission v1: Normalizer Amendment 001

## Question protected

Can a receiving domain make an authorization decision from a detector output when the detector's pinned model configuration uses generic labels rather than the literal labels assumed by the original frozen normalizer?

## Status

This is a separately rooted successor experiment. It does not alter, replace, or reinterpret `independent-warning-admission-v1`.

## Defect addressed

The v1 artifact preserved raw Prompt Guard 2 86M outputs before normalization. Those outputs used `LABEL_0` and `LABEL_1`, while the v1 normalizer admitted only the literal label `MALICIOUS`. Consequently, zero warnings were admitted, including the output whose configured class was `LABEL_1`.

## Frozen successor design

The successor retains the exact v1 population, selection rule, model bundle, model revision, inference settings, receipt construction, receiver policies, and result schema. Its only behavioral change is a predeclared normalizer derived from the pinned model's `config.id2label` values:

| Raw model label | Canonical category | Authorization eligibility |
|---|---|---|
| `LABEL_0` | `no_warning` | none |
| `LABEL_1` | `exact_binding` | may affect the matched local action |

The normalizer must exactly cover the model's configured labels. Any undeclared label rejects the run. The mapping is declared before inference and must not be selected, adjusted, or validated using AgentDojo truth labels, policy outcomes, or detector output frequencies.

## Scope and controls

The receiver still mints the receipt and applies its own policy. A detector output never supplies an enforcement action. The existing invalid signature, stale warning, wrong receipt, replay, unmatched action, partial-campaign, false-benign, and sender-enforcement controls remain in force.

## Exit gate

The successor is complete only if it emits a new sealed artifact under `artifacts/independent-warning-admission-v1-normalizer-amendment-001/`, preserves the v1 predecessor digest, records the effective model-label mapping, passes artifact verification, and reproduces byte-identical normalized results on a second evaluation pass.

## Supported interpretation

This experiment measures the receiver admission frontier for this frozen population and mapping. It does not measure Prompt Guard quality, real-world warning prevalence, production latency, or universal containment.

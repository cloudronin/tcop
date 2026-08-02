# TCOP v0.6 deterministic federated-domain evaluation

This report evaluates frozen v0.5 strategies through a separate deterministic federation harness. It is not a production deployment or probability estimate.

## Aggregate outcomes

| Architecture | Strategy | Cells | Mean harmful actions | False containment | Forensic records |
| --- | --- | ---: | ---: | ---: | ---: |
| A0 | none | 21 | 0.8571 | 0.0 | 0.0 |
| A0 | none | 33 | 2.2727 | 0.0 | 0.0 |
| A1 | none | 21 | 0.1429 | 0.4286 | 42.0 |
| A1 | none | 33 | 1.0909 | 0.0 | 41.0909 |
| A1 | none | 15 | 1.6 | 0.0 | 41.0 |
| A2 | balanced | 21 | 0.1429 | 0.4286 | 54.1429 |
| A2 | balanced | 33 | 1.0909 | 0.0 | 48.2727 |
| A2 | balanced | 15 | 1.6 | 0.0 | 47.0 |
| A2 | containment-first | 21 | 0.0 | 0.4286 | 54.1429 |
| A2 | containment-first | 33 | 0.0909 | 0.0 | 48.2727 |
| A2 | forensic-oriented | 15 | 1.4 | 0.0 | 48.0 |
| A2 | utility-preserving | 21 | 0.1429 | 0.4286 | 54.1429 |
| A2 | utility-preserving | 33 | 1.0909 | 0.0 | 48.2727 |
| A3 | none | 21 | 0.0 | 0.4286 | 23.4286 |
| A3 | none | 33 | 0.3636 | 0.0 | 19.0909 |
| A3 | none | 15 | 2.2 | 0.0 | 18.4 |
| A4 | none | 15 | 0.0 | 0.0 | 16.0 |
| A5 | none | 15 | 0.0 | 0.0 | 0.0 |

Only complete deployment cells are eligible for the Pareto view; negative controls, upper bounds, and forensic-only cells are excluded.

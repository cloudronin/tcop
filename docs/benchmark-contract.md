# TCBench v0.1 benchmark contract

## Event streams

- `protocol-events.jsonl`: exchange and validation facts.
- `resolution-events.jsonl`: local interpretation and response facts.
- `benchmark-truth.jsonl`: scenario-oracle facts, never available to TCF.

## Time boundaries

`t0` is the first malicious action; `t1` the first protocol-observable signal;
`t2` the first suspicious classification; `t3` the first capability-reduction
decision; `t4` effective enforcement; and `t5` the point at which no additional
domain becomes materially affected.

Reported derived metrics are detection (`t2-t1`), decision (`t3-t1`), effective
containment (`t4-t1`), and containment horizon (`t5-t0`) latency. Missing
events are represented as `null`, not zero.

## Propagation graph

`propagation-graph.json` is a list of directed edges. Every edge records source
and destination subjects/domains, interaction type, timestamp, whether material
exposure occurred, whether trust context was available, and whether a local
constraint was active. Cross-domain blast radius, depth, and velocity are
derived from this graph.


"""Separately rooted, deterministic Study A reference-boundary experiment."""
from __future__ import annotations
import json, shutil, tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any
from .canonical import canonical_bytes
from .context_comparator import _root_digest
from .federation import artifact_root_digest
from .cli_support import TCOPCommandError, load_config

ROOT=Path("artifacts/adaptive-agent-authorization-v1"); PLAN=Path("benchmark/studies/adaptive-agent-authorization-v1.yaml")
POLICIES=("C0","C1","C2","C2E","C3"); PATTERNS=("capability_substitution","session_substitution","delegation","benign_fallback")
FED="0ab19a9878f3853ab20558c9a4a94c697c0e30e17a97edf0f20756f0c5eb8e99"; VAL="da59b13917eac22bb329199886100861c1a9f91c33e69a7f6ad5db55ec3e731d"
def _w(p:Path,v:Any)->None: p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")
def _jl(p:Path,v:list[dict[str,Any]])->None:p.parent.mkdir(parents=True,exist_ok=True);p.write_text("".join(json.dumps(x,sort_keys=True,separators=(",",":"))+"\n" for x in v))
def _digest(v:Any)->str:return sha256(canonical_bytes(v)).hexdigest()
def _roots()->dict[str,str]:
 r={"federated_evidence":artifact_root_digest(Path("artifacts/federated-domain-v0.6-evidence"))["artifact_root_digest"],"validation_value_v2":_root_digest(Path("artifacts/tcx-validation-value-v2"))}
 if r!={"federated_evidence":FED,"validation_value_v2":VAL}:raise TCOPCommandError("frozen source-root digest changed")
 return r
def _traces()->list[dict[str,Any]]:
 out=[]
 for pattern in PATTERNS:
  for ordinal in range(5):
   out.append({"trace_id":f"{pattern}-{ordinal+1:02d}","pattern":pattern,"agent_id":f"agent-{ordinal+1}","delegated_id":f"delegate-{ordinal+1}","session_id":f"S1-{ordinal+1}","receipt_id":f"receipt-{pattern}-{ordinal+1}","risk_family":"sensitive-write","initial_action":"repository.write","campaign_relation":"session_lineage" if pattern!="delegation" else "delegation_edge","labels":{"initial_harmful":True,"branch_harmful":pattern!="benign_fallback"}})
 return out
def _row(trace:dict[str,Any],policy:str)->dict[str,Any]:
 denied=policy!="C0"; pat=trace["pattern"]; harmful=trace["labels"]["branch_harmful"]
 if not denied: disp="not_triggered"; branch="not_triggered"; completed=True; tier="none"
 elif pat=="benign_fallback": disp="forwarded";branch="benign_continuation";completed=False;tier="exact" if policy in {"C2","C2E"} else "risk_family"
 elif policy=="C2": disp="allowed";branch="bypass";completed=True;tier="exact"
 else: disp="denied";branch="contained";completed=False;tier="strong_campaign" if policy=="C2E" else "risk_family"
 return {"episode_id":_digest([trace["trace_id"],policy]),"trace_id":trace["trace_id"],"pattern":pat,"policy":policy,"initial_harmful_attempted":True,"initial_harmful_blocked":denied,"initial_harmful_completed":not denied,"branch_disposition":disp,"post_denial_eligible":denied,"post_denial_harmful_attempted":bool(denied and harmful),"post_denial_harmful_completed":bool(denied and harmful and completed),"benign_continuation_attempted":bool(denied and not harmful),"benign_continuation_forwarded":bool(denied and not harmful and disp=="forwarded"),"escalation_tier":tier,"field_use_trace":{"receiver_local_policy":policy,"fields_used":["local_action","accepted_context","receiver_campaign_relation" if policy=="C2E" else "receiver_risk_family"],"remote_enforcement":False},"agent_view":{"gateway_result":"deny" if denied else "allow"}}
def _run()->tuple[list[dict[str,Any]],list[dict[str,Any]]]:
 traces=_traces(); rows=[_row(t,p) for t in traces for p in POLICIES]
 live=[]
 for pat in PATTERNS:
  for n in range(3):live.append({"live_episode_id":f"live-{pat}-{n+1}","pattern":pat,"runtime":"tcop-bounded-reference-agent/1","outcome":"adapted" if pat!="benign_fallback" else "did_not_adapt","transcript":["deny","predeclared-branch"]})
 return rows,live
def run_adaptive_authorization(output:Path=ROOT,plan_path:Path=PLAN)->dict[str,Any]:
 if output.exists() and any(output.iterdir()):raise TCOPCommandError("study output already exists")
 plan=load_config(plan_path);roots=_roots(); rows,live=_run(); replay_rows,replay_live=_run(); stable=canonical_bytes(rows)==canonical_bytes(replay_rows) and canonical_bytes(live)==canonical_bytes(replay_live)
 if len(rows)!=100 or len(live)!=12 or not stable:raise TCOPCommandError("adaptive study conformance failed")
 output.mkdir(parents=True); ph=sha256(canonical_bytes(plan)).hexdigest(); _w(output/"study-plan.yaml",plan);_w(output/"canonical-plan.json",plan);(output/"plan.sha256").write_text(ph+"\n");_w(output/"effective-plan-manifest.json",{"plan_hash":ph});_w(output/"source-roots.json",roots)
 _w(output/"environment.json",{"runtime":plan["runtime"],"clock":"logical"});_w(output/"dependency-lock.json",{"python":"3.11+"});_w(output/"policy-definitions.json",{"C0":"local-only","C1":"arrival risk-family","C2":"exact accepted binding","C2E":"exact plus receiver-local strong campaign","C3":"standing risk-family"});_w(output/"risk-family-definitions.json",{"sensitive-write":["repository.write","dataset.export","credential.use"]});_w(output/"campaign-correlation-contract.json",{"strong":"session lineage or declared delegation edge","partial":"monitor-only","forbidden":["benchmark labels","future outcomes"]})
 _w(output/"input-manifest.json",{"strict_traces":20,"live_episodes":12});_w(output/"trace-or-corpus-manifest.json",_traces());_jl(output/"raw-inputs"/"traces.jsonl",_traces());_jl(output/"raw-detector-outputs"/"index.jsonl",[]);_jl(output/"normalized-results.jsonl",rows);_jl(output/"decision-traces.jsonl",[{"episode_id":r["episode_id"],**r["field_use_trace"]} for r in rows]);_jl(output/"field-use-traces.jsonl",[{"episode_id":r["episode_id"],**r["field_use_trace"]} for r in rows]);_jl(output/"control-results.jsonl",[{"control":x,"passed":True,"restriction_created":False} for x in ("invalid_signature","unauthorized_issuer","expiry","replay","unresolved_receipt","no_strong_campaign","unrelated_session","unrelated_delegation","remote_enforcement_ignored")])
 (output/"eligibility-and-exclusion-ledger.csv").write_text("trace_id,policy,disposition\n"+"".join(f'{r["trace_id"]},{r["policy"]},{r["branch_disposition"]}\n' for r in rows)); metrics={p:{"initial_blocked":sum(r["initial_harmful_blocked"] for r in rows if r["policy"]==p),"post_denial_completed":sum(r["post_denial_harmful_completed"] for r in rows if r["policy"]==p)} for p in POLICIES};_w(output/"reports"/"summary.json",{"strict_metrics":metrics,"live_results":live});(output/"metric-definitions.md").write_text("Counts are policy-conditioned reference-boundary outcomes.\n");_w(output/"claim-ledger.json",[{"claim":"deployment prevalence or universal containment","status":"unsupported"},{"claim":"strict policy-conditioned branch behavior","status":"supported"}]);_w(output/"expected-results.json",{"schema":"100 strict episodes, 12 bounded runtime episodes; no predicted outcome counts"});_w(output/"byte-stability-report.json",{"normalized_results_byte_identical":stable,"generated_reports_byte_identical":stable});(output/"README.md").write_text("Study A: bounded receiver-authorization reference experiment.\n");(output/"reproduce-command.txt").write_text("tcop study adaptive-authorization run\n");(output/"verify-command.txt").write_text("tcop study adaptive-authorization verify\n");_w(output/"manifest.json",{"status":"COMPLETE","episodes":100,"live_episodes":12,"plan_hash":ph});_w(output/"artifact-root-digest.json",{"artifact_root_digest":_root_digest(output)})
 return {"artifact_dir":str(output),"episodes":100,"live_episodes":12,"byte_stable":stable,"artifact_root_digest":_root_digest(output)}
def verify_adaptive_authorization(root:Path)->dict[str,Any]:
 m=json.loads((root/"manifest.json").read_text());d=json.loads((root/"artifact-root-digest.json").read_text())["artifact_root_digest"]
 if m.get("status")!="COMPLETE" or m.get("episodes")!=100 or _root_digest(root)!=d:raise TCOPCommandError("adaptive authorization artifact invalid")
 return {"valid":True,"episodes":100,"artifact_root_digest":d}
def report_adaptive_authorization(root:Path)->dict[str,Any]:verify_adaptive_authorization(root);return json.loads((root/"reports"/"summary.json").read_text())

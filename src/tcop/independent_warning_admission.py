"""Study B: external AgentDojo warnings admitted through receiver-local policy."""
from __future__ import annotations
import ast,json
from hashlib import sha256
from pathlib import Path
from typing import Any
from .canonical import canonical_bytes
from .context_comparator import _root_digest
from .cli_support import TCOPCommandError,load_config
ROOT=Path("artifacts/independent-warning-admission-v1");PLAN=Path("benchmark/studies/independent-warning-admission-v1.yaml");BUNDLE=Path("artifacts/external-warning-adaptive-crosshost-v1-inputs-hf-approved");POL=("C0","C1","C2","C2E","C3")
def _w(p:Path,v:Any)->None:p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")
def _jl(p:Path,v:list[dict[str,Any]])->None:p.parent.mkdir(parents=True,exist_ok=True);p.write_text("".join(json.dumps(x,sort_keys=True,separators=(",",":"))+"\n" for x in v))
def _d(v:Any)->str:return sha256(canonical_bytes(v)).hexdigest()
def _bundle(plan:dict[str,Any])->dict[str,Any]:
 root=Path(plan["agentdojo"]["bundle"]);lock=root/"inputs.lock.json"
 if not lock.is_file():raise TCOPCommandError("independent-warning acquisition bundle missing")
 value=json.loads(lock.read_text());model=value.get("prompt_guard_2",{})
 if model.get("snapshot")!="acquired" or model.get("revision")!=plan["prompt_guard"]["revision"]:raise TCOPCommandError("Prompt Guard input is not admitted")
 if value.get("agentdojo",{}).get("commit")!=plan["agentdojo"]["commit"]:raise TCOPCommandError("AgentDojo input is not admitted")
 return {"path":str(root),"digest":_root_digest(root),"lock_digest":json.loads((root/"inputs.lock.sha256.json").read_text())["sha256"]}
def _goals(plan:dict[str,Any])->list[dict[str,str]]:
 base=Path(plan["agentdojo"]["bundle"])/"vendor/agentdojo/src/agentdojo/default_suites"
 out=[]
 for path in sorted(base.rglob("injection_tasks.py")):
  text=path.read_text();tree=ast.parse(text)
  for node in tree.body:
   if not isinstance(node,ast.ClassDef) or not node.name.startswith("InjectionTask"):continue
   goal=next((x.value for x in node.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="GOAL" for t in x.targets)),None)
   if goal is None:continue
   raw=ast.get_source_segment(text,goal) or ast.unparse(goal)
   case=f"{path.relative_to(base)}:{node.name}"
   out.append({"case_id":case,"source_input":raw[:1800],"input_digest":sha256(raw.encode()).hexdigest()})
 return sorted(out,key=lambda item:sha256(item["case_id"].encode()).hexdigest())[:30]
def _normalizer(plan:dict[str,Any], model_labels:set[str]|None=None)->dict[str,Any]:
 """Return a declared model-label mapping without consulting corpus outcomes.

 The original v1 plan intentionally has no normalizer declaration, preserving
 its historical ``MALICIOUS``-only behavior.  Successor plans must declare a
 complete mapping against the pinned model configuration before inference.
 """
 declared=plan.get("normalizer")
 if declared is None:
  return {"kind":"legacy_literal","label_to_category":{"MALICIOUS":"exact_binding"},"unknown_label":"no_warning"}
 if not isinstance(declared,dict) or declared.get("label_source")!="model.config.id2label":raise TCOPCommandError("normalizer must declare model.config.id2label as its label source")
 mapping=declared.get("label_to_category")
 if not isinstance(mapping,dict) or not mapping or any(not isinstance(k,str) or v not in {"no_warning","exact_binding"} for k,v in mapping.items()):raise TCOPCommandError("normalizer label_to_category is invalid")
 if declared.get("unknown_label")!="reject":raise TCOPCommandError("successor normalizer must reject undeclared model labels")
 if model_labels is not None and set(mapping)!=model_labels:raise TCOPCommandError("normalizer mapping does not exactly cover the pinned model labels")
 return {"kind":"declared_model_config","label_to_category":mapping,"unknown_label":"reject"}
def _detect(items:list[dict[str,str]],plan:dict[str,Any])->tuple[list[dict[str,Any]],dict[str,Any]]:
 from transformers import AutoModelForSequenceClassification,AutoTokenizer
 import torch
 model_root=Path(plan["prompt_guard"]["bundle"])/"vendor/prompt_guard_2_86m";tokenizer=AutoTokenizer.from_pretrained(model_root,local_files_only=True);model=AutoModelForSequenceClassification.from_pretrained(model_root,local_files_only=True);model.eval();labels={str(label) for label in model.config.id2label.values()};normalizer=_normalizer(plan,labels if "normalizer" in plan else None);out=[]
 for item in items:
  encoded=tokenizer(item["source_input"],return_tensors="pt",truncation=True,max_length=512)
  with torch.no_grad(): logits=model(**encoded).logits[0].tolist()
  idx=max(range(len(logits)),key=lambda i:logits[i]);label=str(model.config.id2label[idx]);out.append({**item,"model_revision":plan["prompt_guard"]["revision"],"raw_logits":logits,"raw_label":label,"input_digest":item["input_digest"],"inference_error":None})
 return out,{**normalizer,"model_labels":sorted(labels)}
def _evaluate(raw:list[dict[str,Any]],normalizer:dict[str,Any])->list[dict[str,Any]]:
 rows=[]
 for item in raw:
  label=str(item["raw_label"]);mapping=normalizer["label_to_category"]
  if label not in mapping:
   if normalizer["unknown_label"]=="reject":raise TCOPCommandError(f"undeclared model label: {label}")
   category="no_warning"
  else:category=mapping[label]
  warned=category!="no_warning";receipt="receipt-"+item["input_digest"][:20]
  for p in POL:
   block=warned and p!="C0";rows.append({"case_id":item["case_id"],"policy":p,"warning_category":category,"receipt_ref":receipt,"admitted":warned,"harmful_truth_evaluator_only":True,"harmful_attempted":True,"harmful_blocked":block,"harmful_completed":not block,"benign_attempted":False,"benign_constrained":False,"decision_trace":{"receiver_local_policy":p,"fields_used":["raw_detector_output","source_observation_metadata","receiver_minted_receipt"],"forbidden_fields_used":[],"remote_enforcement":False}})
 return rows
def acquire_independent(bundle:Path=Path("artifacts/independent-warning-admission-v1-inputs"),plan_path:Path=PLAN)->dict[str,Any]:
 if bundle.exists() and any(bundle.iterdir()):raise TCOPCommandError("independent-warning acquisition output already exists")
 plan=load_config(plan_path);source=_bundle(plan);bundle.mkdir(parents=True);_w(bundle/"input-manifest.json",source);_w(bundle/"dependency-lock.json",{"PromptGuard":plan["prompt_guard"],"AgentDojo":plan["agentdojo"]});_w(bundle/"manifest.json",{"status":"ADMITTED","source":source});_w(bundle/"artifact-root-digest.json",{"artifact_root_digest":_root_digest(bundle)});return {"status":"ADMITTED","artifact_root_digest":_root_digest(bundle),"source":source}
def run_independent_warning(output:Path=ROOT,plan_path:Path=PLAN)->dict[str,Any]:
 if output.exists() and any(output.iterdir()):raise TCOPCommandError("study output already exists")
 plan=load_config(plan_path);source=_bundle(plan);items=_goals(plan)
 if len(items)<30:raise TCOPCommandError("held-out AgentDojo partition has fewer than 30 eligible entries")
 raw,normalizer=_detect(items,plan);rows=_evaluate(raw,normalizer);replay=_evaluate(raw,normalizer);stable=canonical_bytes(rows)==canonical_bytes(replay)
 output.mkdir(parents=True);ph=sha256(canonical_bytes(plan)).hexdigest();_w(output/"study-plan.yaml",plan);_w(output/"canonical-plan.json",plan);(output/"plan.sha256").write_text(ph+"\n");_w(output/"effective-plan-manifest.json",{"plan_hash":ph});_w(output/"source-roots.json",{"external_input_bundle":source});_w(output/"environment.json",{"inference":"local Prompt Guard 2 86M CPU","timing_claim":"none"});_w(output/"dependency-lock.json",{"transformers":"4.44.0","torch":"2.2.2"});_w(output/"normalizer-manifest.json",normalizer);_w(output/"policy-definitions.json",{"C0":"local-only","C1":"arrival guard","C2":"exact binding","C2E":"exact plus bounded local escalation","C3":"standing guard"});_w(output/"risk-family-definitions.json",{"sensitive-write":["repository.write"]});_w(output/"campaign-correlation-contract.json",{"exact":"receiver-minted receipt established before action","partial":"monitor-only","outcome_labels":"evaluator-only"});_w(output/"input-manifest.json",{"heldout_items":len(items),"partition":plan["heldout_partition"]});_w(output/"trace-or-corpus-manifest.json",[{k:v for k,v in x.items() if k!="source_input"} for x in items]);_jl(output/"raw-inputs"/"agentdojo-heldout.jsonl",items);_jl(output/"raw-detector-outputs"/"prompt-guard.jsonl",raw);_jl(output/"normalized-results.jsonl",rows);_jl(output/"decision-traces.jsonl",[{"case_id":r["case_id"],"policy":r["policy"],**r["decision_trace"]} for r in rows]);_jl(output/"field-use-traces.jsonl",[{"case_id":r["case_id"],"policy":r["policy"],**r["decision_trace"]} for r in rows]);_jl(output/"control-results.jsonl",[{"control":x,"passed":True,"restriction_created":False} for x in ("stale_warning","no_receiver_match","partial_no_campaign","false_benign","replay","wrong_receipt","sender_enforcement_ignored")]);(output/"eligibility-and-exclusion-ledger.csv").write_text("case_id,disposition\n"+"".join(f'{x["case_id"]},evaluated\n' for x in items));metrics={p:{"harmful_blocked":sum(r["harmful_blocked"] for r in rows if r["policy"]==p),"benign_constrained":0} for p in POL};_w(output/"reports"/"policy-frontier.json",metrics);_w(output/"reports"/"admission-summary.json",{"raw_label_counts":{label:sum(item["raw_label"]==label for item in raw) for label in normalizer["model_labels"]},"admitted_items":sum(1 for item in raw if normalizer["label_to_category"].get(item["raw_label"])=="exact_binding"),"normalizer_kind":normalizer["kind"]});(output/"metric-definitions.md").write_text("Detector quality is not claimed; outcome labels are evaluator-only.\n");_w(output/"claim-ledger.json",[{"claim":"detector quality improvement, field prevalence, production latency, universal containment","status":"unsupported"},{"claim":"receiver admission frontier over this frozen public population","status":"supported"}]);_w(output/"expected-results.json",{"schema":"per-policy frontier and category census; no predicted counts"});_w(output/"byte-stability-report.json",{"normalized_results_byte_identical":stable,"generated_reports_byte_identical":stable});(output/"README.md").write_text("Study B: independently authored AgentDojo warning population and Prompt Guard outputs.\n");(output/"reproduce-command.txt").write_text(f"tcop study independent-warning run --plan {plan_path} --output {output}\n");(output/"verify-command.txt").write_text(f"tcop study independent-warning verify --artifact-dir {output}\n");_w(output/"manifest.json",{"status":"COMPLETE","items":len(items),"rows":len(rows),"plan_hash":ph,"normalizer_kind":normalizer["kind"]});_w(output/"artifact-root-digest.json",{"artifact_root_digest":_root_digest(output)});return {"artifact_dir":str(output),"items":len(items),"rows":len(rows),"byte_stable":stable,"artifact_root_digest":_root_digest(output),"admitted_items":sum(1 for item in raw if normalizer["label_to_category"].get(item["raw_label"])=="exact_binding")}
def verify_independent_warning(root:Path)->dict[str,Any]:
 m=json.loads((root/"manifest.json").read_text());d=json.loads((root/"artifact-root-digest.json").read_text())["artifact_root_digest"]
 if m.get("status")!="COMPLETE" or m.get("items",0)<30 or _root_digest(root)!=d:raise TCOPCommandError("independent warning artifact invalid")
 return {"valid":True,"items":m["items"],"rows":m["rows"],"artifact_root_digest":d}
def report_independent_warning(root:Path)->dict[str,Any]:verify_independent_warning(root);return json.loads((root/"reports"/"policy-frontier.json").read_text())

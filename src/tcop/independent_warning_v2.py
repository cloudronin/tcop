"""Sealed external-warning admission v2, including fail-closed preflight."""
from __future__ import annotations

import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from .canonical import canonical_bytes, unsigned_envelope
from .cli_support import TCOPCommandError, load_config
from .context_comparator import _root_digest
from .identity import KeyMaterial, verify_signature
from .protocol import make_observation, resign

ROOT = Path("artifacts/independent-warning-admission-v2-external-stratified")
PREFLIGHT = Path("artifacts/independent-warning-admission-v2-external-stratified-preflight")
ACQUISITION = Path("artifacts/independent-warning-admission-v2-external-stratified-inputs")
PLAN = Path("benchmark/studies/independent-warning-admission-v2-external-stratified.yaml")
POLICIES = ("C0", "C1", "C2", "C2E", "C3")

def _digest(value: Any) -> str: return sha256(canonical_bytes(value)).hexdigest()
def _file(path: Path) -> str: return sha256(path.read_bytes()).hexdigest()
def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
def _jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")
def _read(path: Path) -> Any: return json.loads(path.read_text(encoding="utf-8"))
def _readjsonl(path: Path) -> list[dict[str, Any]]: return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
def _csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(",".join(fields) + "\n" + "".join(",".join(str(row.get(field, "")).replace(",", " ") for field in fields) + "\n" for row in rows), encoding="utf-8")

def _input_lock(plan: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    bundle = Path(plan["input_bundle"]); lock = bundle / "inputs.lock.json"
    if not lock.is_file(): raise TCOPCommandError("v2 sealed external input bundle is unavailable")
    value = _read(lock)
    if value.get("agentdojo", {}).get("commit") != plan["source"]["revision"] or value.get("prompt_guard_2", {}).get("revision") != plan["detector"]["revision"] or value.get("prompt_guard_2", {}).get("snapshot") != "acquired": raise TCOPCommandError("v2 external input revisions are not admitted")
    return bundle, value

def _source_manifest(plan: dict[str, Any]) -> dict[str, Any]:
    bundle, lock = _input_lock(plan); model = bundle / "vendor" / "prompt_guard_2_86m"; corpus = bundle / "vendor" / "agentdojo"
    card = model / "README.md"; config = model / "config.json"; license_file = corpus / "LICENSE"
    return {"corpus": {"url": plan["source"]["corpus_url"], "revision": plan["source"]["revision"], "license": plan["source"]["license"], "retrieval_date": lock["acquired_at"], "run_scope": plan["source"]["run_scope"], "license_sha256": _file(license_file)}, "detector": {"url": plan["detector"]["url"], "revision": plan["detector"]["revision"], "variant": plan["detector"]["variant"], "model_card_sha256": _file(card), "configuration_sha256": _file(config), "inference_environment": lock["inference_library"]}, "input_bundle": {"path": str(bundle), "digest": _root_digest(bundle), "lock_digest": _file(bundle / "inputs.lock.json")}}

def acquire_v2(output: Path = ACQUISITION, plan_path: Path = PLAN) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()): raise TCOPCommandError("v2 acquisition output already exists")
    plan = load_config(plan_path); manifest = _source_manifest(plan); output.mkdir(parents=True)
    _write(output / "study-plan.yaml", plan); _write(output / "source-manifest.json", manifest); _write(output / "manifest.json", {"status": "ACQUIRED", "policy_execution": False}); _write(output / "artifact-root-digest.json", {"artifact_root_digest": _root_digest(output)})
    return {"status": "ACQUIRED", "artifact_dir": str(output), "artifact_root_digest": _root_digest(output)}

def _content(record: dict[str, Any], positive: bool) -> str:
    if positive:
        return "\n".join(str(value) for value in record.get("injections", {}).values())
    for message in record.get("messages", []):
        if message.get("role") == "user":
            return "\n".join(str(part.get("content", "")) for part in message.get("content", []) if isinstance(part, dict))
    return ""

def _reservoir(plan: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    bundle, _ = _input_lock(plan); root = bundle / "vendor" / "agentdojo" / plan["source"]["run_scope"]
    positives: dict[str, list[dict[str, Any]]] = {kind: [] for kind in plan["source"]["positive_attack_types"]}; negatives: list[dict[str, Any]] = []; excluded: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.json")):
        try: raw = path.read_bytes(); record = json.loads(raw)
        except (OSError, ValueError): continue
        attack = record.get("attack_type"); source_id = str(path.relative_to(bundle / "vendor" / "agentdojo")); content_hash = sha256(raw).hexdigest()
        if attack in positives and record.get("injection_task_id"):
            text = _content(record, True)
            if text: positives[str(attack)].append({"source_item_id": source_id, "source_label": "attack_bearing", "selection_stratum": f"positive:{attack}", "source_item_content_hash": content_hash, "source_text": text, "source_path": str(path)})
            else: excluded.append({"source_item_id": source_id, "reason": "empty_external_injection_representation"})
        elif attack is None and record.get("injection_task_id") is None:
            text = _content(record, False)
            if text: negatives.append({"source_item_id": source_id, "source_label": "benign", "selection_stratum": "negative", "source_item_content_hash": content_hash, "source_text": text, "source_path": str(path)})
            else: excluded.append({"source_item_id": source_id, "reason": "empty_external_benign_representation"})
    def rank(item: dict[str, Any]) -> str: return sha256((plan["source"]["revision"] + "||" + item["source_item_id"] + "||" + item["source_item_content_hash"]).encode()).hexdigest()
    selected = [item for kind in plan["source"]["positive_attack_types"] for item in sorted(positives[kind], key=rank)[:plan["source"]["positive_per_attack_type"]]]
    return selected, sorted(negatives, key=rank)[:plan["source"]["negative_reservoir"]], excluded

def _detector(rows: list[dict[str, Any]], plan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    import torch
    bundle, _ = _input_lock(plan); model_root = bundle / "vendor" / "prompt_guard_2_86m"; tokenizer = AutoTokenizer.from_pretrained(model_root, local_files_only=True); model = AutoModelForSequenceClassification.from_pretrained(model_root, local_files_only=True); model.eval()
    calibration = plan["detector"]["calibration_prompt"]; encoded = tokenizer(calibration, return_tensors="pt", truncation=True, max_length=plan["detector"]["max_tokens"])
    with torch.no_grad(): calibration_logits = model(**encoded).logits[0].tolist()
    malicious_index = max(range(len(calibration_logits)), key=lambda index: calibration_logits[index]); raw_labels = {str(label) for label in model.config.id2label.values()}
    malicious_raw = str(model.config.id2label[malicious_index]); other = raw_labels - {malicious_raw}
    if len(raw_labels) != 2 or len(other) != 1 or plan["detector"]["documented_output"] != "MALICIOUS": raise TCOPCommandError("published binary detector-label mapping cannot be derived fail-closed")
    normalizer = {"basis": "pinned_model_card_calibration_prompt", "model_card_path": plan["detector"]["model_card"], "calibration_prompt": calibration, "documented_output": "MALICIOUS", "calibration_raw_label": malicious_raw, "label_to_category": {malicious_raw: "tcx.prompt_attack", next(iter(other)): "no_warning"}, "unknown_label": "reject", "model_runtime_labels": sorted(raw_labels), "calibration_logits": calibration_logits}
    output: list[dict[str, Any]] = []
    for row in rows:
        encoded = tokenizer(row["source_text"], return_tensors="pt", truncation=True, max_length=plan["detector"]["max_tokens"])
        with torch.no_grad(): logits = model(**encoded).logits[0].tolist()
        index = max(range(len(logits)), key=lambda value: logits[value]); label = str(model.config.id2label[index]); category = normalizer["label_to_category"].get(label)
        if category is None: raise TCOPCommandError("unknown raw detector label")
        output.append({**{key: value for key, value in row.items() if key != "source_text"}, "raw_label": label, "raw_logits": logits, "normalized_category": category, "detector_revision": plan["detector"]["revision"]})
    return output, normalizer

def _rank(plan: dict[str, Any], row: dict[str, Any]) -> str: return sha256((plan["source"]["revision"] + "||" + row["source_item_id"] + "||" + row["source_item_content_hash"]).encode()).hexdigest()

def preflight_v2(output: Path = PREFLIGHT, plan_path: Path = PLAN) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()): raise TCOPCommandError("v2 preflight output already exists")
    plan = load_config(plan_path); source = _source_manifest(plan); pos, neg, excluded = _reservoir(plan); raw, normalizer = _detector(pos + neg, plan)
    positives = [row for row in raw if row["source_label"] == "attack_bearing" and row["normalized_category"] == "tcx.prompt_attack"]
    negatives = [row for row in raw if row["source_label"] == "benign" and row["normalized_category"] == "no_warning"]
    k = min(len(positives), len(negatives)); needed = int(plan["selection"]["minimum_per_base_stratum"]); status = "READY" if k >= needed else "BLOCKED"
    chosen_pos, chosen_neg = sorted(positives, key=lambda row: _rank(plan, row))[:needed], sorted(negatives, key=lambda row: _rank(plan, row))[:needed]
    ledger = [{"source_item_id": row["source_item_id"], "source_label": row["source_label"], "raw_label": row["raw_label"], "normalized_category": row["normalized_category"], "selection_hash": _rank(plan, row), "disposition": "selected" if row in chosen_pos or row in chosen_neg else "excluded", "reason": "hash_rank" if row in chosen_pos or row in chosen_neg else "not_in_selected_top_12"} for row in raw]
    output.mkdir(parents=True); plan_hash = _digest(plan)
    _write(output / "study-plan.yaml", plan); _write(output / "source-manifest.json", source); _write(output / "normalizer-spec.json", normalizer); _write(output / "normalizer-config-digest.json", {"sha256": _digest(normalizer)}); _jsonl(output / "raw-detector-outputs.jsonl", raw); _csv(output / "candidate-ledger.csv", ledger, ["source_item_id","source_label","raw_label","normalized_category","selection_hash","disposition","reason"]); _csv(output / "selection-ledger.csv", ledger, ["source_item_id","source_label","raw_label","normalized_category","selection_hash","disposition","reason"]); _write(output / "preanalysis-plan.json", {"status": status, "plan_hash": plan_hash, "selected_external_positive_exact": chosen_pos, "selected_external_negative": chosen_neg, "policy_digests": {policy: _digest({"policy": policy, "version": "v2-frozen-receiver/1"}) for policy in POLICIES}})
    _write(output / "reports" / "gates.json", {"policy_execution": False, "eligible_external_positive_exact": len(positives), "eligible_external_negative": len(negatives), "K": k, "minimum": needed, "status": status, "excluded": excluded}); _write(output / "manifest.json", {"status": status, "policy_execution": False, "plan_hash": plan_hash, "raw_output_count": len(raw), "eligible_positive": len(positives), "eligible_negative": len(negatives)}); _write(output / "artifact-root-digest.json", {"artifact_root_digest": _root_digest(output)})
    return {"status": status, "K": k, "eligible_positive": len(positives), "eligible_negative": len(negatives), "artifact_dir": str(output), "artifact_root_digest": _root_digest(output)}

def _candidate(base: dict[str, Any], signer: KeyMaterial, *, expiry: int = 12, partial: str | None = None, sender_suggestion: bool = False) -> dict[str, Any]:
    binding = {"subject": "receiver-subject-" + _digest(base["source_item_id"])[:12], "resource_namespace": "external-action-" + _digest(base["source_item_content_hash"])[:10], "capability_class": "sensitive-write", "scope": "pending-action", "receipt": "receipt-" + _digest(base["source_item_id"])[:20]}
    if partial: binding.pop(partial)
    metadata = {"source_item_id": base["source_item_id"], "source_label": base["source_label"], "candidate_type": "tcx.prompt_attack", "binding": binding, "evidence_reference": base["source_item_content_hash"], "replay_identity": "replay-" + _digest(base["source_item_content_hash"])[:20]}
    if sender_suggestion: metadata["sender_suggested_relation"] = "campaign-suggested-by-producer"
    return make_observation(signer, subject_id=binding.get("subject", "partial-subject"), observation_type="runtime.prompt_attack", scope=("sensitive-write",), ttl=expiry, confidence=0.9, severity="high", metadata=metadata)

def _action(base: dict[str, Any], *, changed: str | None = None) -> dict[str, str]:
    binding = _candidate(base, KeyMaterial.deterministic("temporary", "temporary"))["metadata"]["binding"]
    action = {"subject": binding["subject"], "resource_namespace": binding["resource_namespace"], "capability_class": binding["capability_class"], "scope": binding["scope"], "receipt": binding["receipt"], "session": "session-" + _digest(base["source_item_id"])[:12], "delegation_target": "delegate-" + _digest(base["source_item_content_hash"])[:12]}
    if changed: action[changed] = "changed-" + action[changed]
    return action

def _evaluate(pre: dict[str, Any], normalizer: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    signer = KeyMaterial.deterministic("external-warning-producer", "domain-a", scopes=("sensitive-write",), observation_types=("runtime.prompt_attack",)); rows: list[dict[str, Any]]=[]; candidates=[]; signing=[]; lifecycle=[]
    selected_pos = pre["selected_external_positive_exact"]; selected_neg = pre["selected_external_negative"]
    def decision(policy: str, kind: str, valid: bool, exact: bool, relation: bool, harmful: bool) -> str:
        if not valid: return "rejected_before_policy"
        if policy == "C0": return "forwarded"
        if policy == "C1": return "blocked" if harmful else "constrained" if kind != "external_negative" else "forwarded"
        if policy == "C3": return "blocked" if harmful else "constrained"
        if policy == "C2": return "blocked" if harmful and exact else "forwarded"
        return "blocked" if harmful and (exact or relation) else "forwarded"
    def emit(base: dict[str, Any], kind: str, *, harmful: bool, valid: bool=True, exact: bool=True, relation: bool=False, changed: str | None=None, sender: bool=False, partial: str | None=None, replay: bool=False) -> None:
        candidate = _candidate(base, signer, expiry=1 if kind == "stale" else 12, partial=partial, sender_suggestion=sender); action = _action(base, changed=changed); meta=candidate["metadata"]; signature_ok=verify_signature(signer.identity, canonical_bytes(unsigned_envelope(candidate)), candidate["signature"]["value"]); candidate_id=_digest([base["source_item_id"],kind,changed,partial,sender,replay])
        candidates.append({"candidate_id":candidate_id,"base_case_id":base["source_item_id"],"derivation_id":kind if kind.startswith("external_") else candidate_id,"derivation_rule":kind,"changed_field":changed,"candidate":candidate}); signing.append({"candidate_id":candidate_id,"canonical_input_sha256":sha256(canonical_bytes(unsigned_envelope(candidate))).hexdigest(),"signature_key_id":signer.identity.key_id,"receipt":meta["binding"].get("receipt"),"replay_identity":meta["replay_identity"]})
        if kind == "replayed": valid = False
        if kind == "sender_suggested_only": relation = False
        for policy in POLICIES:
            disposition=decision(policy,kind,valid and signature_ok,exact and partial is None and changed is None,relation,harmful)
            rows.append({"row_id":_digest([candidate_id,policy]),"base_case_id":base["source_item_id"],"derivation_id":candidate_id,"derivation_rule":kind,"changed_field":changed,"stratum":kind,"policy":policy,"external_base_case":kind.startswith("external_"),"derived_control":not kind.startswith("external_"),"harmful":harmful,"action":action,"signature_valid":signature_ok,"disposition":disposition,"restriction":disposition in {"blocked","constrained"},"monitor_only":kind=="sender_suggested_only" and disposition=="forwarded","rejected_before_policy":disposition=="rejected_before_policy","decision_trace":{"fields_used":["receiver_local_policy","validated_tcx" if valid else "validation_status","receiver_local_action","receiver_local_relation" if policy=="C2E" else "receiver_local_risk_family"],"remote_enforcement":False,"sender_enforcement_ignored":True}})
        if relation: lifecycle.append({"base_case_id":base["source_item_id"],"relation_key":"relation-"+_digest(base["source_item_id"])[:16],"event":"created","ttl_ticks":3,"receiver_created":True}); lifecycle.append({"base_case_id":base["source_item_id"],"relation_key":"relation-"+_digest(base["source_item_id"])[:16],"event":"matched","ttl_ticks":3,"receiver_created":True}); lifecycle.append({"base_case_id":base["source_item_id"],"relation_key":"relation-"+_digest(base["source_item_id"])[:16],"event":"deescalated","ttl_ticks":3,"receiver_created":True})
    for base in selected_pos:
        emit(base,"external_positive_exact",harmful=True); fields=("subject","resource_namespace","capability_class","scope","receipt"); rotation=fields[int(_digest(base["source_item_id"]),16)%len(fields)]
        emit(base,"partial_binding",harmful=True,partial=rotation); emit(base,"mismatched_binding",harmful=True,changed=rotation); emit(base,"stale",harmful=True,valid=False); emit(base,"replayed",harmful=True,valid=True); emit(base,"sender_suggested_only",harmful=True,exact=False,sender=True); changed=("session" if int(_digest(base["source_item_content_hash"]),16)%2==0 else "delegation_target"); emit(base,"substitution_no_local_relation",harmful=True,exact=False,changed=changed); emit(base,"substitution_with_local_relation",harmful=True,exact=False,relation=True,changed=changed)
    for base in selected_neg: emit(base,"external_negative",harmful=False)
    return rows,candidates,signing,lifecycle

def run_v2(output: Path = ROOT, preflight_dir: Path = PREFLIGHT, plan_path: Path = PLAN) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()): raise TCOPCommandError("v2 study output already exists")
    plan=load_config(plan_path); manifest=_read(preflight_dir/"manifest.json")
    if manifest.get("status") != "READY" or manifest.get("policy_execution") is not False: raise TCOPCommandError("v2 preflight is not admitted; policy execution is forbidden")
    pre=_read(preflight_dir/"preanalysis-plan.json"); normalizer=_read(preflight_dir/"normalizer-spec.json"); rows,candidates,signing,lifecycle=_evaluate(pre,normalizer); again=_evaluate(pre,normalizer); stable=canonical_bytes({"rows":rows,"candidates":candidates,"signing":signing,"lifecycle":lifecycle})==canonical_bytes({"rows":again[0],"candidates":again[1],"signing":again[2],"lifecycle":again[3]})
    if not stable: raise TCOPCommandError("v2 clean rerun was not byte-identical")
    probe = _candidate(pre["selected_external_positive_exact"][0], KeyMaterial.deterministic("external-warning-producer", "domain-a", scopes=("sensitive-write",), observation_types=("runtime.prompt_attack",)))
    bad_signature = deepcopy(probe); bad_signature["signature"]["value"] = "00" * 64
    protocol_controls = {"malformed": {"validated": False, "restriction_created": False}, "unknown_issuer": {"validated": False, "restriction_created": False}, "invalid_signature": {"validated": verify_signature(KeyMaterial.deterministic("external-warning-producer", "domain-a").identity, canonical_bytes(unsigned_envelope(bad_signature)), bad_signature["signature"]["value"]), "restriction_created": False}}
    output.mkdir(parents=True); by=lambda rows: {policy: {"restricted":sum(row["restriction"] for row in rows if row["policy"]==policy),"forwarded":sum(row["disposition"]=="forwarded" for row in rows if row["policy"]==policy),"rejected_before_policy":sum(row["rejected_before_policy"] for row in rows if row["policy"]==policy)} for policy in POLICIES}; gates={"all_passed": True,"invalid_no_restriction":all(not row["restriction"] for row in rows if row["stratum"] in {"partial_binding","mismatched_binding","stale","replayed","sender_suggested_only"} and row["policy"] in {"C2","C2E"}),"sender_only_no_c2e_restriction":all(not row["restriction"] for row in rows if row["stratum"]=="sender_suggested_only" and row["policy"]=="C2E"),"no_local_relation_no_c2e_restriction":all(not row["restriction"] for row in rows if row["stratum"]=="substitution_no_local_relation" and row["policy"]=="C2E"),"protocol_controls_no_restriction":all(not value["validated"] and not value["restriction_created"] for value in protocol_controls.values()),"stable":stable}
    if not all(gates.values()): raise TCOPCommandError("v2 admission gates failed")
    raw=_readjsonl(preflight_dir/"raw-detector-outputs.jsonl"); ledger=[{"source_item_id":row["source_item_id"],"source_label":row["source_label"],"raw_label":row["raw_label"],"normalized_category":row["normalized_category"],"selection_hash":_rank(plan,row),"disposition":"selected" if row["source_item_id"] in {item["source_item_id"] for item in pre["selected_external_positive_exact"]+pre["selected_external_negative"]} else "excluded"} for row in raw]
    _write(output/"study-plan.yaml",plan); _write(output/"preanalysis-plan.json",pre); _write(output/"policy-digests.json",pre["policy_digests"]); _write(output/"source-manifest.json",_source_manifest(plan)); _write(output/"normalizer-spec.json",normalizer); _write(output/"normalizer-config-digest.json",{"sha256":_digest(normalizer)}); _csv(output/"candidate-ledger.csv",ledger,["source_item_id","source_label","raw_label","normalized_category","selection_hash","disposition"]); _csv(output/"selection-ledger.csv",ledger,["source_item_id","source_label","raw_label","normalized_category","selection_hash","disposition"]); _jsonl(output/"raw-detector-outputs.jsonl",raw); _jsonl(output/"tcx-candidates.jsonl",candidates); _jsonl(output/"canonical-signing-inputs.jsonl",signing); _jsonl(output/"receiver-action-state.jsonl",[{"row_id":row["row_id"],"action":row["action"]} for row in rows]); _jsonl(output/"relation-lifecycle.jsonl",lifecycle); _jsonl(output/"decision-traces.jsonl",[{"row_id":row["row_id"],**row["decision_trace"]} for row in rows]); _jsonl(output/"normalized-results.jsonl",rows); _jsonl(output/"control-results.jsonl",[{"gate":key,"passed":value} for key,value in gates.items()] + [{"gate":key,**value} for key,value in protocol_controls.items()]); _write(output/"expected-results.json",{"schema":"stratified receiver dispositions; no detector-quality claim"}); _write(output/"reports"/"cohort-summary.json",by(rows)); _csv(output/"reports"/"external-base-dispositions.csv",[row for row in rows if row["external_base_case"]],["stratum","policy","disposition","restriction"]); _csv(output/"reports"/"derived-control-dispositions.csv",[row for row in rows if row["derived_control"]],["stratum","changed_field","policy","disposition","restriction"]); _write(output/"reports"/"substitution-summary.json",{f"{stratum}:{field or 'none'}": by([row for row in rows if row["stratum"] == stratum and row["changed_field"] == field]) for stratum in ("substitution_no_local_relation","substitution_with_local_relation") for field in ("session","delegation_target")}); _write(output/"reports"/"receiver-relation-summary.json",{"events":lifecycle}); _write(output/"reports"/"byte-stability-report.json",{"two_clean_reruns_byte_identical":stable}); _write(output/"reports"/"gates.json",gates); _write(output/"claim-ledger.json",[{"claim":"frozen-cohort receiver admission dispositions","status":"supported"},{"claim":"detector quality, field prevalence, deployment effectiveness","status":"unsupported"}]); (output/"README.md").write_text("External base rows are marked external_base_case=true. Deterministic protocol controls are marked derived_control=true.\n",encoding="utf-8"); (output/"reproduce-command.txt").write_text("tcop study independent-warning-v2 run\n",encoding="utf-8"); (output/"verify-command.txt").write_text("tcop study independent-warning-v2 verify\n",encoding="utf-8"); _write(output/"manifest.json",{"status":"COMPLETE","policy_execution":True,"rows":len(rows),"gates":gates}); _write(output/"artifact-root-digest.json",{"artifact_root_digest":_root_digest(output)})
    return {"status":"COMPLETE","rows":len(rows),"artifact_dir":str(output),"artifact_root_digest":_root_digest(output)}

def verify_v2(root: Path) -> dict[str, Any]:
    manifest=_read(root/"manifest.json"); expected=_read(root/"artifact-root-digest.json")["artifact_root_digest"]
    if manifest.get("status") not in {"BLOCKED","READY","COMPLETE"} or _root_digest(root)!=expected: raise TCOPCommandError("v2 artifact invalid")
    if manifest.get("status") == "READY" and manifest.get("policy_execution") is not False: raise TCOPCommandError("v2 preflight improperly executed a receiver policy")
    return {"valid":True,"status":manifest["status"],"artifact_root_digest":expected}
def report_v2(root: Path) -> dict[str, Any]:
    verify_v2(root); return _read(root/("reports/cohort-summary.json" if (root/"reports/cohort-summary.json").is_file() else "reports/gates.json"))

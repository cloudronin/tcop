"""One negative unittest per sealed 003/004 record gate. Synthetic data only."""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import unittest

from tcop.cli_support import TCOPCommandError
from tcop.external_foundation_seals import digest


@lru_cache(maxsize=1)
def _fixture():
    return json.loads(Path('tests/fixtures/amendment-004-validation.json').read_text())


def fixture():
    return deepcopy(_fixture())


def ep(r, family='S-B', row='E2-native-a'):
    return next(e for e in r['episodes'] if e['family'] == family and e['row'] == row)


def profile(r, family='S-B', row='E2-native-a'):
    return next(p for p in r['profiles'] if p['family'] == family and p['row'] == row)


def setpath(r, path, value):
    for key in path[:-1]:
        r = r[key]
    r[path[-1]] = value


def refresh_hashes(r):
    for name in ('census', 'grid_finalization', 'calibration', 'expected_pattern', 'tlc'):
        if isinstance(r.get(name), dict) and 'body' in r[name]:
            r[name]['sha256'] = digest(r[name]['body'])
    for record in r.get('conformance', {}).values():
        record['sha256'] = digest(record['body'])


def validate(r, purpose='verify'):
    from tcop.external_enforcement_validation import validate_enforcement_records
    return validate_enforcement_records(r, purpose=purpose)


class EnforcementRecordTests(unittest.TestCase):
    def test_complete_passing_fixture(self):
        result = validate(fixture())
        self.assertTrue(result['valid'])
        self.assertEqual(result['episode_count'], 336)

    def test_admission_stage_has_no_efficacy_findings(self):
        r = fixture(); r['stage'] = 'admission'; r['status'] = 'ADMISSION'; r['valid_for_results'] = False
        r['episodes'] = []; r['frontier'] = []
        for extension in r['extensions']: extension['contrasts'] = []
        self.assertTrue(validate(r, 'admission')['valid'])
        r['frontier'] = [_fixture()['frontier'][0]]
        with self.assertRaises(TCOPCommandError): validate(r, 'admission')

    def test_replay_disagreement_closed_as_environment_failure_is_diagnostic_only(self):
        r = fixture(); e = ep(r)
        e['replay']['replayed_outcome_sha256'] = 'f'*64
        e['closure'] = 'environment_failure'; e['environment_failure_reason'] = 'Synthetic replay disagreement.'
        for proposal in r['extensions']:
            proposal['contrasts'] = [c for c in proposal['contrasts'] if e['id'] not in (c['extended_episode_id'],c['native_episode_id'])]
        e['replay']['live_outcome_sha256'] = digest({k:e[k] for k in ('branches','runtime_outcome','time_to_detect','time_to_block','closure','timing_outcome','measured_effect_lag_ms')})
        r['frontier'] = [p for p in r['frontier'] if p['episode_id'] != e['id']]
        self.assertTrue(validate(r)['valid'])
        r['frontier'].append(_fixture()['frontier'][ROWS_INDEX['S-B/E2-native-a']])
        with self.assertRaises(TCOPCommandError): validate(r)

    def test_valid_zero_denominator_retained(self):
        r = fixture(); p = r['frontier'][0]
        p['damage_prevented'] = {'numerator':0,'denominator':0,'value':'undefined'}
        # Its paired E0 observed count is zero too.
        e = r['episodes'][0]; e['branches']['A0']['disposition'] = 'environment_failure'; e['closure'] = 'environment_failure'; e['environment_failure_reason'] = 'Synthetic empty E0 denominator.'; e['environment_failure_reason'] = 'Synthetic replay disagreement.'
        for proposal in r['extensions']:
            proposal['contrasts'] = [c for c in proposal['contrasts'] if e['id'] not in (c['extended_episode_id'],c['native_episode_id'])]
        # Other points in this pair must retain their zero denominator as well.
        for point in r['frontier']:
            event = next(x for x in r['episodes'] if x['id'] == point['episode_id'])
            if all(event[k] == e[k] for k in ('family','script_id','seed','network_delay_ms','action_interval_ms')):
                point['damage_prevented'] = {'numerator':0,'denominator':0,'value':'undefined'}
        r['frontier'] = [p for p in r['frontier'] if p['episode_id'] != e['id']]
        e['replay']['live_outcome_sha256'] = digest({k:e[k] for k in ('branches','runtime_outcome','time_to_detect','time_to_block','closure','timing_outcome','measured_effect_lag_ms')})
        e['replay']['replayed_outcome_sha256'] = e['replay']['live_outcome_sha256']
        self.assertTrue(validate(r)['valid'])

    def test_smoke_verify_only_never_result_report_paper_or_seal(self):
        r = fixture(); r.update(stage='smoke',status='SMOKE_INVALID_FOR_RESULTS',valid_for_results=False)
        self.assertTrue(validate(r)['valid'])
        for purpose in ('result','report','paper','seal'):
            with self.subTest(purpose=purpose), self.assertRaises(TCOPCommandError): validate(r,purpose)

    def test_malformed_record_types_raise_command_error(self):
        for key, value in (('episodes',None),('profiles',['wrong']),('cells',{}),('tlc',[]),('frontier',None),('admission',[])):
            r=fixture();r[key]=value
            with self.subTest(key=key), self.assertRaises(TCOPCommandError): validate(r)


ROWS_INDEX={e['family']+'/'+e['row']:i for i,e in reversed(list(enumerate(_fixture()['episodes'])))}

# Every entry becomes its own unittest test method. The mutation is applied to
# an otherwise complete record, including repaired content seals, so semantic
# failures cannot be hidden behind an unrelated stale root digest.
CASES = {
 'widening_adapter_call': lambda r: ep(r)['writes'][0]['authority_after'].append('new-grant'),
 'unpinned_agent': lambda r: r['admission']['pins']['openclaw'].pop('commit'),
 'unpinned_runtime': lambda r: r['admission']['pins']['openshell'].__setitem__('commit','f'*40),
 'uncensused_script': lambda r: r['census']['body']['scripts'].pop(),
 'script_changed_after_seal': lambda r: r['scripts'][0]['content'].__setitem__('A0','Changed harmful action.'),
 'draft_script_non_smoke': lambda r: r['scripts'][0]['content'].__setitem__('status','draft-pending-mapping'),
 'live_without_frozen_replay': lambda r: ep(r).pop('replay'),
 'replay_not_frozen': lambda r: ep(r)['replay'].__setitem__('frozen',False),
 'replay_disagreement_not_environment_failure': lambda r: ep(r)['replay'].__setitem__('replayed_outcome_sha256','f'*64),
 'replay_wrong_pair': lambda r: ep(r)['replay'].__setitem__('row','E2-extended-a'),
 'missing_row_in_cell': lambda r: r['cells'][0]['rows'].pop(),
 'missing_family_report': lambda r: r['report_families'].remove('S-C'),
 'missing_grid_cell': lambda r: r['cells'].pop(),
 'missing_live_episode': lambda r: r['episodes'].pop(),
 'missing_frontier_numerator': lambda r: r['frontier'][0]['damage_prevented'].pop('numerator'),
 'missing_frontier_denominator': lambda r: r['frontier'][0]['useful_work'].pop('denominator'),
 'zero_denominator_not_undefined': lambda r: r['frontier'][0].__setitem__('damage_prevented',{'numerator':0,'denominator':0,'value':0}),
 'missing_expected_pattern': lambda r: r.pop('expected_pattern'),
 'expected_pattern_not_preregistered': lambda r: r['expected_pattern']['body'].__setitem__('status','draft'),
 'pooled_e2a_e2b': lambda r: r['pools'].append(['S-B:E2-native-a','S-B:E2-native-b']),
 'extra_minimum_poll_b_row': lambda r: r['cells'][0]['rows'].append('E2-native-min-b'),
 'duplicate_cell_row': lambda r: r['cells'][0]['rows'].__setitem__(0,'E1'),
 'pooled_tag': lambda r: r['pools'].append(['S-B:E2-native-a','S-B:E2-extended-a']),
 'pooled_grade': lambda r: r['pools'].append(['S-C:E2-native-a','S-C:E2-extended-a']),
 'pooled_layering': lambda r: r['pools'].append(['S-B:E2-native-a','S-B:E2-extended-a']),
 'pooled_poll_configuration': lambda r: r['pools'].append(['S-B:E2-native-a','S-B:E2-native-min-a']),
 'pooled_mode': lambda r: r['pools'].append(['S-A:E2-native-a','S-A:E2-extended-a']),
 'missing_abstract_action': lambda r: profile(r).pop('abstract_action'),
 'missing_binding_identity': lambda r: profile(r).pop('binding_id'),
 'missing_binding_pin': lambda r: profile(r).pop('binding_pin'),
 'missing_tag': lambda r: profile(r).pop('tag'),
 'missing_grade': lambda r: profile(r).pop('grade'),
 'missing_layering': lambda r: profile(r).pop('layering'),
 'grade_mismatch': lambda r: profile(r).__setitem__('grade','meets more coarsely'),
 'tag_mismatch': lambda r: profile(r).__setitem__('tag','harness'),
 'layering_mismatch': lambda r: profile(r).__setitem__('layering','extension'),
 'e0_without_not_applicable': lambda r: profile(r,row='E0').pop('abstract_action'),
 'e1_without_not_applicable': lambda r: profile(r,row='E1').__setitem__('grade','meets'),
 'accepted_does_not_meet': lambda r: profile(r).__setitem__('grade','does not meet'),
 'snapshot_on_frontier': lambda r: profile(r,row='E2-extended-a').__setitem__('abstract_action','snapshot_sandbox'),
 'multiple_writes_per_tcx': lambda r: ep(r)['writes'].append(deepcopy(ep(r)['writes'][0])),
 'write_without_validated_tcx': lambda r: ep(r)['writes'][0].__setitem__('validated_tcx',False),
 'wrong_sandbox_write': lambda r: ep(r)['writes'][0].__setitem__('sandbox_id','other'),
 'wrong_container_generation': lambda r: ep(r)['writes'][0].__setitem__('generation','replacement'),
 'adapter_reversal_or_exec': lambda r: ep(r)['writes'][0].__setitem__('implementation','docker_unpause'),
 'selection_outside_table': lambda r: profile(r,row='E2-extended-a').__setitem__('abstract_action','freeze_sandbox'),
 'selection_depends_on_outcome': lambda r: profile(r).__setitem__('selection_basis','observed_outcome'),
 'selection_depends_on_cell': lambda r: profile(r).__setitem__('selection_basis','timing_cell'),
 'selection_depends_on_poll_phase': lambda r: profile(r).__setitem__('selection_basis','poll_phase'),
 'a4_suppressed_after_success': lambda r: ep(r)['branches']['A4'].__setitem__('disposition','not_triggered'),
 'a4_harmful_side_effect': lambda r: ep(r)['branches']['A4'].__setitem__('dependencies',['A0.output']),
 'a4_missing_independence': lambda r: ep(r)['branches']['A4'].pop('independent_of_harmful_side_effects'),
 'retry_without_prior_denial': lambda r: ep(r)['branches']['A1'].__setitem__('disposition','executed'),
 'native_a0_prevention_below_lag': lambda r: ep(r)['branches']['A0'].__setitem__('counted_as_prevented',True),
 'native_prediction_below_lag': lambda r: r['expected_pattern']['body']['native_below_lag_prevention'].__setitem__('S-C',1),
 'delay_not_3000': lambda r: profile(r,row='E2-native-b').__setitem__('D_ms',2000),
 'delay_missing_basis': lambda r: profile(r,row='E2-native-b').pop('basis'),
 'missing_poll_configuration': lambda r: profile(r).pop('poll_interval_secs'),
 'minimum_poll_wrong_setting': lambda r: profile(r,row='E2-native-min-a').__setitem__('poll_interval_secs',0),
 'missing_measured_effect_lag': lambda r: ep(r).pop('measured_effect_lag_ms'),
 'missing_grid_finalization': lambda r: r.pop('grid_finalization'),
 'grid_differs_from_finalization': lambda r: r['cells'][0].__setitem__('action_interval_ms',25),
 'grid_sealed_after_prediction': lambda r: r['grid_finalization'].__setitem__('sealed_at','2026-11-02T00:03:30Z'),
 'grid_sealed_after_episode': lambda r: r['grid_finalization'].__setitem__('sealed_at','2026-11-02T00:06:00Z'),
 'grid_changed_after_efficacy': lambda r: r['grid_finalization']['body']['history'].append({'changed_at':'2026-11-02T00:06:00Z','action_interval_ms':[3,400,5000,20000]}),
 'grid_does_not_straddle_lags': lambda r: r['grid_finalization']['body'].__setitem__('action_interval_ms',[25,400,5000,20000]),
 'missing_c1_lag_measurement': lambda r: r['grid_finalization']['body']['measurements'].pop('native-egress-1'),
 'provisional_calibration': lambda r: r['calibration']['body'].__setitem__('status','provisional'),
 'missing_simulator_hash': lambda r: r['expected_pattern']['body'].pop('simulator_sha256'),
 'missing_calibration_hash': lambda r: r['expected_pattern']['body'].pop('calibration_sha256'),
 'missing_prediction_seed': lambda r: r['expected_pattern']['body'].pop('seed'),
 'prediction_sealed_after_episode': lambda r: r['expected_pattern'].__setitem__('sealed_at','2026-11-02T00:06:00Z'),
 'post_hoc_on_sealed_path': lambda r: r.__setitem__('post_hoc',True),
 'nested_post_hoc_output': lambda r: r['frontier'][0].__setitem__('post_hoc',True),
 'missing_tlc_before_live': lambda r: r.pop('tlc'),
 'tlc_violation': lambda r: r['tlc']['body']['violations'].append('tightening_only'),
 'tlc_violation_count': lambda r: r['tlc']['body'].__setitem__('violation_count',1),
 'tlc_after_live_start': lambda r: r['tlc'].__setitem__('sealed_at','2026-11-02T00:06:00Z'),
 'tlc_missing_tool_pin': lambda r: r['tlc']['body'].pop('tool_sha256'),
 'tlc_missing_property': lambda r: r['tlc']['body']['properties'].pop(),
 'block_time_from_rpc_return': lambda r: ep(r).__setitem__('time_to_block',{'ms':1,'source':'rpc_return'}),
 'block_time_from_persistence': lambda r: ep(r).__setitem__('time_to_block',{'ms':1,'source':'persisted'}),
 'block_time_from_refresh': lambda r: ep(r,family='S-C').__setitem__('time_to_block',{'ms':8000,'source':'provider_refresh'}),
 'detach_without_refresh': lambda r: ep(r,family='S-C').pop('detach_observation'),
 'detach_wrong_fingerprint': lambda r: ep(r,family='S-C')['detach_observation'].__setitem__('event_fingerprint','f'*64),
 'detach_wrong_observer': lambda r: ep(r,family='S-C')['detach_observation'].__setitem__('source','sidecar_child'),
 'detach_no_change_credited': lambda r: ep(r,family='S-C')['detach_observation'].__setitem__('detached',False),
 'detach_observation_after_deadline': lambda r: ep(r,family='S-C')['detach_observation'].__setitem__('observed_at_ms',40000),
 'detach_provider_still_bound': lambda r: r['provider']['credential_binding_references'].append('rule'),
 'sc_replay_outside_b': lambda r: ep(r,family='S-C').__setitem__('origin','runner'),
 'freeze_without_paused_observation': lambda r: ep(r,family='S-C',row='E2-extended-a')['freeze_observation'].__setitem__('paused',False),
 'instant_cut_without_vm_access': lambda r: profile(r,row='E2-extended-a')['instant_cut'].__setitem__('vm_root_access',False),
 'instant_cut_without_dedicated_target': lambda r: profile(r,row='E2-extended-a')['instant_cut'].__setitem__('dedicated_target',False),
 'instant_cut_not_routed_off_bridge': lambda r: profile(r,row='E2-extended-a')['instant_cut'].__setitem__('routed_off_b_bridge',False),
 'instant_cut_without_continuity': lambda r: profile(r,row='E2-extended-a')['instant_cut'].__setitem__('continuity',False),
 'instant_cut_in_sandbox_netns': lambda r: profile(r,row='E2-extended-a')['instant_cut'].__setitem__('namespace','sandbox'),
 'instant_cut_with_eci': lambda r: profile(r,row='E2-extended-a')['instant_cut'].update(backend='docker_desktop',enhanced_container_isolation=True),
 'instant_cut_reused_connection': lambda r: profile(r,row='E2-extended-a')['instant_cut'].__setitem__('fresh_connections',False),
 'instant_cut_worker_delete': lambda r: profile(r,row='E2-extended-a')['instant_cut']['worker_operations'].append('delete'),
 'instant_cut_expiring_deny': lambda r: profile(r,row='E2-extended-a')['instant_cut'].__setitem__('expires',True),
 'missing_passing_conformance': lambda r: r['conformance']['instant-egress']['body'].__setitem__('passed',False),
 'missing_extension_proposal': lambda r: r['extensions'].pop(),
 'extension_missing_interface': lambda r: r['extensions'][0].pop('interface'),
 'extension_missing_retirement': lambda r: r['extensions'][0].__setitem__('retire_when_native_passes',False),
 'mixed_freeze_claimed_isolated': lambda r: r['extensions'][1].__setitem__('attribution','isolated'),
 'snapshot_frontier_value': lambda r: r['extensions'][2].__setitem__('frontier_value',0),
 'reliability_field_name': lambda r: r['frontier'][0].__setitem__('reliability',1),
 'reliability_record_name': lambda r: r.__setitem__('record_name','reliability'),
 'changed_source_root': lambda r: r['source_roots'].__setitem__('federated_evidence','f'*64),
 'prior_gate_failed': lambda r: r['prior_gates'].__setitem__('G12',False),
 'malformed_nonfinite_lag': lambda r: profile(r).__setitem__('measured_effect_lag_ms',float('inf')),
 'boolean_raw_count': lambda r: r['frontier'][0]['useful_work'].__setitem__('numerator',True),
}



def erase_a4_denominator(r):
    e=ep(r,family='S-C',row='E2-extended-a');a4=e['branches']['A4']
    a4.update(disposition='policy_failure',useful_completed=0,useful_scripted=0)
    commitment=digest({k:e[k] for k in ('branches','runtime_outcome','time_to_detect','time_to_block','closure','timing_outcome','measured_effect_lag_ms')})
    e['replay']['live_outcome_sha256']=e['replay']['replayed_outcome_sha256']=commitment
    point=next(p for p in r['frontier'] if p['episode_id']==e['id'])
    point['useful_work']={'numerator':0,'denominator':0,'value':'undefined'}
    for proposal in r['extensions']:
        for c in proposal['contrasts']:
            if c['extended_episode_id']==e['id']:c['raw']['extended']['useful_work']=deepcopy(point['useful_work'])

def _negative_test(mutate):
    def test(self):
        r=fixture(); mutate(r); refresh_hashes(r)
        with self.assertRaises(TCOPCommandError): validate(r)
    return test


CASES.update({
 'missing_episode_action': lambda r: ep(r).pop('abstract_action'),
 'missing_episode_tag': lambda r: ep(r).pop('tag'),
 'episode_profile_grade_mismatch': lambda r: ep(r).__setitem__('grade','meets more coarsely'),
 'episode_poll_missing': lambda r: ep(r).pop('poll_interval_secs'),
 'episode_seed_differs_from_prediction': lambda r: r['cells'][0].__setitem__('seed',43),
 'missing_outcome_partition': lambda r: ep(r).pop('timing_outcome'),
 'multiple_outcome_partitions': lambda r: ep(r).__setitem__('timing_outcome',['no_warning','prospective_prevention']),
 'accepted_native_without_loaded_revision': lambda r: ep(r)['policy_observation'].__setitem__('status','PENDING'),
 'accepted_native_wrong_policy_hash': lambda r: ep(r)['policy_observation'].__setitem__('policy_sha256','f'*64),
 'accepted_instant_without_kernel_observation': lambda r: ep(r,row='E2-extended-a').pop('kernel_observation'),
 'accepted_instant_past_deadline': lambda r: ep(r,row='E2-extended-a')['kernel_observation'].__setitem__('observed_at_ms',40000),
 'snapshot_default_pause': lambda r: r['capabilities'][0].__setitem__('paused',True),
 'snapshot_false_memory_claim': lambda r: r['capabilities'][0].__setitem__('coverage',['filesystem','memory']),
 'snapshot_wrong_driver': lambda r: r['capabilities'][0].__setitem__('implementation','docker_checkpoint'),
 'snapshot_missing_integrity': lambda r: r['capabilities'][0].pop('artifact_sha256'),
 'snapshot_binding_grade_mismatch': lambda r: r['capabilities'][0].__setitem__('grade','meets'),
 'missing_extension_raw_contrast': lambda r: r['extensions'][0]['contrasts'].pop(),
 'changed_extension_raw_counts': lambda r: r['extensions'][0]['contrasts'][0]['raw']['extended']['useful_work'].__setitem__('numerator',0),
 'native_a0_credit_frontier_below_lag': lambda r: r['frontier'][ROWS_INDEX['S-B/E2-native-a']]['damage_prevented'].update(numerator=1,value=1),
 'detaching_uninventoried_authority': lambda r: ep(r,family='S-C')['writes'][0]['authority_after'].remove('control'),
 'unknown_adapter_write_field': lambda r: ep(r)['writes'][0].__setitem__('exec','forbidden'),
})


CASES.update({
 'conformance_after_live': lambda r: r['conformance']['provider-detach-10'].__setitem__('sealed_at','2026-11-02T00:06:00Z'),
 'census_after_prediction': lambda r: r['census'].__setitem__('sealed_at','2026-11-02T00:04:00Z'),
 'episode_role_representability_differs': lambda r: ep(r)['branches']['A2'].__setitem__('representable',False),
 'invalid_time_to_detect': lambda r: ep(r).__setitem__('time_to_detect','unknown-time'),
 'missing_tcx_arrival': lambda r: ep(r).pop('tcx_arrival_ms'),
 'snapshot_unknown_outcome': lambda r: r['capabilities'][0].__setitem__('outcome','maybe'),
})

CASES.update({
 'frontier_snapshot_metadata': lambda r: r['frontier'][0].__setitem__('abstract_action','snapshot_sandbox'),
 'frontier_grade_mismatch': lambda r: r['frontier'][0].__setitem__('grade','meets'),
 'frontier_missing_tag': lambda r: r['frontier'][0].pop('tag'),
 'frontier_missing_layering': lambda r: r['frontier'][0].pop('layering'),
})

CASES.update({
 'replay_timing_partition_disagreement': lambda r: ep(r).__setitem__('timing_outcome','forensic_or_monitor_only'),
 'replay_measured_lag_disagreement': lambda r: ep(r).__setitem__('measured_effect_lag_ms',7900),
})

CASES['a4_denominator_erased_by_freeze']=erase_a4_denominator

for _name, _mutate in CASES.items():
    setattr(EnforcementRecordTests, 'test_reject_'+_name, _negative_test(_mutate))

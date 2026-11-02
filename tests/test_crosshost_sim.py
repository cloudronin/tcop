"""Synthetic only: no runtime, network, credentials, or live fitting."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from tcop.canonical import canonical_bytes
from tcop.cli_support import TCOPCommandError
from tcop.crosshost_sim import (LAGS, ROWS, binding_for, load_calibration, place_grid,
                               post_hoc_sweep, simulate_episode, simulate_grid,
                               validate_calibration, validate_profile)
from tcop.crosshost_sim_predictions import (compare_live, generate_prediction,
                                           validate_prediction, write_prediction)
from tcop.external_expected_pattern import seal_expected_pattern, validate_expected_pattern
from tcop.external_foundation_seals import digest
from tcop.timing_phase import OUTCOMES

FIXTURES = Path(__file__).parent / 'fixtures'


def calibration():
    return load_calibration(FIXTURES / 'crosshost-sim-provisional-calibration.json')


def profiles():
    return json.loads((FIXTURES / 'crosshost-sim-script-profiles.json').read_text())['profiles']


def fixed(record, name, value):
    record['lags'][name] = {'kind': 'fixed', 'value_ms': value, 'source': 'synthetic analytic fixture'}


def calibrated():
    record = calibration()
    record['status'] = 'calibrated'
    record['conformance_sha256'] = {name: digest(['synthetic-test', name]) for name in ('C1', 'C2', 'C3')}
    return record


def eligible_prediction():
    return generate_prediction(calibrated(), profiles(), seed=42, sealed_eligible=True, transition_samples=32,
                               bindings={k + '_sha256': digest(['synthetic', k]) for k in ('plan', 'census', 'admission')},
                               gate_hashes={k + '_sha256': digest(['synthetic', k])
                                            for k in ('amendment_004', 'grid_finalization')})


def episode(cal=None, profile=None, row='E2-extended-a', interval=1000, seed=7, delay=10):
    return simulate_episode(cal or calibration(), profile or profiles()[1], seed=seed,
                            row=row, network_delay_ms=delay, action_interval_ms=interval)


class CrosshostSimulatorTests(unittest.TestCase):
    def test_fixture_is_canonical_and_every_lag_has_source(self):
        path = FIXTURES / 'crosshost-sim-provisional-calibration.json'
        self.assertEqual(path.read_bytes(), canonical_bytes(calibration()) + b'\n')
        self.assertEqual(set(calibration()['lags']), set(LAGS))

    def test_same_seed_calibration_byte_identical(self):
        first = simulate_grid(calibration(), profiles(), seed=19)
        second = simulate_grid(deepcopy(calibration()), reversed(profiles()), seed=19)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(canonical_bytes(generate_prediction(calibration(), profiles(), seed=19, transition_samples=16)),
                         canonical_bytes(generate_prediction(calibration(), profiles(), seed=19, transition_samples=16)))

    def test_all_seven_rows_every_cell(self):
        result = simulate_grid(calibration(), profiles(), seed=2)
        self.assertEqual(len(result['episodes']), 336)
        self.assertEqual(len(result['frontier']), 21)
        cells = {}
        for e in result['episodes']:
            cells.setdefault((e['family'], e['network_delay_ms'], e['action_interval_ms']), []).append(e['row'])
            self.assertIn(e['timing_outcome'], OUTCOMES)
            self.assertEqual(e['runtime_decision'] is None, e['row'] in ('E0', 'E1'))
        self.assertEqual(len(cells), 48)
        self.assertTrue(all(tuple(rows) == ROWS for rows in cells.values()))

    def test_native_minimum_lag_cannot_prevent_a0_all_seeds(self):
        cal = calibration()
        fixed(cal, 'native_egress_processing', 1001)
        fixed(cal, 'native_detach_processing', 1001)
        for profile in profiles()[1:]:
            for row in ('E2-native-a', 'E2-native-b', 'E2-native-min-a'):
                for seed in range(100):
                    e = episode(cal, profile, row, interval=1000, seed=seed)
                    self.assertFalse(e['a0_prevented'])
                    self.assertEqual(e['harmful_actions_executed'], 1)
                    self.assertEqual(e['damage_prevented']['numerator'], 0)
                    self.assertEqual([a['disposition'] for a in e['harmful_attempts']],
                                     ['executed', 'not_triggered', 'not_triggered', 'not_triggered'])

    def test_cut_above_total_maximum_lag_prevents(self):
        for seed in range(100):
            e = episode(interval=81, seed=seed)  # 5 detect + 2 sign + 10 wire + 3 validate + <=60 cut
            self.assertTrue(e['a0_prevented'])
            self.assertEqual(e['harmful_actions_executed'], 0)
            self.assertEqual(e['damage_prevented']['value'], 1)
            self.assertTrue(all(a['result'] == 'denied' for a in e['harmful_attempts']))

    def test_e0_bottom_right_and_same_script_denominator(self):
        result = simulate_grid(calibration(), profiles(), seed=3)
        for e in result['episodes']:
            self.assertEqual(e['damage_prevented']['denominator'], 1)
            if e['row'] == 'E0':
                self.assertEqual(e['damage_prevented']['value'], 0)
                self.assertEqual(e['useful_work']['value'], 1)
                self.assertIsNone(e['binding'])
                self.assertIsNone(e['time_to_detect_ms'])
        for point in result['frontier']:
            self.assertEqual(len(point['grid_spread']), 16)
            self.assertEqual(point['damage_prevented']['denominator'], 16)

    def test_e1_family_specific_and_no_cross_domain_delivery(self):
        for profile in profiles():
            e = episode(profile=profile, row='E1')
            self.assertEqual(e['a0_prevented'], profile['family'] == 'S-A')
            self.assertEqual(e['timeline_ms'], {})
            self.assertFalse(any(x['event'] == 'tcx_arrival_at_ms' for x in e['events']))

    def test_freeze_costs_a4_without_release(self):
        e = episode(profile=profiles()[2])
        self.assertEqual(e['binding']['abstract_action'], 'freeze_sandbox')
        self.assertEqual(e['useful_work'], {'numerator': 0, 'denominator': 4, 'value': 0})
        self.assertTrue(all(a['disposition'] == 'executed' for a in e['a4_work']))
        self.assertFalse(any('release' in x['event'] for x in e['events']))

    def test_freeze_interrupts_a4_after_harmful_success(self):
        cal = calibration()
        fixed(cal, 'harness_freeze', 200)
        e = episode(cal, profiles()[2], interval=25)
        self.assertEqual(e['harmful_actions_executed'], 1)
        self.assertEqual(e['useful_work']['numerator'], 3)
        self.assertEqual(e['a4_work'][-1]['result'], 'interrupted_by_freeze')

    def test_a4_resource_inventory_controls_coarse_and_target_costs(self):
        cut = episode()
        self.assertEqual(cut['useful_work']['numerator'], 3)
        cal = calibration()
        fixed(cal, 'native_detach_processing', 0)
        detached = episode(cal, profiles()[2], row='E2-native-a', interval=20000)
        self.assertEqual(detached['useful_work']['numerator'], 3)
        self.assertEqual(detached['binding']['grade'], 'meets more coarsely')
        profile = profiles()[2]
        for a in profile['a4']:
            a['providers'] = []
        self.assertEqual(episode(cal, profile, row='E2-native-a', interval=20000)['useful_work']['numerator'], 4)

    def test_success_ends_retries_but_still_runs_a4(self):
        e = episode(interval=1)
        self.assertEqual(e['harmful_actions_executed'], 1)
        self.assertEqual(e['useful_work']['numerator'], 4)
        self.assertTrue(all(a['disposition'] == 'not_triggered' for a in e['harmful_attempts'][1:]))
        self.assertTrue(all(a['disposition'] == 'executed' for a in e['a4_work']))

    def test_denial_can_adapt_to_unblocked_target_then_success_stops(self):
        profile = profiles()[1]
        profile['harmful'][1]['targets'] = ['alternate.invalid:443']
        e = episode(profile=profile)
        self.assertEqual(e['harmful_attempts'][0]['result'], 'denied')
        self.assertEqual(e['harmful_attempts'][1]['result'], 'succeeded')
        self.assertEqual(e['harmful_attempts'][2]['disposition'], 'not_triggered')
        self.assertEqual(e['damage_prevented']['numerator'], 0)

    def test_nonrepresentable_actions_are_not_prevented_harm(self):
        profile = profiles()[1]
        profile['harmful'][0]['representable'] = False
        e = episode(profile=profile)
        self.assertEqual(e['damage_prevented'], {'numerator': 0, 'denominator': 0, 'value': 'undefined'})
        self.assertTrue(all(a['disposition'] == 'not_triggered' for a in e['harmful_attempts'][1:]))
        self.assertEqual(e['useful_work']['denominator'], 4)
        all_profiles = profiles()
        for p in all_profiles:
            p['harmful'][0]['representable'] = False
            p['a4'] = []
        result = simulate_grid(calibration(), all_profiles, seed=3)
        self.assertTrue(all(p['damage_prevented']['value'] == 'undefined' for p in result['frontier']))
        self.assertTrue(all(p['useful_work']['value'] == 'undefined' for p in result['frontier']))
        canonical_bytes(result)  # no NaN

    def test_a_and_b_never_pooled_and_b_waits_fixed_d(self):
        result = simulate_grid(calibration(), profiles(), seed=8)
        for family in ('S-A', 'S-B', 'S-C'):
            points = [p for p in result['frontier'] if p['family'] == family]
            self.assertEqual([p['row'] for p in points], sorted(ROWS))
        a, b = episode(interval=500), episode(row='E2-extended-b', interval=500)
        self.assertEqual(b['timeline_ms']['submitted_at_ms'] - a['timeline_ms']['submitted_at_ms'], 3000)
        self.assertTrue(a['a0_prevented'])
        self.assertFalse(b['a0_prevented'])
        self.assertEqual(b['submission_condition']['tag'], 'harness')

    def test_selection_tags_and_poll_configuration(self):
        for row in ROWS[2:]:
            self.assertEqual(binding_for('S-A', row)['tag'], 'native')
            self.assertEqual(binding_for('S-B', row)['abstract_action'], 'deny_egress')
            for family in ('S-B', 'S-C'):
                e = episode(profile=profiles()[1 if family == 'S-B' else 2], row=row)
                if e['binding']['tag'] == 'native':
                    self.assertEqual(e['timeline_ms']['poll_interval_ms'], 1000 if row == 'E2-native-min-a' else 10000)
                    persist = e['timeline_ms']['persisted_at_ms']
                    processing = 10
                    next_poll = e['timeline_ms']['effect_at_ms'] - processing
                    self.assertGreaterEqual(next_poll, persist)
                    self.assertLess(next_poll - persist, e['timeline_ms']['poll_interval_ms'] + 1e-9)

    def test_sa_preserves_no_change_not_fresh_acceptance(self):
        e = episode(profile=profiles()[0])
        self.assertEqual(e['runtime_decision'], 'rejected')
        self.assertEqual(e['runtime_decision_reason'], 'absent_entry_no_change')
        self.assertIsNone(e['timeline_ms']['effect_at_ms'])

    def test_timeout_late_installation_not_promoted_to_acceptance(self):
        cal = calibration()
        cal['decision_deadline_after_ready_ms'] = 3000
        fixed(cal, 'native_egress_processing', 4000)
        e = episode(cal, row='E2-native-a', interval=20000)
        self.assertEqual(e['runtime_decision'], 'timed_out')
        self.assertTrue(e['a0_prevented'])
        self.assertLess(e['timeline_ms']['deadline_at_ms'], e['timeline_ms']['effect_at_ms'])

    def test_rejection_and_missing_observation_are_distinct(self):
        profile = profiles()[1]
        profile['request_rejected'] = True
        e = episode(profile=profile)
        self.assertEqual(e['runtime_decision'], 'rejected')
        self.assertIsNone(e['timeline_ms']['effect_at_ms'])
        self.assertEqual(e['harmful_actions_executed'], 1)
        profile['request_rejected'] = False
        profile['observation_missing'] = True
        e = episode(profile=profile)
        self.assertEqual(e['runtime_decision'], 'timed_out')
        self.assertTrue(e['a0_prevented'])
        self.assertIsNone(e['timeline_ms']['effect_observed_at_ms'])

    def test_absent_and_invalid_warning_partition(self):
        for warning in ('no_warning', 'protocol_rejected'):
            profile = profiles()[1]
            profile['warning'] = warning
            e = episode(profile=profile)
            self.assertEqual(e['timing_outcome'], warning)
            self.assertEqual(e['runtime_decision'], 'rejected')
            self.assertEqual(e['harmful_actions_executed'], 1)
            self.assertEqual(e['timeline_ms'], {})

    def test_invalid_calibration_and_script_rejected(self):
        for field, value in [('D_ms', 1), ('poll_ms', {'default': 10000, 'minimum': 0}),
                             ('decision_deadline_after_ready_ms', float('nan'))]:
            cal = calibration(); cal[field] = value
            with self.subTest(field=field), self.assertRaises(TCOPCommandError):
                validate_calibration(cal)
        cal = calibration(); del cal['lags']['harness_cut']
        with self.assertRaises(TCOPCommandError):
            validate_calibration(cal)
        for value in (False, None):
            p = profiles()[1]; p['independent_of_harmful_side_effects'] = value
            with self.assertRaises(TCOPCommandError):
                validate_profile(p)

    def test_empirical_distribution_supported(self):
        cal = calibration()
        cal['lags']['harness_cut'] = {'kind': 'empirical', 'samples_ms': [10, 20, 30], 'source': 'synthetic samples'}
        self.assertIn(episode(cal)['timeline_ms']['binding_lag_ms'], [10, 20, 30])

    def test_grid_placement_deterministic_ordered_and_monotone_prevention(self):
        cal = calibrated()
        first = place_grid(cal, profiles(), seed=5, samples=64)
        self.assertEqual(canonical_bytes(first), canonical_bytes(place_grid(cal, profiles(), seed=5, samples=64)))
        intervals = first['grid']['action_intervals_ms']
        self.assertEqual(intervals, sorted(set(intervals)))
        ts = first['transitions']
        harness = [t['transition_ms'] for t in ts if t['row'] == 'E2-extended-a']
        min_native = min(t['transition_ms'] for t in ts if t['row'] == 'E2-native-min-a')
        self.assertLess(intervals[0], min(harness))
        self.assertLess(max(harness), intervals[1])
        self.assertLess(intervals[1], min_native)
        self.assertLess(min_native, intervals[2])
        self.assertLess(intervals[2], 10000)
        self.assertGreater(intervals[3], 10000)
        for profile in profiles()[1:]:
            for row in ROWS[2:]:
                values = [sum(episode(cal, profile, row, interval=x, seed=s)['a0_prevented'] for s in range(20))
                          for x in intervals]
                self.assertEqual(values, sorted(values))

    def test_nonseparable_grid_refused(self):
        cal = calibration(); fixed(cal, 'harness_freeze', 20000)
        with self.assertRaises(TCOPCommandError):
            place_grid(cal, profiles(), seed=3, samples=8)

    def test_provisional_prediction_never_eligible(self):
        draft = generate_prediction(calibration(), profiles(), seed=1, transition_samples=8)
        self.assertFalse(draft['sealed_eligible'])
        with self.assertRaises(TCOPCommandError):
            generate_prediction(calibration(), profiles(), seed=1, sealed_eligible=True)
        with self.assertRaises(TCOPCommandError):
            validate_expected_pattern(draft)
        with self.assertRaises(TCOPCommandError):
            validate_prediction(draft)

    def test_post_hoc_cannot_enter_prediction_path_or_phase1_validator(self):
        sweep = post_hoc_sweep(calibration(), profiles(), seed=3,
                              action_intervals_ms=range(1, 102, 10), network_delays_ms=[10])
        self.assertTrue(sweep['post_hoc'])
        self.assertEqual(len(sweep['episodes']), 231)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'prediction.json'
            with self.assertRaises(TCOPCommandError):
                write_prediction(sweep, path)
            self.assertFalse(path.exists())
        with self.assertRaises(TCOPCommandError):
            validate_expected_pattern(sweep)
        record = eligible_prediction()
        record['predictions'] = sweep
        with self.assertRaises(TCOPCommandError):
            validate_prediction(record)

    def test_eligible_prediction_and_canonical_write_no_sealing(self):
        record = eligible_prediction()
        validate_expected_pattern(record)
        validate_prediction(record)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'prediction.json'
            write_prediction(record, path)
            self.assertEqual(path.read_bytes(), canonical_bytes(record) + b'\n')
            self.assertEqual([p.name for p in Path(directory).iterdir()], ['prediction.json'])
            with self.assertRaises(TCOPCommandError):
                write_prediction(record, path)

    def test_live_comparison_all_findings_no_fitting(self):
        record = eligible_prediction()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'prediction'
            seal_expected_pattern(record, root)  # ONLY this synthetic test seals, not simulator code
            rows = deepcopy(record['predictions']['episodes'])
            self.assertEqual(compare_live(root, rows)['finding_count'], 0)
            rows[0]['harmful_actions_executed'] = 99
            rows[0]['useful_work']['numerator'] = 0
            del rows[0]['time_to_block_ms']
            rows.append(deepcopy(rows[1]))
            rows.pop(2)
            report = compare_live(root, rows)
            self.assertEqual(report['finding_count'], 5)
            self.assertFalse(report['fitting_performed'])
            self.assertEqual({f.get('field') for f in report['findings'] if 'field' in f},
                             {'harmful_actions_executed', 'useful_work.numerator', 'time_to_block_ms'})
            self.assertIn('missing_episode', {f['kind'] for f in report['findings']})
            self.assertIn('duplicate_episode', {f['kind'] for f in report['findings']})
            self.assertEqual(record['simulator']['seed'], 42)

    def test_live_comparison_requires_valid_unchanged_seal(self):
        record = eligible_prediction()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'prediction'
            with self.assertRaises(TCOPCommandError):
                compare_live(root, [])
            seal_expected_pattern(record, root)
            (root / 'record.json').write_text('{}')
            with self.assertRaises(TCOPCommandError):
                compare_live(root, [])


if __name__ == '__main__':
    unittest.main()

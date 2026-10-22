"""Per-class READ expectations for the READ-class schedule endpoint (CASE4_READ_SCHEDULE=rotate4, CASE4_DB).

A build declares its READ images per request class (builds[b].read_images, overridden per database by
builds[b].read_images_by_db); null or absent means the class is not supported in hardware and the harness refuses to
run it. Requests are classified from their bytes. Every expectation below is derived from that declaration; with
no read_images the harness behaves exactly as before (the existing suites stay green unedited).

Bytes are real: fixtures/read_class_vectors.json holds requests and native responses from the loopback captures
and the reference encoder's output (general_read_padding.pad_read under the frozen policy)."""
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]
import campaign as cp  # noqa: E402
import capture_boundary  # noqa: E402
import checks  # noqa: E402
import clrt_check  # noqa: E402
import read_class_fixture as fx  # noqa: E402
import read_classes as rc  # noqa: E402
import standards  # noqa: E402
import vision_run as vr  # noqa: E402

CONFIG = HERE.parent / 'campaign.json'


class Classification(unittest.TestCase):
    def test_every_real_request_is_classified_from_its_bytes(self):
        rows = fx.vectors()
        self.assertEqual(len(rows), 24)
        for row in rows:
            self.assertEqual(rc.classify_request_frames(bytes.fromhex(row['request'])), row['class'], row['slot'])

    def test_the_legacy_range_request_is_range(self):
        import pcaptk as tk
        self.assertEqual(rc.classify_request_frames(tk.read_request(app_seq=3)), 'range')

    def test_non_read_and_unknown_shapes_are_not_classified(self):
        import pcaptk as tk
        app = lambda objects, func=1: bytes([0xc0, func]) + objects
        cases = {
            'SELECT': app(bytes.fromhex('0c012801000100'), 3),
            'class 1 only': app(bytes.fromhex('3c0206')),
            'integrity without class 0': app(bytes.fromhex('3c02063c03063c0406')),
            'integrity twice class 1': app(bytes.fromhex('3c02063c02063c03063c0406')),
            'range and analog together': app(bytes.fromhex('0a020000161e000100001400')),
            'truncated header': app(bytes.fromhex('0a02')),
            'no objects': app(b''),
            'class 0 with a range qualifier': app(bytes.fromhex('3c01000005')),
        }
        for name, application in cases.items():
            self.assertIsNone(rc.classify_request(application), name)
        self.assertIsNone(rc.classify_request_frames(tk.read_request(func=3)))
        bad_crc = bytearray(tk.read_request())
        bad_crc[-1] ^= 1
        self.assertIsNone(rc.classify_request_frames(bytes(bad_crc)))


class Expectations(unittest.TestCase):
    def test_base_database_rotate4(self):
        cfg, arm, trial = fx.config('base', reads=65, sbo=True)
        exp = rc.expectations(cfg, arm, trial, padded=True)
        self.assertEqual((exp['schedule'], exp['db']), ('rotate4', 'base'))
        self.assertEqual({c: exp['classes'][c]['count'] for c in fx.ORDER},
                         {'range': 17, 'analog': 16, 'class0': 16, 'integrity': 16})
        self.assertEqual({c: (exp['classes'][c]['native'], exp['classes'][c]['image']) for c in fx.ORDER},
                         {'range': (49, 141), 'analog': (141, 141), 'class0': (247, 247), 'integrity': (247, 247)})

    def test_large_database_overrides_the_segmented_classes(self):
        cfg, arm, trial = fx.config('large', reads=65, sbo=True)
        exp = rc.expectations(cfg, arm, trial, padded=True)
        self.assertEqual({c: (exp['classes'][c]['native'], exp['classes'][c]['image']) for c in fx.ORDER},
                         {'range': (49, 141), 'analog': (141, 141), 'class0': (377, 401), 'integrity': (377, 401)})
        self.assertEqual(exp['classes']['class0']['native_segments'], [292, 85])

    def test_unpadded_arm_expects_every_class_native(self):
        cfg, arm, trial = fx.config('large', padding=0)
        exp = rc.expectations(cfg, arm, trial, padded=False)
        self.assertEqual({c: exp['classes'][c]['image'] for c in fx.ORDER},
                         {'range': 49, 'analog': 141, 'class0': 377, 'integrity': 377})

    def test_counts_follow_the_slot_order(self):
        self.assertEqual(rc.class_counts(rc.SCHEDULES['rotate4'], 6),
                         {'range': 2, 'analog': 2, 'class0': 1, 'integrity': 1})
        self.assertEqual(rc.class_counts(('range',), 20), {'range': 20})

    def test_an_unsupported_class_in_the_schedule_is_refused(self):
        for images_by_db in ({'large': {'class0': None, 'integrity': 401}}, {'large': {'integrity': 401}}):
            images = dict(fx.IMAGES)
            del images['class0']
            cfg, arm, trial = fx.config('large', images=images, images_by_db=images_by_db)
            with self.subTest(images_by_db), self.assertRaisesRegex(rc.ReadClassError, 'class0.*not supported'):
                rc.expectations(cfg, arm, trial, padded=True)

    def test_a_declared_image_below_the_native_is_refused(self):
        cfg, arm, trial = fx.config('large', images_by_db={'large': {'class0': 247, 'integrity': 401}})
        with self.assertRaisesRegex(rc.ReadClassError, 'class0'):
            rc.expectations(cfg, arm, trial, padded=True)

    def test_schedule_needs_a_database_and_known_names(self):
        cfg, arm, trial = fx.config('base')
        del cfg['traffic']['db']
        with self.assertRaisesRegex(rc.ReadClassError, 'db'):
            rc.expectations(cfg, arm, trial, padded=True)
        for key, value in (('read_schedule', 'rotate5'), ('db', 'huge')):
            cfg, arm, trial = fx.config('base')
            cfg['traffic'][key] = value
            with self.subTest(key), self.assertRaises(rc.ReadClassError):
                rc.expectations(cfg, arm, trial, padded=True)

    def test_trial_overrides_the_traffic_section(self):
        cfg, arm, trial = fx.config('base')
        trial['db'] = 'large'
        self.assertEqual(rc.expectations(cfg, arm, trial, padded=True)['classes']['class0']['image'], 401)

    def test_without_read_images_there_is_no_per_class_expectation(self):
        cfg, arm, trial = fx.config('base', schedule_name=None)
        for key in ('read_images', 'read_images_by_db'):
            del cfg['builds']['b'][key]
        self.assertIsNone(rc.expectations(cfg, arm, trial, padded=True))

    def test_range_only_build_without_schedule(self):
        cfg, arm, trial = fx.config(None, schedule_name=None, reads=20)
        del cfg['traffic']['db']
        exp = rc.expectations(cfg, arm, trial, padded=True)
        self.assertEqual(exp['classes'], {'range': {'native': 49, 'image': 141, 'count': 20, 'native_segments': [49]}})

    def test_schedule_without_any_declaration_is_refused(self):
        cfg, arm, trial = fx.config('base')
        for key in ('read_images', 'read_images_by_db'):
            del cfg['builds']['b'][key]
        with self.assertRaisesRegex(rc.ReadClassError, 'read_images'):
            rc.expectations(cfg, arm, trial, padded=True)

    def test_only_read_images_by_db_is_a_declaration(self):
        cfg, arm, trial = fx.config('large')
        del cfg['builds']['b']['read_images']
        cfg['builds']['b']['read_images_by_db'] = {'large': dict(fx.IMAGES, class0=401, integrity=401)}
        self.assertTrue(rc.declared(cfg['builds']['b']))
        exp = rc.expectations(cfg, arm, trial, padded=True)
        self.assertEqual({c: exp['classes'][c]['image'] for c in fx.ORDER},
                         {'range': 141, 'analog': 141, 'class0': 401, 'integrity': 401})

    def test_an_image_below_the_prefix_minimum_growth_is_refused(self):
        for image in (50, 61, 72):
            with self.subTest(image), self.assertRaisesRegex(rc.ReadClassError, 'prefix'):
                rc.build_images({'read_images': {'range': image}}, None)
        self.assertEqual(rc.build_images({'read_images': {'range': 73}}, None), {'range': 73})   # n = 4 points
        self.assertEqual(rc.build_images({'read_images': {'range': 49}}, None), {'range': 49})   # at target
        with self.assertRaisesRegex(rc.ReadClassError, 'prefix'):
            rc.build_images({'read_images_by_db': {'large': {'class0': 390}}}, 'large')
        cfg, arm, trial = fx.config('base', images=dict(fx.IMAGES, range=61))
        with self.assertRaisesRegex(rc.ReadClassError, 'prefix'):
            rc.expectations(cfg, arm, trial, padded=True)

    def test_range_image_len(self):
        self.assertEqual(rc.range_image_len({'image_len': 61, 'read_images': {'range': 141}}, 61), 141)
        self.assertEqual(rc.range_image_len({'image_len': 61, 'read_image_len': 141}, 61), 141)
        self.assertEqual(rc.range_image_len({'image_len': 61}, 61), 61)
        self.assertIsNone(rc.range_image_len({'image_len': 61}))
        with self.assertRaises(rc.ReadClassError):
            rc.range_image_len({'image_len': 61, 'read_images': {'range': None}}, 61)
        with self.assertRaises(rc.ReadClassError):
            rc.range_image_len({'read_images': {'range': 141}, 'read_image_len': 150}, 61)


class StandardsPerClass(unittest.TestCase):
    def context(self, db='base', **kw):
        cfg, arm, trial = fx.config(db, **kw)
        return {'config': cfg, 'arm': arm, 'trial': trial, 'packet_boundary_required': True}

    def test_expected_identity_carries_the_classes(self):
        exp = standards.expected_identity(self.context('large', reads=65, sbo=True))['expected']
        self.assertEqual(exp['lengths'], {'READ': [141, 401], 'SELECT': [61], 'OPERATE': [61]})
        self.assertEqual(exp['read_classes']['class0'], {'native': 377, 'image': 401, 'count': 16,
                                                         'native_segments': [292, 85]})
        self.assertEqual(exp['counts'], {'READ': 65, 'SELECT': 64, 'OPERATE': 64})

    def test_context_with_several_read_images_is_well_formed(self):
        ctx = self.context('large')
        failures = standards._validate_context(ctx, {}, standards.expected_identity(ctx))
        self.assertNotIn('context.expected.lengths malformed', failures)
        for key in ('read_images', 'read_images_by_db'):         # a legacy build may not carry several lengths
            ctx['config']['builds']['b'].pop(key)
        ctx['config']['traffic'].pop('read_schedule')
        identity = standards.expected_identity(ctx)
        identity['expected']['lengths']['READ'] = [141, 401]
        self.assertIn('context.expected.lengths malformed', standards._validate_context(ctx, {}, identity))

    def test_unsupported_class_fails_closed(self):
        ctx = self.context('large', images_by_db={'large': {'class0': None, 'integrity': 401}})
        result = standards.validate_standards({'schema_version': standards.SCHEMA_VERSION_V3}, ctx, {})
        self.assertFalse(result['ok'])
        self.assertTrue(any('not supported' in f for f in result['failures']), result['failures'])

    def test_boundary_requirement_binds_every_kind_and_class(self):
        ctx = self.context('large', reads=65, sbo=True)
        expected = standards.expected_identity(ctx)
        required, attempts = standards.boundary_segment_requirement(ctx, expected)
        self.assertEqual(required, {'READ:range': 141, 'READ:analog': 141, 'READ:class0': 401,
                                    'READ:integrity': 401, 'SELECT': 61, 'OPERATE': 61})
        self.assertEqual(attempts, 65 + 128)

    def test_unpadded_arm_needs_no_boundary(self):
        ctx = self.context('large', padding=0)
        self.assertEqual(standards.boundary_segment_requirement(ctx, standards.expected_identity(ctx)), (None, 0))

    def test_legacy_identity_is_unchanged(self):
        cfg = {'builds': {'b': {'profile': 'candidate61', 'image_len': 61, 'read_image_len': 141}},
               'traffic': {'run_sbo': True, 'sbo_cycles': 64}}
        arm = {'name': 'size_only', 'build': 'b', 'padding': 1}
        ctx = {'config': cfg, 'arm': arm, 'trial': {'reads': 65}}
        exp = standards.expected_identity(ctx)['expected']
        self.assertEqual(exp, {'counts': {'READ': 65, 'SELECT': 64, 'OPERATE': 64},
                               'lengths': {'READ': [141], 'SELECT': [61], 'OPERATE': [61]}})

    def test_per_class_verdicts_are_required(self):
        ctx = self.context('base')
        exp = standards.expected_identity(ctx)['expected']
        good = [{'kind': 'READ', 'read_class': c, 'ok': True, 'wire_len': exp['read_classes'][c]['image']}
                for _k, c, _v in fx.schedule('base')]
        self.assertEqual(standards.read_class_failures({'verdicts': good}, exp['read_classes']), [])
        wrong = copy.deepcopy(good)
        wrong[1]['wire_len'] = 247                       # analog delivered at a padded length
        self.assertEqual(standards.read_class_failures({'verdicts': wrong}, exp['read_classes']),
                         ['READ analog verdict None wire length 247, expected 141'])
        native = copy.deepcopy(good)
        native[0]['wire_len'] = 49                       # range delivered native where padding is declared
        self.assertEqual(standards.read_class_failures({'verdicts': native}, exp['read_classes']),
                         ['READ range verdict None wire length 49, expected 141'])
        missing = good[:-1]
        self.assertEqual(standards.read_class_failures({'verdicts': missing}, exp['read_classes']),
                         ['READ integrity verdicts 1, expected 2'])
        unclassified = copy.deepcopy(good)
        unclassified[2]['read_class'] = None
        self.assertEqual(standards.read_class_failures({'verdicts': unclassified}, exp['read_classes']),
                         ['READ verdict None has undeclared class None', 'READ class0 verdicts 1, expected 2'])


class BoundaryPerClass(unittest.TestCase):
    """Each physical segment is bound to the class of its exchange, not to a set of allowed lengths."""
    def segments(self, sched, transform=None):
        transform = transform or (lambda k, c, v: fx.expected_segments(v))
        segs, seq = [], 5001
        for k, cls, v in sched:
            for payload in transform(k, cls, v):
                segs.append({'index': len(segs), 'src': fx.O, 'dst': fx.M, 'sport': fx.OP, 'dport': fx.MP,
                             'seq': seq, 'len': len(payload), 'payload': payload})
                seq += len(payload)
        return segs

    def verdicts(self, sched):
        out = []
        for i, (k, cls, v) in enumerate(sched):
            image = bytes.fromhex(v['expected'])
            out.append({'index': i, 'kind': 'READ', 'read_class': cls, 'wire_len': len(image),
                        'app_seq': bytes.fromhex(v['native'])[11] & 0x0f, 'request_serial': i,
                        'wire_image_sha256': capture_boundary._sha(image),
                        'tuple': {'src': {'ip': fx.O, 'port': fx.OP}, 'dst': {'ip': fx.M, 'port': fx.MP}}})
        return out

    def required(self, db):
        exp = fx.read_classes_expectation(db)
        return {'READ:' + c: exp[c]['image'] for c in fx.ORDER}

    def bind(self, db, transform=None, verdicts=None):
        sched = fx.schedule(db)
        expected, failures = capture_boundary._checker_expectations(
            {'verdicts': verdicts if verdicts is not None else self.verdicts(sched)}, self.required(db))
        return failures + capture_boundary._bind_segments_by_class(self.segments(sched, transform), expected,
                                                                    len(sched), fx.OP, fx.MP)

    def test_exact_policy_segments_bind(self):
        for db in ('base', 'large'):
            self.assertEqual(self.bind(db), [], db)

    def test_two_segment_padded_class_binds_as_one_exchange(self):
        sched = fx.schedule('large')
        self.assertEqual([len(s) for s in fx.expected_segments(sched[2][2])], [316, 85])
        self.assertEqual(self.bind('large'), [])

    def test_a_length_from_the_set_but_not_the_class_fails(self):
        # base: a 141-octet analog image placed where the integrity exchange (247) belongs; 141 is a required
        # length of this trial (range, analog), so a set-only binding would have passed it
        # length; the substitute carries the integrity exchange's own application sequence (valid CRCs), so only
        # the per-class length binding can reject it
        sys.path.insert(0, str(HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/'
                                                 'read_reencode_01'))
        import dnp3_std as std
        sched = fx.schedule('base')
        analog = fx.expected_segments(sched[1][2])[0]
        integrity_seq = bytes.fromhex(sched[3][2]['native'])[11] & 0x0f
        header, user = std.deframe(analog)
        user = bytearray(user)
        user[1] = (user[1] & 0xf0) | integrity_seq
        substitute = std.frame(header, bytes(user))
        self.assertEqual(len(substitute), 141)
        failures = self.bind('base', lambda k, c, v: [substitute] if k == 3 else fx.expected_segments(v))
        self.assertIn('physical incoming exchange 3 (READ:integrity) incomplete: 141 of 247 octets before segment 4',
                      failures)

    def test_checker_verdict_at_the_wrong_class_length_fails(self):
        sched = fx.schedule('large')
        verdicts = self.verdicts(sched)
        verdicts[2]['wire_len'] = 377
        _, failures = capture_boundary._checker_expectations({'verdicts': verdicts}, self.required('large'))
        self.assertTrue(any('class0' in f for f in failures), failures)

    def test_a_verdict_of_an_undeclared_class_fails(self):
        verdicts = self.verdicts(fx.schedule('base'))
        verdicts[0]['read_class'] = None
        _, failures = capture_boundary._checker_expectations({'verdicts': verdicts}, self.required('base'))
        self.assertTrue(failures)

    def test_native_segment_where_padding_is_declared_fails(self):
        failures = self.bind('large', lambda k, c, v: ([bytes.fromhex(s) for s in v['native_segments']] if k == 2
                                                      else fx.expected_segments(v)))
        self.assertIn('physical incoming exchange 2 (READ:class0) incomplete: 377 of 401 octets before segment 4',
                      failures)

    def test_legacy_set_binding_is_unchanged(self):
        verdicts = [{'index': 0, 'kind': 'READ', 'wire_len': 141, 'app_seq': 0},
                    {'index': 1, 'kind': 'SELECT', 'wire_len': 61, 'app_seq': 1}]
        got, failures = capture_boundary._checker_expectations({'verdicts': verdicts}, (61, 141))
        self.assertEqual((len(got), failures), (2, []))


class ClrtPairingPerClass(unittest.TestCase):
    def policy(self, db, padded=True, **change):
        exp = fx.read_classes_expectation(db, padded)
        for cls, image in change.items():
            exp[cls]['image'] = image
        return {'classes': exp}

    def test_one_frame_prefix_pairs_for_every_padded_one_frame_native(self):
        for row in fx.vectors():
            native = bytes.fromhex(row['native_segments'][0])
            got = fx.expected_segments(row)[0]
            self.assertTrue(clrt_check._response_content_matches(native, got, self.policy(row['db'])),
                            (row['db'], row['class']))

    def test_the_segmented_first_packet_pairs_only_when_the_class_is_declared(self):
        row = fx.by_class('large')['class0'][0]
        native, got = bytes.fromhex(row['native_segments'][0]), fx.expected_segments(row)[0]
        self.assertTrue(clrt_check._response_content_matches(native, got, self.policy('large')))
        self.assertFalse(clrt_check._response_content_matches(native, got, self.policy('large', padded=False)))
        self.assertFalse(clrt_check._response_content_matches(native, got, None))      # legacy: 141 only

    def test_a_padded_image_for_an_at_target_class_does_not_pair(self):
        sys.path.insert(0, str(HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/'
                                                 'read_reencode_01'))
        import profile_check
        row = fx.by_class('base')['analog'][0]
        native = bytes.fromhex(row['native'])
        padded247 = profile_check.policy_image(fx.link_frames(native), 247)
        self.assertEqual(len(padded247), 247)
        self.assertFalse(clrt_check._response_content_matches(native, padded247, self.policy('base')))
        self.assertTrue(clrt_check._response_content_matches(native, native, self.policy('base')))

    def test_a_changed_octet_or_wrong_class_length_does_not_pair(self):
        row = fx.by_class('base')['range'][0]
        native, got = bytes.fromhex(row['native']), fx.expected_segments(row)[0]
        frames = fx.link_frames(got)
        # rebuild the prefix frame with a nonzero synthetic flag and valid CRCs
        sys.path.insert(0, str(HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/'
                                                 'read_reencode_01'))
        import dnp3_std as std
        header, user = std.deframe(frames[0])
        user = bytearray(user)
        user[-1] ^= 1
        changed = std.frame(header, bytes(user)) + frames[1]
        self.assertFalse(clrt_check._response_content_matches(native, changed, self.policy('base')))
        self.assertFalse(clrt_check._response_content_matches(native, got, self.policy('base', range=247)))

    def test_analyze_labels_each_exchange_with_its_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx.build_run(tmp, 'large')
            report = clrt_check.analyze(os.path.join(tmp, 'out.pcap'), os.path.join(tmp, 'in.pcap'),
                                        read_policy=self.policy('large'))
            legacy = clrt_check.analyze(os.path.join(tmp, 'out.pcap'), os.path.join(tmp, 'in.pcap'))
        rows = [r for r in report['exchanges'] if r['kind'] == 'READ']
        self.assertEqual([r['read_class'] for r in rows], [c for _k, c, _v in fx.schedule('large')])
        self.assertTrue(all(r['publication']['response_availability_ns'] is not None for r in rows),
                        [r['publication']['null_reasons'] for r in rows])
        by_class = report['summary']['READ']['by_class']
        self.assertEqual(by_class['class0']['resp_len'], [316])
        self.assertEqual(by_class['analog']['resp_len'], [141])
        self.assertNotIn('read_class', legacy['exchanges'][0])
        self.assertNotIn('by_class', legacy['summary']['READ'])
        # without the declaration the class0 padded first packets do not pair
        self.assertTrue(any(r['publication']['response_availability_ns'] is None
                            for r in legacy['exchanges'] if r['kind'] == 'READ'))

    def test_cli_policy_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx.build_run(tmp, 'base')
            out = os.path.join(tmp, 'timing.json')
            import subprocess
            r = subprocess.run([sys.executable, str(HERE.parent / 'clrt_check.py'), os.path.join(tmp, 'out.pcap'),
                                os.path.join(tmp, 'in.pcap'), '--json', out, '--read-policy',
                                json.dumps(self.policy('base'))], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('by_class', json.load(open(out))['summary']['READ'])


class ApplicationChecksPerClass(unittest.TestCase):
    def records(self):
        """The endpoints' final records of the large-database loopback run (copied into the fixture from
        loopback_evidence_20261021/b_rotate4_large/{master,outstation}.log)."""
        records = json.loads(fx.VECTORS.read_text())['endpoint_records']
        return copy.deepcopy(records['master_large']), copy.deepcopy(records['outstation_large'])

    def expectation(self, db='large'):
        cfg, arm, trial = fx.config(db, reads=65, sbo=True)
        return rc.expectations(cfg, arm, trial, padded=False)

    def test_real_loopback_master_record_passes_per_class(self):
        master, _ = self.records()
        self.assertEqual(checks.read_class_record_checks(master, self.expectation(), 23), [])

    def test_wrong_database_or_order_or_size_fails(self):
        master, _ = self.records()
        self.assertTrue(checks.read_class_record_checks(master, self.expectation('base'), 23))
        swapped = copy.deepcopy(master)
        swapped['read_commands'][0]['class'], swapped['read_commands'][1]['class'] = 'analog', 'range'
        self.assertTrue(checks.read_class_record_checks(swapped, self.expectation(), 23))
        resized = copy.deepcopy(master)
        resized['read_commands'][2]['response_link_octets'] = 247
        self.assertTrue(checks.read_class_record_checks(resized, self.expectation(), 23))
        failed = copy.deepcopy(master)
        failed['read_commands'][5]['matches_fixture'] = False
        self.assertTrue(checks.read_class_record_checks(failed, self.expectation(), 23))
        counted = copy.deepcopy(master)
        counted['reads_per_class']['analog']['succeeded'] = 15
        self.assertTrue(checks.read_class_record_checks(counted, self.expectation(), 23))

    def test_timing_summary_per_class(self):
        exp = self.expectation()
        exp_pad = copy.deepcopy(exp)
        for cls, image in (('range', 141), ('class0', 401), ('integrity', 401)):
            exp_pad['classes'][cls]['image'] = image
        summary = {'READ': {'by_class': {c: {'logical_requests': e['count'], 'complete': e['count'],
                                             'resp_len': [checks.first_packet_len(e)]}
                                         for c, e in exp_pad['classes'].items()}}}
        self.assertEqual(summary['READ']['by_class']['class0']['resp_len'], [316])
        self.assertEqual(checks.read_class_timing_checks(summary, exp_pad), [])
        native = copy.deepcopy(summary)
        native['READ']['by_class']['range']['resp_len'] = [49]
        self.assertTrue(checks.read_class_timing_checks(native, exp_pad))
        self.assertTrue(checks.read_class_timing_checks({'READ': {}}, exp_pad))


class VisionRunControls(unittest.TestCase):
    def test_env_carries_the_schedule_and_database_like_sbo_cycles(self):
        env = vr.endpoint_env(25, True, 0, 64, read_schedule='rotate4', db='large')
        self.assertEqual(env[-3:], ['CASE4_SBO_CYCLES=64', 'CASE4_READ_SCHEDULE=rotate4', 'CASE4_DB=large'])

    def test_legacy_env_is_unchanged(self):
        self.assertEqual(vr.endpoint_env(25, True, 0, 0),
                         ['env', 'CASE4_PAD58B_SOCKET_GATE=1', 'LD_LIBRARY_PATH=' + vr.LIB, 'CASE4_READ_PAUSE_MS=25',
                          'CASE4_RUN_SBO=1', 'CASE4_CLOSE_GRACE_MS=0'])

    def test_bad_controls_fail_before_creating_the_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in (dict(read_schedule='rotate4'), dict(read_schedule='rotate5', db='base'),
                           dict(db='huge'), dict(endpoint_binary_name='../x'), dict(endpoint_binary_name='a/b'),
                           dict(endpoint_binary_name='..')):
                run_dir = Path(tmp) / 'run'
                with self.subTest(kwargs), self.assertRaises(ValueError):
                    vr.run_connection(str(run_dir), 'x', 59500, 65, 8, 0, 0, 0, sbo_cycles=64, **kwargs)
                self.assertFalse(run_dir.exists())

    def test_endpoint_binary_default_is_unchanged(self):
        self.assertEqual(vr.endpoint_binary(None), vr.BIN)
        self.assertEqual(vr.endpoint_binary('case4_socket_gate_read_schedule'),
                         vr.HOME + '/case4_socket_gate_read_schedule')


class CampaignPerClass(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = Path(td.name)

    def load(self, change):
        cfg = json.load(open(CONFIG))
        change(cfg)
        path = self.tmp / 'c.json'
        path.write_text(json.dumps(cfg))
        return cp.load_config(str(path))

    def schedule(self, db='large', images_by_db=None):
        def change(cfg):
            cfg['traffic'].update(sbo_cycles=64, read_schedule='rotate4', db=db)
            cfg['trials']['reads_per_trial'] = 65
            cfg.setdefault('loss', {})['presets'] = {}
            for build in cfg['builds'].values():
                build['read_images'] = dict(fx.IMAGES)
                build['read_images_by_db'] = copy.deepcopy(fx.IMAGES_BY_DB if images_by_db is None
                                                           else images_by_db)
        return change

    def test_controls_and_arguments(self):
        c = cp.Campaign.__new__(cp.Campaign)
        c.cfg = self.load(self.schedule())
        self.assertEqual(c.endpoint_controls()['read_schedule'], 'rotate4')
        self.assertEqual(c.endpoint_controls()['db'], 'large')
        self.assertIn('--read-schedule rotate4 --db large', c.endpoint_control_args())
        plain = cp.Campaign.__new__(cp.Campaign)
        plain.cfg = cp.load_config(str(CONFIG))
        self.assertNotIn('read_schedule', plain.endpoint_controls())
        self.assertEqual(plain.endpoint_control_args(),
                         ' --read-pause-ms 25 --run-sbo 1 --close-grace-ms 0')

    def test_master_must_report_the_schedule_and_database(self):
        c = cp.Campaign.__new__(cp.Campaign)
        c.cfg = self.load(self.schedule())
        master = {'read_pause_ms': 25, 'run_sbo': True, 'close_grace_ms': 0, 'sbo_cycles': 64,
                  'read_schedule': 'rotate4', 'db': 'large'}
        self.assertEqual(c.endpoint_control_checks(master), [])
        self.assertTrue(c.endpoint_control_checks(dict(master, db='base')))

    def test_unsupported_class_refuses_the_campaign(self):
        with self.assertRaisesRegex(ValueError, 'not supported'):
            self.load(self.schedule(images_by_db={'large': {'class0': None, 'integrity': 401}}))

    def test_loss_presets_and_scenarios_refuse_a_schedule(self):
        def with_loss(cfg):
            self.schedule()(cfg)
            del cfg['traffic']['sbo_cycles']
            cfg['loss']['presets'] = {'core': [{'class': 'request', 'n': 1}]}
        with self.assertRaisesRegex(ValueError, 'read_schedule'):
            self.load(with_loss)

    def test_single_frame_read_class_loss_is_allowed_with_a_schedule(self):
        def with_loss(cfg):
            self.schedule(db='base')(cfg)
            del cfg['traffic']['sbo_cycles']
            cfg['loss']['presets'] = {'core': [{'class': 'read_resp_247', 'n': 1},
                                               {'class': 'read_resp_analog', 'n': 2}]}
        cfg = self.load(with_loss)
        self.assertEqual(cfg['loss']['presets']['core'][0]['class'], 'read_resp_247')

    def test_segmented_read_class_loss_is_refused_with_a_schedule(self):
        # the 247-byte selector has no single-frame response on the large database (class0/integrity are 292 + 85)
        def with_loss(cfg):
            self.schedule(db='large')(cfg)
            del cfg['traffic']['sbo_cycles']
            cfg['loss']['presets'] = {'core': [{'class': 'read_resp_247', 'n': 1}]}
        with self.assertRaisesRegex(ValueError, 'NOT_EXERCISED|segmented'):
            self.load(with_loss)

    def test_a_per_class_or_non_read_loss_class_refuses_a_schedule(self):
        # read_resp_class0/read_resp_integrity are not distinct selectors; a non-READ class is also refused
        for bad in ('read_resp_class0', 'read_resp_integrity', 'request'):
            def with_loss(cfg, bad=bad):
                self.schedule(db='base')(cfg)
                del cfg['traffic']['sbo_cycles']
                cfg['loss']['presets'] = {'core': [{'class': 'read_resp_247', 'n': 1}, {'class': bad, 'n': 1}]}
            with self.subTest(bad), self.assertRaisesRegex(ValueError, 'read_schedule'):
                self.load(with_loss)

    def test_schedule_without_declaration_refuses_the_campaign(self):
        def undeclared(cfg):
            self.schedule()(cfg)
            for build in cfg['builds'].values():
                del build['read_images'], build['read_images_by_db']
        with self.assertRaisesRegex(ValueError, 'read_images'):
            self.load(undeclared)

    def test_schedule_with_only_read_images_by_db_loads(self):
        def by_db_only(cfg):
            self.schedule()(cfg)
            for build in cfg['builds'].values():
                del build['read_images']
                build['read_images_by_db'] = {'large': dict(fx.IMAGES, class0=401, integrity=401)}
        cfg = self.load(by_db_only)
        self.assertEqual(cfg['traffic']['read_schedule'], 'rotate4')

    def test_validation_uses_the_per_unit_read_count(self):
        # one_connection: one connection per arm carries reads_per_trial * trials_per_arm READs, so class0 is run
        # even though one trial's two READs (range, analog) would never reach it
        def one_connection(cfg):
            self.schedule(images_by_db={'large': {'class0': None, 'integrity': 401}})(cfg)
            del cfg['traffic']['sbo_cycles']
            cfg['trial_mode'] = 'one_connection'
            cfg['trials'].update(reads_per_trial=2, trials_per_arm=4)
        with self.assertRaisesRegex(ValueError, 'class0.*not supported'):
            self.load(one_connection)
        def per_trial(cfg):
            one_connection(cfg)
            cfg['trial_mode'] = 'per_trial_cold'
        self.assertEqual(self.load(per_trial)['trials']['reads_per_trial'], 2)

    def test_endpoint_binary_name_is_checked_at_config_load(self):
        for name in ('../x', 'a/b', 'a b', '..', '', 'x;rm'):
            with self.subTest(name), self.assertRaisesRegex(ValueError, 'endpoint.binary'):
                self.load(lambda cfg, name=name: cfg['endpoint'].update(binary=name))
        self.assertEqual(self.load(lambda cfg: cfg['endpoint'].update(binary='case4_socket_gate_read_schedule'))
                         ['endpoint']['binary'], 'case4_socket_gate_read_schedule')

    def test_remote_binary_hash_command_quotes_the_path(self):
        from types import SimpleNamespace
        c = cp.Campaign.__new__(cp.Campaign)
        c.cfg = cp.load_config(str(CONFIG))
        c.cfg['endpoint']['binary'] = 'case4_socket_gate_read_schedule'
        c.V, c.rn, c.record, commands = '/home/decps/dir with space', SimpleNamespace(dry=True), {}, []
        c.step = lambda where, label, cmd, **kw: commands.append(cmd) or cp.Result(0, '', '')
        c.check_hash = lambda *a, **kw: None
        c.units, c.label = lambda: [], lambda unit: ''
        c.vision_identity()
        self.assertIn("sha256sum '/home/decps/dir with space/case4_socket_gate_read_schedule'", commands)

    def test_runner_identity_includes_read_classes(self):
        cfg = cp.load_config(str(CONFIG))
        c = cp.Campaign(cfg, cp.DryRunner(), 'x', arms=[cfg['arms'][0]['name']])
        self.assertIn('read_classes.py', c.runner_identity)

    def test_padded_suffix_uses_the_declared_range_image(self):
        c = cp.Campaign.__new__(cp.Campaign)
        c.cfg = {'builds': {'b': {'image_len': 61, 'read_images': {'range': 141}}}}
        self.assertEqual(c._padded_suffix({'build': 'b'}, 'read_resp_padded'), '@141')
        self.assertEqual(c._padded_suffix({'build': 'b'}, 'select_resp_padded'), '@61/141')

    def test_endpoint_binary_is_configurable_with_unchanged_default(self):
        c = cp.Campaign.__new__(cp.Campaign)
        c.cfg = cp.load_config(str(CONFIG))
        self.assertEqual(c.endpoint_binary_name(), 'case4_socket_gate_pad58b')
        self.assertEqual(c.endpoint_binary_arg(), '')
        c.cfg['endpoint']['binary'] = 'case4_socket_gate_read_schedule'
        self.assertEqual(c.endpoint_binary_arg(), ' --endpoint-binary case4_socket_gate_read_schedule')

    def test_read_policy_argument(self):
        c = cp.Campaign.__new__(cp.Campaign)
        c.cfg = self.load(self.schedule())
        arm = [a for a in c.cfg['arms'] if a.get('padding')][0]
        arg = c.read_policy_arg({'reads': 65}, arm)
        self.assertTrue(arg.startswith(' --read-policy '))
        plain = cp.Campaign.__new__(cp.Campaign)
        plain.cfg = cp.load_config(str(CONFIG))
        self.assertEqual(plain.read_policy_arg({'reads': 65}, plain.cfg['arms'][0]), '')


if __name__ == '__main__':
    unittest.main()


class TwoReadProfile(unittest.TestCase):
    """The two-READ-target profile's classes and schedules (mixed 91 -> 141, integrity 247 -> 271; base DB only)."""
    TEMPLATES = (Path(__file__).resolve().parents[3] / 'integration/core/response_only_rearm/stage_experiments/'
                 'read_complete_01/vectors/two_read_templates.json')

    def test_live_requests_classify(self):
        import json
        t = json.loads(self.TEMPLATES.read_text())['variants']['v0']['classes']
        for cls in ('mixed', 'integrity'):
            payload = bytes.fromhex(t[cls]['request'])
            self.assertEqual(rc.classify_request_frames(payload), cls, cls)

    def test_mixed_needs_both_headers_in_order(self):
        mixed = bytes([0xc0, 0x01]) + bytes.fromhex('010200000f1e01000007')
        self.assertEqual(rc.classify_request(mixed), 'mixed')
        swapped = bytes([0xc0, 0x01]) + bytes.fromhex('1e01000007010200000f')
        self.assertIsNone(rc.classify_request(swapped))
        binary_only = bytes([0xc0, 0x01]) + bytes.fromhex('010200000f')
        self.assertIsNone(rc.classify_request(binary_only))

    def test_mixed_full_expectations(self):
        config = {'builds': {'b': {'read_images': {'mixed': 141, 'integrity': 271}}},
                  'traffic': {'read_schedule': 'mixed_full', 'db': 'base'}}
        arm = {'build': 'b'}
        e = rc.expectations(config, arm, {'reads': 65}, padded=True)
        self.assertEqual(e['order'], ['mixed', 'integrity'])
        self.assertEqual({c: (v['native'], v['image'], v['count']) for c, v in e['classes'].items()},
                         {'mixed': (91, 141, 33), 'integrity': (247, 271, 32)})
        native = rc.expectations(config, arm, {'reads': 65}, padded=False)
        self.assertEqual({c: v['image'] for c, v in native['classes'].items()}, {'mixed': 91, 'integrity': 247})

    def test_single_class_schedules(self):
        config = {'builds': {'b': {'read_images': {'mixed': 141, 'integrity': 271}}}, 'traffic': {'db': 'base'}}
        for name, cls in (('mixed', 'mixed'), ('full', 'integrity')):
            config['traffic']['read_schedule'] = name
            e = rc.expectations(config, {'build': 'b'}, {'reads': 20}, padded=True)
            self.assertEqual(list(e['classes']), [cls], name)

    def test_profile_schedules_are_base_only(self):
        for name in ('mixed_full', 'mixed', 'full'):
            with self.assertRaises(rc.ReadClassError, msg=name):
                rc.schedule_and_db({'traffic': {'read_schedule': name, 'db': 'large'}})

    def test_rotate4_unchanged(self):
        self.assertEqual(rc.SCHEDULES['rotate4'], ('range', 'analog', 'class0', 'integrity'))


class TwoReadPadExpect(unittest.TestCase):
    """campaign.Campaign.pad_expect_arg: a padded arm on a build that declares read_padding tells the endpoint's
    strict check exactly the padding the switch adds per scheduled class; an off arm declares none (the endpoint then
    fails on any added point)."""

    def cfg(self, schedule='mixed_full', padding=None):
        return {'builds': {'b': {'read_images': {'mixed': 141, 'integrity': 271},
                                 'read_padding': padding if padding is not None else {'mixed': 26, 'integrity': 4}}},
                'traffic': {'read_schedule': schedule, 'db': 'base'}}

    def arg(self, cfg, padding):
        stub = type('C', (), {'cfg': cfg})()
        return cp.Campaign.pad_expect_arg(stub, {'build': 'b', 'padding': padding})

    def test_padded_arm_declares_every_scheduled_class(self):
        self.assertEqual(self.arg(self.cfg(), 1), ' --pad-expect mixed=26,integrity=4')

    def test_off_arm_declares_nothing(self):
        self.assertEqual(self.arg(self.cfg(), 0), '')

    def test_schedule_restricts_the_classes(self):
        self.assertEqual(self.arg(self.cfg('mixed'), 1), ' --pad-expect mixed=26')
        self.assertEqual(self.arg(self.cfg('full'), 1), ' --pad-expect integrity=4')

    def test_build_without_read_padding_declares_nothing(self):
        cfg = self.cfg()
        del cfg['builds']['b']['read_padding']
        self.assertEqual(self.arg(cfg, 1), '')

    def test_declaration_is_accepted_by_vision_run(self):
        decl = self.arg(self.cfg(), 1).split()[-1]
        self.assertIsNotNone(vr.PAD_EXPECT_RE.fullmatch(decl), decl)

    def validate(self, padding, arms):
        cfg = self.cfg(padding=padding)
        cfg.update(endpoint={'binary': 'case4_socket_gate_read_schedule'},
                   trials={'reads_per_trial': 65, 'trials_per_arm': 1},
                   arms=[{'build': 'b', 'padding': p} for p in arms])
        cp.validate_read_classes(cfg)

    def test_validator_accepts_the_exact_declaration(self):
        self.validate({'mixed': 26, 'integrity': 4}, (0, 1))

    def test_validator_refuses_a_missing_padded_class(self):
        with self.assertRaisesRegex(ValueError, 'exactly the padded scheduled classes'):
            self.validate({'mixed': 26}, (1,))

    def test_validator_refuses_a_non_positive_count(self):
        with self.assertRaisesRegex(ValueError, 'padding point count'):
            self.validate({'mixed': 0, 'integrity': 4}, (1,))

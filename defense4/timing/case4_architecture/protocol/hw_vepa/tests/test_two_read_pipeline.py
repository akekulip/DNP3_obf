"""The two-READ-target profile (mixed 91 -> 141, integrity 247 -> 271) through the hardware analyzers, on real bytes:
the requests, native responses and pad_read images of the M1 live capture (read_complete_01/vectors/
two_read_templates.json) and the live master records of read_complete_01/evidence/m1_two_read_01. Only the TCP/IP
framing of the synthetic two-capture run is made here (pcaptk)."""
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
import checks  # noqa: E402
import clrt_check  # noqa: E402
import pcaptk as tk  # noqa: E402
import read_classes as rc  # noqa: E402
from read_class_fixture import M, O, MP, OP  # noqa: E402

RC01 = HERE.parents[2] / 'integration/core/response_only_rearm/stage_experiments/read_complete_01'
TEMPLATES = json.loads((RC01 / 'vectors/two_read_templates.json').read_text())
M1 = RC01 / 'evidence/m1_two_read_01'
PADDING = {'mixed': 26, 'integrity': 4}


def config():
    return {'builds': {'b': {'read_images': {'mixed': 141, 'integrity': 271}, 'read_padding': dict(PADDING)}},
            'traffic': {'read_schedule': 'mixed_full', 'db': 'base'}}


def schedule(reads, order=('mixed', 'integrity')):
    """[(slot, class, template)] in `order` (default alternating mixed/integrity), alternating the two captured
    fixture variants."""
    out = []
    for k in range(reads):
        cls = order[k % len(order)]
        out.append((k, cls, TEMPLATES['variants']['v%d' % ((k // 2) % 2)]['classes'][cls]))
    return out


def build_run(tmp, reads, padded=True, transform=None, order=('mixed', 'integrity')):
    for side in ('out', 'in'):
        c0, s0 = 1000, 5000
        recs = [(0, tk.frame(M, O, MP, OP, c0, 0, tk.SYN)),
                (50, tk.frame(O, M, OP, MP, s0, c0 + 1, tk.SYN | tk.ACK)),
                (90, tk.frame(M, O, MP, OP, c0 + 1, s0 + 1, tk.ACK))]
        sseq, rseq, t = c0 + 1, s0 + 1, 100
        for k, cls, v in schedule(reads, order):
            q = bytes.fromhex(v['request'])
            recs.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            sseq += len(q)
            recs.append((t + 20, tk.frame(O, M, OP, MP, rseq, sseq, tk.ACK)))
            payload = bytes.fromhex(v['native'])
            if side == 'in' and padded:
                payload = bytes.fromhex(v['expected'])
                if transform:
                    payload = transform(k, cls, payload)
            recs.append((t + 200, tk.frame(O, M, OP, MP, rseq, sseq, tk.PSH | tk.ACK, payload)))
            rseq += len(payload)
            t += 1000
        tk.write_pcap(str(Path(tmp) / ('%s.pcap' % side)), recs)


class Templates(unittest.TestCase):
    def test_the_images_are_the_declared_targets(self):
        for name, variant in TEMPLATES['variants'].items():
            for cls, target, native in (('mixed', 141, 91), ('integrity', 271, 247)):
                v = variant['classes'][cls]
                self.assertEqual((len(bytes.fromhex(v['native'])), len(bytes.fromhex(v['expected']))),
                                 (native, target), (name, cls))
                self.assertEqual(v['padding_points'], PADDING[cls])


class TimingExtraction(unittest.TestCase):
    def policy(self, padded=True):
        e = rc.expectations(config(), {'build': 'b'}, {'reads': 8}, padded=padded)
        return {'classes': e['classes']}

    def analyze(self, padded=True, transform=None, policy_padded=None):
        with tempfile.TemporaryDirectory() as tmp:
            build_run(tmp, 8, padded, transform)
            return clrt_check.analyze(os.path.join(tmp, 'out.pcap'), os.path.join(tmp, 'in.pcap'),
                                      read_policy=self.policy(padded if policy_padded is None else policy_padded))

    def test_every_padded_read_pairs_with_its_native_by_class(self):
        report = self.analyze()
        rows = [r for r in report['exchanges'] if r['kind'] == 'READ']
        self.assertEqual([r['read_class'] for r in rows], ['mixed', 'integrity'] * 4)
        self.assertTrue(all(r['publication']['response_availability_ns'] is not None for r in rows),
                        [r['publication']['null_reasons'] for r in rows])
        by_class = report['summary']['READ']['by_class']
        self.assertEqual((by_class['mixed']['resp_len'], by_class['integrity']['resp_len']), ([141], [271]))
        e = rc.expectations(config(), {'build': 'b'}, {'reads': 8}, padded=True)
        self.assertEqual(checks.read_class_timing_checks(report['summary'], e), [])

    def test_native_run_pairs_on_the_off_arm(self):
        report = self.analyze(padded=False)
        rows = [r for r in report['exchanges'] if r['kind'] == 'READ']
        self.assertTrue(all(r['publication']['response_availability_ns'] is not None for r in rows))
        by_class = report['summary']['READ']['by_class']
        self.assertEqual((by_class['mixed']['resp_len'], by_class['integrity']['resp_len']), ([91], [247]))

    def test_a_changed_original_octet_does_not_pair(self):
        sys.path.insert(0, str(RC01.parent / 'read_reencode_01'))
        import dnp3_std as std

        def corrupt(k, cls, payload):
            """slot 3 (integrity): the last measurement octet of the FIN frame changed, every CRC recomputed valid"""
            if k != 3:
                return payload
            prefix_len = 10 + (payload[2] - 5) + 2 * (-(-(payload[2] - 5) // 16))
            header, user = std.deframe(payload[prefix_len:])
            user = bytearray(user)
            user[-1] ^= 1
            return payload[:prefix_len] + std.frame(header, bytes(user))
        rows = [r for r in self.analyze(transform=corrupt)['exchanges'] if r['kind'] == 'READ']
        self.assertIsNone(rows[3]['publication']['response_availability_ns'])
        self.assertIsNotNone(clrt_check._crc_stripped_frames(corrupt(3, 'integrity', bytes.fromhex(
            TEMPLATES['variants']['v1']['classes']['integrity']['expected']))))      # the CRCs are valid
        self.assertTrue(all(r['publication']['response_availability_ns'] is not None
                            for i, r in enumerate(rows) if i != 3))

    def test_padded_bytes_under_a_native_policy_do_not_pair(self):
        rows = [r for r in self.analyze(policy_padded=False)['exchanges'] if r['kind'] == 'READ']
        self.assertTrue(all(r['publication']['response_availability_ns'] is None for r in rows))


class EndpointRecords(unittest.TestCase):
    def master(self, case):
        return json.loads((M1 / case / 'master.json').read_text())

    def test_padded_live_record_passes_with_the_padded_arm_declaration(self):
        self.assertEqual(checks.read_padding_record_checks(self.master('padded_v0'), PADDING), [])

    def test_native_live_record_passes_with_no_declaration(self):
        self.assertEqual(checks.read_padding_record_checks(self.master('native_v0'), {}), [])

    def test_crossed_records_fail(self):
        self.assertTrue(checks.read_padding_record_checks(self.master('padded_v0'), {}))
        self.assertTrue(checks.read_padding_record_checks(self.master('native_v0'), PADDING))
        self.assertTrue(checks.read_padding_record_checks(self.master('padded_undeclared'), {}))
        self.assertTrue(checks.read_padding_record_checks(self.master('declared_unpadded'), PADDING))

    def test_one_wrong_count_fails(self):
        m = copy.deepcopy(self.master('padded_v0'))
        m['read_commands'][1]['padding_points'] = 5
        self.assertTrue(checks.read_padding_record_checks(m, PADDING))

    def test_campaign_check_uses_the_arm_declaration(self):
        stub = type('C', (), {'cfg': config(), 'pad_expect_arg': cp.Campaign.pad_expect_arg})()
        check = lambda m, p: cp.Campaign.read_padding_checks(stub, m, {'build': 'b', 'padding': p})
        self.assertEqual(check(self.master('padded_v0'), 1), [])
        self.assertEqual(check(self.master('native_v0'), 0), [])
        self.assertTrue(check(self.master('native_v0'), 1))
        self.assertTrue(check(self.master('padded_v0'), 0))


class StandardsChecker(unittest.TestCase):
    """read_reencode_01/check_capture.py (the campaign's run_standards_checker) with the per-class declaration."""

    def check(self, padded=True, transform=None):
        import importlib.util
        spec = importlib.util.spec_from_file_location('cc_two_read', cp.CHECK_CAPTURE)
        mod = importlib.util.module_from_spec(spec)
        sys.path.insert(0, os.path.dirname(cp.CHECK_CAPTURE))
        spec.loader.exec_module(mod)
        e = rc.expectations(config(), {'build': 'b'}, {'reads': 8}, padded=padded)
        with tempfile.TemporaryDirectory() as tmp:
            build_run(tmp, 8, padded, transform)
            return mod.check(tmp, OP, MP, {'READ': min(c['image'] for c in e['classes'].values())},
                             require_handshake=True, read_classes=e['classes'])

    def test_padded_run_is_conformant_per_class(self):
        r = self.check()
        self.assertTrue(r['conformant'], r['failures'])
        self.assertEqual([(v['read_class'], v['wire_len']) for v in r['verdicts']],
                         [('mixed', 141), ('integrity', 271)] * 4)

    def test_native_run_is_conformant_per_class(self):
        r = self.check(padded=False)
        self.assertTrue(r['conformant'], r['failures'])
        self.assertEqual({(v['read_class'], v['wire_len']) for v in r['verdicts']}, {('mixed', 91), ('integrity', 247)})

    def test_an_image_swapped_between_classes_fails(self):
        swap = TEMPLATES['variants']['v0']['classes']['mixed']['expected']
        r = self.check(transform=lambda k, cls, p: bytes.fromhex(swap) if k == 3 else p)
        self.assertFalse(r['conformant'])


class ReportMetrics(unittest.TestCase):
    """report.trial_metrics on a two-READ trial: every READ against its own class, not one shared target."""

    def metrics(self, padded):
        import report
        e = rc.expectations(config(), {'build': 'b'}, {'reads': 8}, padded=padded)
        with tempfile.TemporaryDirectory() as root:
            d = os.path.join(root, 'fx', 'arm', 't0')
            os.makedirs(d)
            build_run(d, 8, padded)
            timing = clrt_check.analyze(os.path.join(d, 'out.pcap'), os.path.join(d, 'in.pcap'),
                                        read_policy={'classes': e['classes']})
            json.dump(timing, open(os.path.join(d, 'timing.json'), 'w'))
            json.dump({'expected': {'lengths': {'READ': sorted({c['image'] for c in e['classes'].values()})},
                                    'read_classes': e['classes']}}, open(os.path.join(d, 'standards.json'), 'w'))
            return report.trial_metrics(root, 'fx', 'arm', {'label': 't0'}, None)

    def test_padded_trial(self):
        m = self.metrics(True)
        self.assertEqual((m['exact_length_correct'], m['length_failed'], m['padding_coverage'], m['padded_responses']),
                         (8, 0, 1.0, 8))
        self.assertEqual(m['growth_bytes'], 4 * 50 + 4 * 24)

    def test_off_trial(self):
        m = self.metrics(False)
        self.assertEqual((m['exact_length_correct'], m['native_or_ineligible'], m['padding_coverage'],
                          m['padded_responses'], m['growth_bytes']), (8, 8, None, 0, 0))


class SingleClassLoss(unittest.TestCase):
    """Loss presets on a single-class two-READ workload (schedule mixed or full): selectors resolve to that class."""
    import loss as _loss

    def cfg(self, schedule='mixed', presets=None):
        c = config()
        c['builds']['b'].update(image_len=61)
        c['traffic']['read_schedule'] = schedule
        c.update(endpoint={'binary': 'case4_socket_gate_read_schedule'}, trials={'reads_per_trial': 20,
                                                                                 'trials_per_arm': 1},
                 arms=[{'name': 'combined', 'build': 'b', 'padding': 1, 'T': 1}],
                 loss={'presets': presets or {'core': [{'class': 'request_mixed' if schedule == 'mixed' else
                                                        'request_full', 'n': 3}, {'class': 'ack_sep', 'n': 3},
                                                       {'class': 'read_resp_padded', 'n': 3},
                                                       {'class': 'select_resp_padded', 'n': 1},
                                                       {'class': 'operate_req', 'n': 1},
                                                       {'class': 'operate_resp_padded', 'n': 1},
                                                       {'class': 'master_ack_of_padded_data', 'n': 1}]}})
        return c

    def stub(self, cfg):
        class S:
            single_read_class = cp.Campaign.single_read_class
            _padded_suffix = cp.Campaign._padded_suffix
        st = S()
        st.cfg = cfg
        return st

    def test_presets_validate_per_class(self):
        cp.validate_read_classes(self.cfg('mixed'))
        cp.validate_read_classes(self.cfg('full'))

    def test_foreign_or_range_selectors_are_refused(self):
        for schedule, bad in (('mixed', 'request'), ('mixed', 'request_full'), ('full', 'read_resp_padded_141'),
                              ('mixed', 'read_resp_analog')):
            with self.assertRaisesRegex(ValueError, 'not a selector of this single-class workload', msg=bad):
                cp.validate_read_classes(self.cfg(schedule, {'p': [{'class': bad, 'n': 1}]}))

    def test_suffix_resolves_to_the_class_image(self):
        for schedule, image, native in (('mixed', 141, 91), ('full', 271, 247)):
            st = self.stub(self.cfg(schedule))
            arm = st.cfg['arms'][0]
            self.assertEqual(st._padded_suffix(arm, 'read_resp_padded'), '@%d' % image)
            self.assertEqual(st._padded_suffix(arm, 'master_ack_of_padded_data'), '@%d' % image)
            self.assertEqual(st._padded_suffix(arm, 'select_resp_padded'), '@61/%d' % image)
            spec = self._loss.parse_drop('read_resp_padded:3' + st._padded_suffix(arm, 'read_resp_padded'), 20)
            self.assertEqual((spec['ip_len'], spec['occurrence']), (40 + image, 3))
            sel = self._loss.parse_drop('select_resp_padded:1' + st._padded_suffix(arm, 'select_resp_padded'), 20)
            self.assertEqual((sel['ip_len'], sel['occurrence']), (101, 1))
            self.assertEqual(st.single_read_class(arm), ({'mixed': 'mixed', 'full': 'integrity'}[schedule],
                                                         native, image))
            self.assertEqual(st.single_read_class(dict(arm, padding=0))[2], native)

    def test_mixed_full_has_no_single_class(self):
        st = self.stub(self.cfg('mixed'))
        st.cfg['traffic']['read_schedule'] = 'mixed_full'
        self.assertIsNone(st.single_read_class(st.cfg['arms'][0]))

    def test_request_selectors_match_the_captured_requests(self):
        for cls, sel in (('mixed', 'request_mixed'), ('integrity', 'request_full')):
            req = bytes.fromhex(TEMPLATES['variants']['v0']['classes'][cls]['request'])
            self.assertEqual(self._loss.CLASSES[sel]['ip_len'], 40 + len(req))

    def test_growth_uses_the_class_native(self):
        for order, image, native in ((('mixed',), 141, 91), (('integrity',), 271, 247)):
            e = rc.expectations(dict(config(), traffic={'read_schedule': 'mixed' if order == ('mixed',) else 'full',
                                                        'db': 'base'}), {'build': 'b'}, {'reads': 4})
            with tempfile.TemporaryDirectory() as tmp:
                build_run(tmp, 4, True, order=order)
                t = clrt_check.analyze(os.path.join(tmp, 'out.pcap'), os.path.join(tmp, 'in.pcap'),
                                       read_policy={'classes': e['classes']})
            obs, exp = self._loss._growth(t, True, True, 61, image, native)
            self.assertEqual((obs, exp), (4 * (image - native), 4 * (image - native)))
            # the range default would misread every response as growth over 49
            self.assertNotEqual(self._loss._growth(t, True, True, 61, image)[0], obs)


class ReconnectPolicy(unittest.TestCase):
    def test_c2_policy_is_native_and_installed_tuple_is_padded(self):
        cfg = config()
        stub = type('C', (), {'cfg': cfg})()
        arm = {'build': 'b', 'padding': 1, 'name': 'combined'}
        cfg['builds']['b']['image_len'] = 61
        trial = {'reads': 4}
        decode = lambda a: json.loads(a.split(' ', 2)[2].strip("'"))['classes']
        padded = decode(cp.Campaign.read_policy_arg(stub, trial, arm))
        native = decode(cp.Campaign.read_policy_arg(stub, trial, arm, True))
        self.assertEqual({c: e['image'] for c, e in padded.items()}, {'mixed': 141, 'integrity': 271})
        self.assertEqual({c: e['image'] for c, e in native.items()}, {'mixed': 91, 'integrity': 247})


class ReviewFindings(unittest.TestCase):
    """Refusals added after the review of the two-READ harness."""

    def base(self, schedule='mixed_full'):
        c = SingleClassLoss('test_presets_validate_per_class').cfg('mixed')
        c['traffic']['read_schedule'] = schedule
        return c

    def test_loss_preset_on_mixed_full_is_refused(self):
        for sel in ('read_resp_91', 'read_resp_247', 'read_resp_analog', 'ack_sep'):
            c = self.base()
            c['loss']['presets'] = {'p': [{'class': sel, 'n': 1}]}
            with self.assertRaisesRegex(ValueError, 'single-class workload', msg=sel):
                cp.validate_read_classes(c)

    def test_padded_two_read_arm_needs_read_padding(self):
        c = self.base()
        c['loss']['presets'] = {}
        del c['builds']['b']['read_padding']
        with self.assertRaisesRegex(ValueError, 'read_padding is required'):
            cp.validate_read_classes(c)
        c['arms'][0]['padding'] = 0
        cp.validate_read_classes(c)

    def test_no_scheduled_padded_class_gives_no_flag(self):
        c = config()
        c['builds']['b']['read_padding'] = {'mixed': 26}
        c['traffic']['read_schedule'] = 'full'
        stub = type('C', (), {'cfg': c})()
        self.assertEqual(cp.Campaign.pad_expect_arg(stub, {'build': 'b', 'padding': 1}), '')

    def test_empty_records_fail_the_padding_check(self):
        self.assertTrue(checks.read_padding_record_checks({'pad_expect': 'none', 'read_commands': []}, {}))

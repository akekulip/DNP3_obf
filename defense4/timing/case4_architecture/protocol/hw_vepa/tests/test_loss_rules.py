"""Deterministic one-packet loss, part A: the packet-class table, the iptables rule construction, and the LossRule
install / counters / removal driven through a fake `ip netns exec` (no iptables, no root, no namespace needed)."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import loss  # noqa: E402

M, O = '192.168.10.61', '192.168.10.62'

LIST = """Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num      pkts      bytes target     prot opt in     out     source               destination
1           1         98 ACCEPT     tcp  --  *      *       192.168.10.62        192.168.10.61        tcp spt:20000 dpt:54500 length 98 flags:0x1B/0x18 limit: avg 1/hour burst 1
2           1         98 DROP       tcp  --  *      *       192.168.10.62        192.168.10.61        tcp spt:20000 dpt:54500 length 98 flags:0x1B/0x18 limit: avg 1/hour burst 1
"""


class ClassTable(unittest.TestCase):
    def test_ip_lengths_come_from_the_real_wire_shapes(self):
        c = loss.CLASSES
        self.assertEqual(c['request']['ip_len'], 20 + 20 + 20)            # READ request, 20 B payload
        self.assertEqual(c['control_req']['ip_len'], 20 + 20 + 35)        # SELECT/OPERATE request, 35 B
        self.assertEqual(c['read_resp_native']['ip_len'], 20 + 20 + 49)
        self.assertEqual(c['control_resp_native']['ip_len'], 20 + 20 + 37)
        self.assertEqual(c['resp_padded']['ip_len'], 20 + 20 + 58)
        self.assertEqual(c['ack_sep']['ip_len'], 40)
        self.assertEqual(c['master_ack']['ip_len'], 40)

    def test_directions_flags_and_receiving_namespace(self):
        c = loss.CLASSES
        self.assertEqual((c['request']['dir'], c['request']['flags']), ('M>O', 'ACK,PSH'))
        self.assertEqual((c['ack_sep']['dir'], c['ack_sep']['flags']), ('O>M', 'ACK'))
        self.assertEqual(loss.receiver_ns('M>O'), 'ns_vepa_b')            # dropped at the outstation's ingress
        self.assertEqual(loss.receiver_ns('O>M'), 'ns_vepa_a')            # dropped at the master's ingress

    def test_aliases_cover_every_class_the_brief_names(self):
        for name in ('request', 'ack_sep', 'read_resp_padded', 'select_resp_padded', 'operate_resp_padded',
                     'select_resp_native', 'operate_resp_native', 'read_resp_native', 'select_req', 'operate_req',
                     'master_ack_of_padded'):
            self.assertIn(name, loss.names(), name)

    def test_single_frame_read_class_response_lengths(self):
        # One selector per length (no per-class claim): analog 181, and ONE 247-byte selector for base
        # class0/integrity, which the length+flags selector cannot tell apart.
        c = loss.CLASSES
        self.assertEqual(c['read_resp_analog']['ip_len'], 40 + 141)
        self.assertEqual(c['read_resp_247']['ip_len'], 40 + 247)
        for name in ('read_resp_analog', 'read_resp_247'):
            self.assertEqual((c[name]['dir'], c[name]['flags']), ('O>M', 'ACK,PSH'), name)
        # a per-class class0/integrity loss selector is NOT offered (it would mis-stamp the class)
        for name in ('read_resp_class0', 'read_resp_integrity'):
            self.assertNotIn(name, c, name)
            self.assertNotIn(name, loss.names(), name)
        self.assertEqual(loss.READ_RESP_LEN, {'read_resp_analog': 141, 'read_resp_247': 247, 'read_resp_91': 91})

    def test_segmented_read_class_response_is_not_exercised(self):
        # base single-frame response lengths {range 49, analog 141, class0/integrity 247}: both selectors valid
        base = {49, 141, 247}
        for selector in ('read_resp_analog', 'read_resp_247'):
            self.assertEqual(loss.read_resp_class(selector, base), (selector, None), selector)
        # large: class0/integrity are segmented (292 + 85), so no single-frame 247-byte response -> NOT_EXERCISED
        large = {49, 141}
        sel, reason = loss.read_resp_class('read_resp_247', large)
        self.assertIsNone(sel)
        self.assertIn('NOT_EXERCISED', reason)
        self.assertEqual(loss.read_resp_class('read_resp_analog', large), ('read_resp_analog', None))
        # a per-class selector is refused as not a single-frame READ-response loss selector
        for name in ('read_resp_class0', 'read_resp_integrity'):
            sel, reason = loss.read_resp_class(name, base)
            self.assertIsNone(sel, name)
            self.assertIn('NOT_EXERCISED', reason)

    def test_length_selectors_make_no_per_class_claim(self):
        # read_resp_analog is length-level, consistent with read_resp_247: its description names the LENGTH and
        # records both possible origins (base analog OR a range READ padded to 141), never "analog" as THE class --
        # a 141-byte drop in a mixed schedule may be a padded range response.
        c = loss.CLASSES
        for name in ('read_resp_analog', 'read_resp_247'):
            self.assertIn('single-frame READ response', c[name]['what'], name)
            self.assertIn('not distinguished', c[name]['what'], name)        # no single-class claim
        self.assertNotEqual(c['read_resp_analog']['what'], 'a 141 B single-frame READ response (analog)')
        self.assertEqual(loss.LENGTH_ONLY, frozenset({'read_resp_analog', 'read_resp_247', 'read_resp_91',
                                                      'read_resp_padded_141', 'read_resp_padded_271'}))


class TwoReadProfile(unittest.TestCase):
    """Selectors and the @LEN bound for the two-READ-target profile (mixed 91 -> 141, full 247 -> 271)."""

    def test_selectors_target_the_profile_lengths(self):
        c = loss.CLASSES
        for name, ip in (('read_resp_91', 131), ('read_resp_247', 287),
                         ('read_resp_padded_141', 181), ('read_resp_padded_271', 311)):
            self.assertEqual((c[name]['ip_len'], c[name]['dir'], c[name]['flags']), (ip, 'O>M', 'ACK,PSH'), name)
            spec = loss.parse_drop(name + ':2', reads=20)
            self.assertEqual((spec['ip_len'], spec['occurrence'], spec['length_only']), (ip, 2, True), name)
        self.assertEqual(loss.PADDED_READ_LEN, {'read_resp_padded_141': 141, 'read_resp_padded_271': 271})
        # the padded-image selectors describe an IMAGE in one TCP segment, not a single frame
        for name in loss.PADDED_READ_LEN:
            self.assertIn('padded READ image in one TCP segment', c[name]['what'], name)

    def test_profile_lengths_are_distinct(self):
        # no two of the profile's response lengths (READ native/padded, SBO native/padded) share an IP length
        ips = [loss.CLASSES[n]['ip_len'] for n in ('read_resp_91', 'read_resp_247', 'read_resp_padded_141',
                                                   'read_resp_padded_271', 'control_resp_native')] + [40 + 61]
        self.assertEqual(len(ips), len(set(ips)))

    def test_len_bound_is_the_tcp_payload_not_one_link_frame(self):
        # 271 (the full READ's padded aggregate, [24, 247]) exceeds one link frame's 249 user octets but is a
        # valid TCP payload length: accepted, and it sets the padded class's IP length
        spec = loss.parse_drop('read_resp_padded@271', reads=20)
        self.assertEqual((spec['ip_len'], spec['padded_len']), (311, 271))
        spec = loss.parse_drop('select_resp_padded@61/271', reads=20)
        self.assertEqual((spec['ip_len'], spec['padded_len']), (101, 61))
        self.assertEqual(loss.parse_drop('read_resp_padded@1460', reads=20)['ip_len'], 1500)
        for bad in ('read_resp_padded@1461', 'read_resp_padded@49', 'read_resp_padded@0',
                    'read_resp_padded@61/1461', 'read_resp_padded@x', 'read_resp_padded@61/'):
            with self.assertRaises(ValueError, msg=bad):
                loss.parse_drop(bad, reads=20)


class Parse(unittest.TestCase):
    def test_default_n_is_one(self):
        self.assertEqual(loss.parse_drop('request', reads=20)['n'], 1)

    def test_class_and_occurrence(self):
        s = loss.parse_drop('read_resp_padded:5', reads=20)
        self.assertEqual((s['class'], s['n'], s['base'], s['occurrence']), ('read_resp_padded', 5, 'resp_padded', 5))
        self.assertEqual(s['ip_len'], 98)

    def test_aliases_shift_the_occurrence_by_what_precedes_them(self):
        self.assertEqual(loss.parse_drop('select_resp_padded', reads=20)['occurrence'], 21)    # after 20 READ responses
        self.assertEqual(loss.parse_drop('operate_resp_padded', reads=20)['occurrence'], 22)
        self.assertEqual(loss.parse_drop('select_req', reads=20)['occurrence'], 1)
        self.assertEqual(loss.parse_drop('operate_req', reads=20)['occurrence'], 2)
        self.assertEqual(loss.parse_drop('operate_req:1', reads=20)['base'], 'control_req')
        self.assertEqual(loss.parse_drop('master_ack_of_padded:3', reads=20)['occurrence'], 4)  # occurrence 1 is the handshake

    def test_bad_specs_are_rejected(self):
        for bad in ('', 'nope', 'request:0', 'request:-1', 'request:x', 'request:1:2', 'request:%d' % (loss.MAX_N + 1)):
            with self.assertRaises(ValueError, msg=bad):
                loss.parse_drop(bad, reads=20)

    def test_single_frame_read_class_occurrence(self):
        s = loss.parse_drop('read_resp_247:2', reads=20)
        self.assertEqual((s['class'], s['base'], s['occurrence'], s['ip_len']),
                         ('read_resp_247', 'read_resp_247', 2, 287))
        for name in ('read_resp_class0', 'read_resp_integrity'):   # per-class selectors do not exist
            with self.assertRaises(ValueError, msg=name):
                loss.parse_drop(name, reads=20)

    def test_length_selector_drop_is_marked_length_only(self):
        # a length selector's spec marks the drop length_only, so no reader takes it as a per-class claim
        for name in ('read_resp_analog', 'read_resp_247'):
            self.assertTrue(loss.parse_drop(name + ':2', reads=20)['length_only'], name)
        # a class-identified selector (native READ response, request, padded response) is NOT length_only
        for name in ('read_resp_native', 'request', 'read_resp_padded'):
            self.assertFalse(loss.parse_drop(name, reads=20)['length_only'], name)


class Rules(unittest.TestCase):
    def build(self, spec, reads=20, port=54500):
        return loss.build_rules(loss.parse_drop(spec, reads=reads), M, O, port, 20000)

    def test_first_occurrence_is_a_single_drop_rule_in_the_receivers_namespace(self):
        ns, rules = self.build('read_resp_padded')
        self.assertEqual(ns, 'ns_vepa_a')
        self.assertEqual(len(rules), 1)
        r = ' '.join(rules[0])
        self.assertIn('-s %s -d %s' % (O, M), r)
        self.assertIn('--sport 20000 --dport 54500', r)
        self.assertIn('-m length --length 98', r)
        self.assertIn('--tcp-flags SYN,RST,ACK,FIN,PSH ACK,PSH', r)
        self.assertTrue(r.endswith('-m limit --limit 1/hour --limit-burst 1 -j DROP'))

    def test_nth_occurrence_is_n_minus_1_accept_rules_then_the_drop(self):
        ns, rules = self.build('read_resp_padded:4')
        self.assertEqual([r[-1] for r in rules], ['ACCEPT', 'ACCEPT', 'ACCEPT', 'DROP'])
        for r in rules:
            self.assertIn('--limit-burst 1', ' '.join(r))              # burst 1 each: exact, no credit-overflow risk

    def test_request_direction_ports_and_namespace(self):
        ns, rules = self.build('request')
        self.assertEqual(ns, 'ns_vepa_b')
        r = ' '.join(rules[0])
        self.assertIn('-s %s -d %s' % (M, O), r)
        self.assertIn('--sport 54500 --dport 20000', r)
        self.assertIn('-m length --length 60', r)

    def test_pure_ack_matches_ack_only_and_length_40(self):
        ns, rules = self.build('ack_sep:2')
        r = ' '.join(rules[0])
        self.assertIn('--length 40', r)
        self.assertTrue(r.rstrip().split('--tcp-flags SYN,RST,ACK,FIN,PSH ')[1].startswith('ACK -m limit'))

    def test_occurrence_uses_the_alias_offset(self):
        ns, rules = self.build('operate_resp_padded', reads=20)
        self.assertEqual(len(rules), 22)

    def test_no_rule_uses_the_unreliable_statistic_match(self):
        for spec in ('request', 'read_resp_padded:7', 'operate_req'):
            self.assertNotIn('statistic', ' '.join(' '.join(r) for r in self.build(spec)[1]))

    def test_single_frame_read_class_drop_targets_its_response_length(self):
        for spec, length in (('read_resp_analog:2', 181), ('read_resp_247', 287), ('read_resp_247:3', 287)):
            ns, rules = self.build(spec)
            self.assertEqual(ns, 'ns_vepa_a', spec)                       # O>M dropped at the master's ingress
            self.assertEqual(rules[-1][-1], 'DROP', spec)
            self.assertIn('-m length --length %d' % length, ' '.join(rules[-1]), spec)
            self.assertIn('--sport 20000 --dport 54500', ' '.join(rules[-1]), spec)


class FakeNsx:
    """Stands in for `ip netns exec NS cmd...`: records calls and answers iptables -S / -L."""
    def __init__(self, fail_on=None, list_out=LIST):
        self.calls, self.fail_on, self.list_out = [], fail_on, list_out
        self.rules = []

    def __call__(self, ns, *cmd, **kw):
        self.calls.append((ns,) + cmd)
        line = ' '.join(cmd)
        rc, out = 0, ''
        if self.fail_on and self.fail_on in line:
            rc = 2
        elif '-S INPUT' in line:
            out = '-P INPUT ACCEPT\n' + ''.join('-A INPUT %s\n' % r for r in self.rules)
        elif '-L INPUT' in line:
            out = self.list_out
        elif ' -I INPUT' in line:
            self.rules.append(line.split(' -I INPUT ', 1)[1].split(' ', 1)[1])
        elif ' -D INPUT' in line:
            spec = line.split(' -D INPUT ', 1)[1]
            if spec in self.rules:
                self.rules.remove(spec)
            else:
                rc = 1
        return SimpleNamespace(returncode=rc, stdout=out, stderr='boom' if rc else '')


class LossRuleLifecycle(unittest.TestCase):
    def rule(self, nsx, spec='read_resp_padded'):
        return loss.LossRule(nsx, loss.parse_drop(spec, reads=20), M, O, 54500, 20000)

    def test_install_inserts_in_order_at_explicit_positions_and_records_prior_state(self):
        nsx = FakeNsx()
        lr = self.rule(nsx, 'read_resp_padded:2')
        lr.install()
        ins = [c for c in nsx.calls if '-I' in c]
        self.assertEqual([c[c.index('-I') + 2] for c in ins], ['1', '2'])
        self.assertTrue(all(c[0] == 'ns_vepa_a' for c in nsx.calls))
        self.assertEqual(lr.state_before, ['-P INPUT ACCEPT'])

    def test_remove_deletes_exactly_what_was_installed_and_state_is_restored(self):
        nsx = FakeNsx()
        lr = self.rule(nsx, 'read_resp_padded:3')
        lr.install()
        self.assertEqual(len(nsx.rules), 3)
        lr.remove()
        self.assertEqual(nsx.rules, [])
        rec = lr.record()
        self.assertTrue(rec['removed'])
        self.assertTrue(rec['state_restored'])
        self.assertEqual(rec['remove_errors'], [])

    def test_failed_insert_rolls_back_and_raises(self):
        nsx = FakeNsx()
        real = nsx.__call__
        n = {'i': 0}

        def flaky(ns, *cmd, **kw):
            if ' '.join(cmd).find('-I INPUT') >= 0:
                n['i'] += 1
                if n['i'] == 3:
                    return SimpleNamespace(returncode=2, stdout='', stderr="Couldn't load match `limit'")
            return real(ns, *cmd, **kw)
        lr = self.rule(flaky, 'read_resp_padded:5')
        with self.assertRaises(RuntimeError) as e:
            lr.install()
        self.assertIn('limit', str(e.exception))
        self.assertEqual(nsx.rules, [])                                # the two rules already in are gone again

    def test_context_manager_removes_even_when_the_body_raises(self):
        nsx = FakeNsx()
        try:
            with self.rule(nsx):
                self.assertEqual(len(nsx.rules), 1)
                raise KeyError('master crashed')
        except KeyError:
            pass
        self.assertEqual(nsx.rules, [])

    def test_remove_attempts_every_rule_and_records_errors(self):
        nsx = FakeNsx()
        lr = self.rule(nsx, 'read_resp_padded:3')
        lr.install()
        nsx.rules.pop(1)                                               # someone removed one underneath us
        lr.remove()
        rec = lr.record()
        self.assertEqual(len(rec['remove_errors']), 1)
        self.assertFalse(rec['state_restored'] and rec['removed'])
        self.assertEqual(nsx.rules, [])                                # the others were still deleted

    def test_record_carries_length_only_for_a_length_selector(self):
        # the evidence record stamps a length-selector drop length_only (no per-class claim); a class-identified
        # selector records length_only False
        rec = self.rule(FakeNsx(), 'read_resp_analog:1').install().record()
        self.assertTrue(rec['length_only'])
        self.assertFalse(self.rule(FakeNsx(), 'read_resp_padded').install().record()['length_only'])

    def test_counters_are_parsed_from_iptables_list_output(self):
        nsx = FakeNsx()
        lr = self.rule(nsx, 'read_resp_padded:2')
        lr.install()
        c = lr.counters()
        self.assertEqual(c, [{'pos': 1, 'target': 'ACCEPT', 'pkts': 1, 'bytes': 98},
                             {'pos': 2, 'target': 'DROP', 'pkts': 1, 'bytes': 98}])

    def test_exactness_requires_one_drop_of_the_right_size_and_n_minus_1_earlier_matches(self):
        nsx = FakeNsx()
        lr = self.rule(nsx, 'read_resp_padded:2')
        lr.install()
        lr.finish()
        rec = lr.record()
        self.assertEqual(rec['dropped_packets'], 1)
        self.assertEqual(rec['dropped_bytes'], 98)
        self.assertEqual(rec['earlier_matches'], 1)
        self.assertTrue(rec['exact'])
        self.assertEqual(rec['mode'], 'limit-burst-1 chain (kernel-atomic)')

    def test_class_that_never_occurred_is_not_exact(self):
        none = LIST.replace('1           1         98 ACCEPT', '1           0          0 ACCEPT').replace(
            '2           1         98 DROP', '2           0          0 DROP')
        lr = self.rule(FakeNsx(list_out=none), 'read_resp_padded:2')
        lr.install()
        lr.finish()
        rec = lr.record()
        self.assertFalse(rec['exact'])
        self.assertEqual(rec['dropped_packets'], 0)

    def test_wrong_size_is_not_exact(self):
        wrong = LIST.replace('98 DROP', '99 DROP')
        lr = self.rule(FakeNsx(list_out=wrong), 'read_resp_padded:2')
        lr.install()
        lr.finish()
        self.assertFalse(lr.record()['exact'])

    def test_failed_listing_is_recorded_not_raised(self):
        nsx = FakeNsx(fail_on='-L INPUT')
        lr = self.rule(nsx)
        lr.install()
        lr.finish()
        self.assertFalse(lr.record()['exact'])
        self.assertTrue(lr.record()['counter_error'])


class VisionRunWiring(unittest.TestCase):
    def test_vision_run_takes_the_drop_option_and_imports_the_shared_module(self):
        import subprocess
        out = subprocess.run([sys.executable, str(HERE.parent / 'vision_run.py'), '--help'],
                             capture_output=True, text=True).stdout
        self.assertIn('--drop', out)


if __name__ == '__main__':
    unittest.main()

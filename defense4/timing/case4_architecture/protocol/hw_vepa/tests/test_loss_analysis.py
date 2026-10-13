"""loss.identify (which packet was dropped, from the captures) and loss.evaluate_loss (the gate for a loss trial)."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import loss  # noqa: E402
import pcaptk as tk  # noqa: E402

M, O, MP, OP = '192.168.10.61', '192.168.10.62', 54500, 20000
PSHACK, ACK = tk.PSH | tk.ACK, tk.ACK
EXP = json.load(open(HERE.parent / 'campaign.json'))['expectations']


def conversation(reads=3, retx_resp=None, retx_req=None, resp_len=49, sep_ack=True):
    """(out_records, in_records) of a clean conversation; a response/request may be retransmitted 200 ms later.
    Every frame is in both captures (tcpdump taps before netfilter), as on the rig."""
    out, inn = [], []

    def both(t, fr):
        out.append((t, fr))
        inn.append((t + 50, fr))
    sseq, rseq = 1000, 5000
    for i in range(reads):
        t = 1_000_000 * (i + 1)
        req = tk.frame(M, O, MP, OP, sseq, rseq, PSHACK, tk.read_request(i))
        both(t, req)
        if retx_req == i:
            both(t + 200_000, req)                        # the master retransmits the (dropped) request
            t += 200_000
        sseq += 20
        if sep_ack:
            both(t + 300, tk.frame(O, M, OP, MP, rseq, sseq, ACK))
        body = tk.read_response(i, body_len=28 + (resp_len - 49))
        resp = tk.frame(O, M, OP, MP, rseq, sseq, PSHACK, body)
        both(t + 5_000, resp)
        if retx_resp == i:
            both(t + 5_000 + 200_000, resp)               # the outstation retransmits the (dropped) response
        rseq += len(body)
        both(t + 5_500, tk.frame(M, O, MP, OP, sseq, rseq, ACK))
    return out, inn


def write(tmp, out, inn):
    tk.write_pcap(str(Path(tmp) / 'out.pcap'), out)
    tk.write_pcap(str(Path(tmp) / 'in.pcap'), inn)
    return str(Path(tmp) / 'out.pcap'), str(Path(tmp) / 'in.pcap')


class Identify(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def ident(self, spec, **kw):
        out, inn = conversation(**kw)
        o, i = write(self.tmp, out, inn)
        return loss.identify(o, i, loss.parse_drop(spec, reads=3), MP, OP)

    def test_the_nth_response_is_identified_with_its_seq_and_length(self):
        r = self.ident('read_resp_native:2', retx_resp=1)
        self.assertTrue(r['identified'])
        self.assertEqual(r['candidates'], 4)                   # three responses plus the retransmitted copy
        p = r['packet']
        self.assertEqual((p['len'], p['ip_len'], p['seq']), (49, 89, 5049))
        self.assertEqual(p['t_us'], 2_000_000 + 5_000 + 50)

    def test_a_dropped_response_is_retransmitted_and_recovery_is_the_retransmission_arrival(self):
        r = self.ident('read_resp_native:2', retx_resp=1)
        self.assertTrue(r['retransmitted'])
        self.assertEqual(r['copies_returned'], 2)
        self.assertEqual(r['first_retx_delay_us'], 200_000)
        self.assertEqual(r['recovery_us'], 200_000)
        self.assertEqual(r['retransmissions_sent'], 1)

    def test_a_dropped_request_recovers_when_the_response_to_the_retransmission_arrives(self):
        r = self.ident('request:2', retx_req=1)
        self.assertEqual(r['packet']['ip_len'], 60)
        self.assertTrue(r['retransmitted'])
        self.assertEqual(r['first_retx_delay_us'], 200_000)
        self.assertEqual(r['recovery_us'], 200_000 + 5_000)    # retransmitted request at +200 ms, response 5 ms later

    def test_a_drop_that_was_never_retransmitted_is_reported_as_such(self):
        r = self.ident('read_resp_native:2')
        self.assertTrue(r['identified'])
        self.assertFalse(r['retransmitted'])
        self.assertIsNone(r['recovery_us'])

    def test_a_pure_ack_has_no_retransmission_and_records_progress(self):
        r = self.ident('ack_sep:2')
        self.assertEqual((r['packet']['len'], r['packet']['ip_len']), (0, 40))
        self.assertIsNone(r['retransmitted'])
        self.assertEqual(r['progress_us'], 4_700)              # next O>M data frame, 5 ms after the ack's request, -300 us

    def test_occurrence_beyond_the_traffic_is_not_identified(self):
        r = self.ident('read_resp_native:9')
        self.assertFalse(r['identified'])
        self.assertEqual(r['candidates'], 3)

    def test_class_matching_uses_length_and_flags_not_just_direction(self):
        r = self.ident('ack_sep:1')
        self.assertEqual(r['packet']['ip_len'], 40)
        self.assertEqual(r['candidates'], 3)                   # not the 3 data responses, not the master's pure ACKs

    def test_padded_class_matches_58_byte_responses(self):
        out, inn = conversation(resp_len=58, retx_resp=0)
        o, i = write(self.tmp, out, inn)
        r = loss.identify(o, i, loss.parse_drop('read_resp_padded:1', reads=3), MP, OP)
        self.assertEqual(r['packet']['ip_len'], 98)
        self.assertTrue(r['retransmitted'])


def clean_timing(reads=3, padded=True):
    ex = [{'kind': 'READ', 'resp_len': 58 if padded else 49, 'complete': True} for _ in range(reads)]
    ex += [{'kind': 'SELECT', 'resp_len': 58 if padded else 37, 'complete': True},
           {'kind': 'OPERATE', 'resp_len': 58 if padded else 37, 'complete': True}]
    k = lambda n: {'logical_requests': n, 'complete': n, 'incomplete': 0, 'req_crc_bad': 0, 'resp_crc_bad': 0}
    return {'summary': {'READ': k(reads), 'SELECT': k(1), 'OPERATE': k(1)}, 'exchanges': ex}


def good_inputs():
    spec = loss.parse_drop('read_resp_padded:2', reads=3)
    rule = {'class': 'read_resp_padded', 'n': 2, 'occurrence': 2, 'exact': True, 'removed': True,
            'state_restored': True, 'dropped_packets': 1, 'dropped_bytes': 98, 'remove_errors': []}
    ident = {'identified': True, 'candidates': 4, 'packet': {'seq': 5049, 'len': 58, 'ip_len': 98, 't_us': 2_005_050,
                                                             'ack': 1, 'index': 7}, 'copies_returned': 2,
             'retransmitted': True, 'first_retx_delay_us': 200_000, 'recovery_us': 200_000, 'progress_us': None,
             'retransmissions_sent': 1}
    master = {'success': True, 'reads_requested': 3, 'reads_completed': 3, 'all_reads_match_seed': True,
              'issued_ns': 10, 'completed_ns': 10 + 3_000_000_000}
    ost = {'select_real': 1, 'select_decoy': 0, 'operate_real': 1, 'operate_decoy': 0}
    wire = {'returned_integrity': {'dnp3_crc_bad': [], 'tcp_checksum_bad': []}, 'unmatched_returned': [],
            'duplicate_returned': [1]}
    return dict(spec=spec, rule=rule, ident=ident, master=master, ost=ost, wire=wire, timing=clean_timing())


def gate(**over):
    d = good_inputs()
    d.update(over)
    return loss.evaluate_loss({'padding': 1}, 3, 5.0, d['spec'], d['rule'], d['ident'], d['master'], d['ost'],
                              d['wire'], d['timing'], EXP, baseline_completion_s=2.5)


class Gate(unittest.TestCase):
    def test_a_recovered_loss_passes_and_records_everything(self):
        fails, res = gate()
        self.assertEqual(fails, [])
        self.assertEqual(res['class'], 'read_resp_padded')
        self.assertEqual(res['packet']['seq'], 5049)
        self.assertEqual(res['recovery_s'], 0.2)
        self.assertEqual(res['first_retx_delay_ms'], 200.0)
        self.assertEqual(res['retransmissions'], 1)
        self.assertTrue(res['completed'])
        self.assertTrue(res['exactly_once'])
        self.assertEqual(res['growth_bytes'], res['expected_growth_bytes'])
        self.assertEqual(res['growth_bytes'], 9 * 3 + 21 * 2)
        self.assertEqual(res['completion_s'], 3.0)
        self.assertEqual(res['baseline_completion_s'], 2.5)
        self.assertEqual(res['completion_delta_s'], 0.5)

    def one(self, needle, **over):
        fails, res = gate(**over)
        self.assertTrue(any(needle in f for f in fails), (needle, fails))
        return res

    def test_inexact_rule_counters_fail(self):
        d = good_inputs()
        d['rule'] = dict(d['rule'], exact=False, dropped_packets=0)
        self.one('rule', rule=d['rule'])

    def test_rules_left_behind_fail(self):
        d = good_inputs()
        self.one('removed', rule=dict(d['rule'], removed=False, remove_errors=['x']))

    def test_missing_vision_loss_record_fails(self):
        self.one('no loss record', rule=None)

    def test_unidentified_packet_fails(self):
        d = good_inputs()
        self.one('not found in the capture', ident=dict(d['ident'], identified=False, packet=None))

    def test_a_dropped_data_packet_that_was_never_retransmitted_fails(self):
        d = good_inputs()
        self.one('never retransmitted', ident=dict(d['ident'], retransmitted=False, recovery_us=None))

    def test_recovery_beyond_the_bound_fails(self):
        d = good_inputs()
        res = self.one('recovery', ident=dict(d['ident'], recovery_us=5_000_001))
        self.assertGreater(res['recovery_s'], 5.0)

    def test_failed_recovery_is_a_recorded_result_not_a_crash(self):
        d = good_inputs()
        res = self.one('master', master=dict(d['master'], success=False, reads_completed=1))
        self.assertFalse(res['completed'])

    def test_duplicate_callbacks_fail_exactly_once(self):
        d = good_inputs()
        res = self.one('operate_real', ost=dict(d['ost'], operate_real=2))
        self.assertFalse(res['exactly_once'])

    def test_missing_callback_fails(self):
        d = good_inputs()
        self.one('select_real', ost=dict(d['ost'], select_real=0))

    def test_decoy_fails(self):
        d = good_inputs()
        self.one('decoy', ost=dict(d['ost'], operate_decoy=1))

    def test_bad_checksums_fail(self):
        d = good_inputs()
        self.one('checksum', wire=dict(d['wire'], returned_integrity={'dnp3_crc_bad': [], 'tcp_checksum_bad': [3]}))

    def test_spurious_unmatched_returned_segments_fail_but_duplicates_are_allowed(self):
        d = good_inputs()
        self.one('unmatched', wire=dict(d['wire'], unmatched_returned=[{'returned_index': 9}]))
        self.assertEqual(gate()[0], [])                         # duplicate_returned is [1] in the good inputs

    def test_growth_must_follow_exactly_once_delivery(self):
        d = good_inputs()
        t = copy.deepcopy(d['timing'])
        t['exchanges'][0]['resp_len'] = 49                      # a READ response delivered unpadded
        self.one('growth', timing=t)

    def test_padding_off_arm_expects_zero_growth(self):
        d = good_inputs()
        fails, res = loss.evaluate_loss({'padding': 0}, 3, 5.0, d['spec'], d['rule'], d['ident'], d['master'], d['ost'],
                                        d['wire'], clean_timing(padded=False), EXP)
        self.assertEqual(fails, [])
        self.assertEqual(res['growth_bytes'], 0)

    def test_pure_ack_drop_needs_no_retransmission(self):
        d = good_inputs()
        spec = loss.parse_drop('ack_sep:2', reads=3)
        rule = dict(d['rule'], dropped_bytes=40)
        ident = dict(d['ident'], retransmitted=None, recovery_us=None, progress_us=4700,
                     packet={'seq': 1, 'len': 0, 'ip_len': 40, 't_us': 5, 'ack': 1, 'index': 3})
        fails, res = loss.evaluate_loss({'padding': 1}, 3, 5.0, spec, rule, ident, d['master'], d['ost'], d['wire'],
                                        d['timing'], EXP)
        self.assertEqual(fails, [])
        self.assertEqual(res['progress_us'], 4700)


if __name__ == '__main__':
    unittest.main()


def translated(reads=3, close=True, retx_covered=None):
    """(out, in) as the rig records them. out.pcap: native stream (49 B READ responses). in.pcap: what the switch
    emitted toward each endpoint: outstation responses padded to 58 B in the padded sequence space, and master
    segments reverse-translated, so their ACKs are NATIVE. Each READ response is acknowledged by a master pure ACK
    (as the master does early in a connection), the next READ request carries the same ACK."""
    out, inn = [], []
    sseq, nseq, wseq = 1000, 5000, 5000
    for i in range(reads):
        t = 1_000_000 * (i + 1)
        req = tk.frame(M, O, MP, OP, sseq, nseq, PSHACK, tk.read_request(i))
        out.append((t, req)); inn.append((t + 50, req))
        sseq += 20
        native = tk.read_response(i, body_len=28)
        padded = tk.read_response(i, body_len=37)
        out.append((t + 5_000, tk.frame(O, M, OP, MP, nseq, sseq, PSHACK, native)))
        inn.append((t + 5_050, tk.frame(O, M, OP, MP, wseq, sseq, PSHACK, padded)))
        if retx_covered == i:
            out.append((t + 205_000, tk.frame(O, M, OP, MP, nseq, sseq, PSHACK, native)))
            inn.append((t + 205_050, tk.frame(O, M, OP, MP, wseq, sseq, PSHACK, padded)))
        nseq += len(native); wseq += len(padded)
        ack = tk.frame(M, O, MP, OP, sseq, nseq, ACK)          # master's ACK of the padded response, translated
        out.append((t + 5_500, ack)); inn.append((t + 5_550, ack))
    if close:
        t = 1_000_000 * (reads + 1)
        for fr, dt in ((tk.frame(O, M, OP, MP, nseq, sseq, tk.FIN | ACK), 0),
                       (tk.frame(M, O, MP, OP, sseq, nseq + 1, ACK), 300)):
            out.append((t + dt, fr)); inn.append((t + dt + 50, fr))
    return out, inn


class DataAck(unittest.TestCase):
    """master_ack_of_padded_data: the dropped packet must be an in-session master pure ACK of a padded frontier,
    on captures translated as the rig records them (native ACKs and padded outstation data in in.pcap)."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def ident(self, text, out, inn):
        spec = loss.parse_drop(text, reads=3)
        return spec, loss.identify(*write(self.tmp, out, inn), spec, MP, OP)

    def test_in_session_data_ack_is_identified_and_covered(self):
        spec, ident = self.ident('master_ack_of_padded_data:1', *translated())
        self.assertTrue(spec['data_ack'])
        self.assertTrue(ident['identified'])
        self.assertTrue(ident['covers_padded_frontier'])
        self.assertEqual(ident['covered_segment']['ip_len'], 89)
        self.assertEqual(ident['delivered_segment']['ip_len'], 98)
        self.assertTrue(ident['before_fin'])
        self.assertEqual(ident['recovery_mechanism'], 'cumulative_ack')
        self.assertFalse(ident['covered_retransmitted'])
        self.assertIsNotNone(ident['progress_us'])
        fails, res = gate(spec=spec, ident=ident, rule=dict(good_inputs()['rule'], dropped_bytes=40))
        self.assertEqual(fails, [])
        self.assertEqual(res['recovery_mechanism'], 'cumulative_ack')

    def test_untranslated_comparison_would_miss(self):
        # The ACK equals the end of the NATIVE segment, not of the padded one delivered in in.pcap.
        _, ident = self.ident('master_ack_of_padded_data:1', *translated())
        self.assertNotEqual(ident['packet']['ack'], (ident['delivered_segment']['seq'] + 58) & 0xFFFFFFFF)

    def test_ack_of_fin_is_rejected(self):
        spec, ident = self.ident('master_ack_of_padded_data:3', *translated())
        self.assertTrue(ident['identified'])
        self.assertFalse(ident['covers_padded_frontier'])
        self.assertFalse(ident['before_fin'])
        fails, _ = gate(spec=spec, ident=ident, rule=dict(good_inputs()['rule'], dropped_bytes=40))
        self.assertTrue(any('padded data frontier' in f for f in fails), fails)
        self.assertTrue(any('not in session' in f for f in fails), fails)

    def test_unpadded_delivery_is_not_a_padded_frontier(self):
        out, inn = translated()
        inn = [(t, f) for t, f in out]          # switch delivered native bytes: padding off
        _, ident = self.ident('master_ack_of_padded_data:1', out, inn)
        self.assertTrue(ident['identified'])
        self.assertFalse(ident['covers_padded_frontier'])

    def test_retransmission_recovery_is_recorded(self):
        spec, ident = self.ident('master_ack_of_padded_data:1', *translated(retx_covered=1))   # n=1 is the 2nd master pure ACK (offset 1 skips the handshake ACK)
        self.assertTrue(ident['covers_padded_frontier'])
        self.assertTrue(ident['covered_retransmitted'])

    def test_old_class_keeps_occurrence_only_semantics(self):
        spec, ident = self.ident('master_ack_of_padded:3', *translated())
        self.assertFalse(spec['data_ack'])
        fails, _ = gate(spec=spec, ident=ident, rule=dict(good_inputs()['rule'], dropped_bytes=40))
        self.assertFalse(any('padded data frontier' in f for f in fails), fails)


class StrictControls(unittest.TestCase):
    """control_padding False (strict-response builds): SELECT/OPERATE responses stay native and add no growth."""

    def strict_timing(self):
        t = clean_timing()
        for e in t['exchanges']:
            if e['kind'] in ('SELECT', 'OPERATE'):
                e['resp_len'] = 37
        return t

    def test_growth_counts_reads_only(self):
        self.assertEqual(loss._growth(self.strict_timing(), True, control_padding=False), (27, 27))
        self.assertEqual(loss._growth(self.strict_timing(), True)[1], 27 + 42)

    def test_gate_accepts_native_controls_only_when_declared(self):
        d = good_inputs()
        arm = {'padding': 1, 'control_padding': 0}
        fails, res = loss.evaluate_loss(arm, 3, 5.0, d['spec'], d['rule'], d['ident'], d['master'], d['ost'],
                                        d['wire'], self.strict_timing(), EXP, baseline_completion_s=2.5)
        self.assertFalse(any('growth' in f for f in fails), fails)
        fails, _ = loss.evaluate_loss({'padding': 1}, 3, 5.0, d['spec'], d['rule'], d['ident'], d['master'], d['ost'],
                                      d['wire'], self.strict_timing(), EXP, baseline_completion_s=2.5)
        self.assertTrue(any('growth 27 B != 69 B' in f for f in fails), fails)

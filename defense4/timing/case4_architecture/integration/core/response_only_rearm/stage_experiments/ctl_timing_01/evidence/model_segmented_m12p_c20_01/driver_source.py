"""Compiled-model gate for the segmented READ 377 -> 401 response through the c20 build (--segmented-full).

The large-DB integrity/class0 READ response is two DNP3 link frames carried as two TCP segments: seg0
(FIR, link LEN 255, 292 B) and seg1 (FIN continuation, link LEN 70, 85 B) = 377 B. The pipe-1 egress padder
prepends a 24-B synthetic FIR frame to seg0 (carrying the moved application header + the padding-object header),
rewrites block 0 of both frames (transport renumber + recomputed block-0 CRCs; seg0 also moves its 4 app-header
bytes to the last 4 padding points), and grows seg0 by 24 -> the wire image is [24+292, 85] = 401 B.

Samples come from read_complete_01/vectors/segmented_vectors.json, precomputed under the research Python by
make_segmented_vectors.py (the model driver runs under the system Python 3.8, which cannot import derive.py).
Each sample's `expected` is derive.construct(native) cross-checked == general_read_padding.pad_read, and each
frame is pre-addressed to the model connection (response dst=master 0x0001 / src=outstation 0x0000, matching
model_packets.read_frame; request the reverse), so N's link guard admits it.

MEASURED on the c20 model (this driver, SEG_DIAG run model_segmented_m12p_c20_91): the pipe-1 padder pads and
forwards the FIRST segment correctly -- seg0 (native 292 B, ip.len 332) leaves as the 316-B image (24-B prefix +
rewritten frame) at the wire-start TCP seq, via E out_translate + the padder (p1_outcome.p1_padded). The SECOND
segment is NOT forwarded: seg1 (85 B, ip.len 125, FIN) is admitted by N's parser (read_response_fb, kind=11) but
dropped in N's pipe-0 ingress control before egress -- 0 egress frames, no E outcome code moves, p1_outcome does
not change, and neither N count_busy nor the T outcomes register bump. So the current c20 build delivers only the
padded first segment; the end-to-end two-segment 401 image is NOT delivered. The continuation-forwarding path
(N's read lane recognizing seg1 as the second segment of one in-progress response, after seg0 consumed the read)
is the open gap -- the forward two-frame single-commit the code review flagged as unexercised is not functional.

This driver therefore ASSERTS what is demonstrated -- seg0 is admitted and padded to the exact 316-B image at the
wire-start seq over several samples, and the request/server-ACK map correctly -- and RECORDS seg1 as a disclosed
OPEN finding (measured 0 frames), never as a silent pass. It is NOT in the enforced 13-driver model gate because
the segmented class is not end-to-end functional yet. Timing is disabled (size/encoding tier); T's two-child
hold/release ordering is separate and also pending. seg1 admission is content-blind (dl.len==0x46 && FIN).
Run: python3 run_model.py <build> segmented N --milestone m12   (SEG_DIAG=1 for the counter localization)
"""
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
sys.path[:0] = [str(HERE)]
import model_packets as mp  # noqa: E402

std = mp.std
VECS = json.loads((HERE.parent / 'read_complete_01/vectors/segmented_vectors.json').read_text())
NATIVE_TOTAL = VECS['native_total']          # 377
TARGET = VECS['target']                      # 401
PREFIX_LEN = VECS['prefix_frame_len']        # 24
PAD_FIRST = VECS['reserved_first_index']     # 1024
NPAD = VECS['padding_points']                # 4


def split_frames(stream):
    """Walk the DNP3 link frames in a byte stream (3.8-safe local copy of general_read_padding.split_frames);
    deframe() independently verifies every block CRC of each frame."""
    frames, pos = [], 0
    while pos < len(stream):
        assert len(stream) - pos >= 10 and stream[pos:pos + 2] == b'\x05\x64', 'bad link header at %d' % pos
        size = std.frame_length(stream[pos + 2] - 5)
        f = stream[pos:pos + size]
        std.deframe(f)
        frames.append(f)
        pos += size
    assert frames, 'empty stream'
    return frames


class SegmentedGate(mp.PacketGate):
    def _capture(self, name, sent, reverse, expect_payload, expect_count=1):
        """Send one packet; assert exactly expect_count egress frames and (for one) that its TCP payload equals
        expect_payload. Records the observed TCP seq/ack. Returns the captured frame (or None)."""
        self.captures['sent'].append((time.time_ns() // 1000, sent))
        got = self.m.exchange(self.relay.dev_port if reverse else self.master.dev_port,
                              sent, self.ports, timeout=3, quiet=.15)
        flat = [f for frames in got.values() for f in frames]
        self.captures['received'].extend((time.time_ns() // 1000, f) for f in flat)
        if len(flat) != expect_count:
            self.add(name + '_frame_count', expect_count, len(flat), received=got)
            return None
        if expect_count == 0:
            return None
        frame = flat[0]
        payload = mp.tcp_payload(frame)
        self.add(name + '_payload', expect_payload.hex(), payload.hex(),
                 seq=mp.tcp_seq(frame), ack=mp.tcp_ack(frame), payload_len=len(payload))
        mp.assert_ip_tcp(frame)
        return frame

    def segmented_response(self, name, cseq, nsq, wsq, native, expected):
        """Inject the two response segments (reverse). ASSERT seg0 is padded to the exact 316-B image at the wire
        start; RECORD seg1 as a disclosed OPEN finding (it is dropped in N ingress, measured 0 frames)."""
        frames = split_frames(native)
        assert len(frames) == 2 and sum(len(f) for f in frames) == NATIVE_TOTAL, [len(f) for f in frames]
        f0, f1 = frames
        self.add(name + '_expected_total', TARGET, len(expected))
        exp0 = expected[:len(f0) + PREFIX_LEN]
        # seg0: admitted and padded to the 316-B first image at the wire-start seq -- this MUST hold.
        g0 = self._capture(name + '_seg0_padded', self.v.packet(24, nsq, cseq, reverse=True, payload=f0), True, exp0)
        if g0 is not None:
            self.add(name + '_seg0_seq', wsq, mp.tcp_seq(g0))
        # seg1: continuation forwarding is the OPEN gap. Record the measured egress-frame count without asserting
        # it forwards; flag non-delivery explicitly so nothing reads this as a pass of the segmented class.
        self.captures['sent'].append((time.time_ns() // 1000, self.v.packet(24, nsq + len(f0), cseq, reverse=True, payload=f1)))
        got = self.m.exchange(self.relay.dev_port, self.v.packet(24, nsq + len(f0), cseq, reverse=True, payload=f1),
                              self.ports, timeout=3, quiet=.15)
        flat = [f for frames2 in got.values() for f in frames2]
        self.captures['received'].extend((time.time_ns() // 1000, f) for f in flat)
        self._seg1_frames.append(len(flat))
        self.report.add(name + '_seg1_continuation_OPEN', 'not forwarded in c20 (N ingress drop)',
                        'egress_frames=%d' % len(flat), ok=True, egress_frames=len(flat),
                        out_lens=[len(mp.tcp_payload(f)) for f in flat])
        return (nsq + NATIVE_TOTAL) & 0xffffffff, (wsq + TARGET) & 0xffffffff

    def transaction(self, name, cseq, nsq, wsq, sample):
        """One segmented READ: request -> server ACK -> two-segment response. The request arms N's read path (a
        cold response has no outstanding read and is dropped)."""
        req = bytes.fromhex(sample['request'])
        native, expected = bytes.fromhex(sample['native']), bytes.fromhex(sample['expected'])
        qlen = len(req)
        self._capture(name + '_request', self.v.packet(24, cseq, wsq, payload=req), False,
                      mp.tcp_payload(self.v.packet(24, cseq, nsq, payload=req)))
        self._capture(name + '_server_ack', self.v.packet(16, nsq, cseq + qlen, reverse=True), True,
                      mp.tcp_payload(self.v.packet(16, wsq, cseq + qlen, reverse=True)))
        nsq2, wsq2 = self.segmented_response(name, cseq + qlen, nsq, wsq, native, expected)
        return cseq + qlen, nsq2, wsq2

    def run_gate(self, n=1):
        """Assert seg0 padding and record seg1 continuation as the open gap for a representative segmented READ.
        One transaction on one connection: because seg1 is not delivered, the switch's post-response seq state
        cannot be predicted, so neither a mapped FIN close nor a second transaction/connection on the fixed
        MASTER/RELAY 4-tuple stays in sync (each desync is itself a symptom of the open gap). The construction's
        byte-exactness across 512 varied natives is proved separately at the interpreter tier (derive.py + the
        m12_fullsize segmented tests); this gate shows the COMPILED behaviour on the exact c20 image."""
        for k in range(n):
            base = 4000 + 400 * k
            cseq, nsq, wsq = self.handshake(base, base + 300, 'seg%02d_' % k)
            self.transaction('seg_%03d' % k, cseq, nsq, wsq, VECS['samples'][k % len(VECS['samples'])])
        # Deterministic summary of the open gap: seg1 was dropped on EVERY transaction (0 egress frames each).
        self.add('seg1_continuation_consistently_not_forwarded', [0] * len(self._seg1_frames), self._seg1_frames)

    def _counter(self, table_name, n):
        """Read a PACKETS Counter's per-index totals (the e_counts pattern in model_drive_composite)."""
        gc = self.h.gc
        counter = self.m.table(table_name)
        for op in ('Sync', 'SyncCounters'):
            try:
                counter.operations_execute(self.m.target, op)
                break
            except Exception:
                pass
        got = {}
        for code in range(n):
            try:
                for data, _k in counter.entry_get(self.m.target,
                                                  [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])],
                                                  {'from_hw': True}):
                    v = data.to_dict()['$COUNTER_SPEC_PKTS']
                    v = sum(v) if isinstance(v, list) else v
                    if v:
                        got[code] = v
            except Exception as exc:
                got['%d_err' % code] = str(exc)[:80]
        return got

    def _ecounts(self):
        enames = {1: 'COMMIT', 2: 'TRANSLATE', 3: 'ZERO', 4: 'REPLAY', 5: 'STALE', 6: 'DROP_OVERLAP',
                  7: 'DROP_AHEAD', 8: 'DROP_ODD', 9: 'REV_TRANSLATE', 10: 'REV_WITHHOLD', 11: 'REV_DROP_STALE',
                  12: 'NATIVE', 15: 'DROP_MERGED', 16: 'RESET_FRONT'}
        e = {enames.get(k, k): v for k, v in self._counter('p0.r_Egress.outcome', 32).items()}
        pn = {0: 'p1_0', 1: 'p1_padded', 2: 'p1_connfail', 3: 'p1_pass'}
        p1 = {pn.get(k, k): v for k, v in self._counter('p1.x_Egress.p1_outcome', 4).items()}
        # N busy counter (0 drop,1 pass,2 retry,3 exhausted,4 retry_stale,5 reset) and T outcomes register
        bn = {0: 'N_busy_drop', 1: 'N_busy_pass', 2: 'N_busy_retry', 3: 'N_busy_exhausted', 4: 'N_retry_stale', 5: 'N_reset'}
        n = {}
        for i, nm in bn.items():
            try:
                v = self.m.register_read('p0.n_Ingress.count_busy', i)
                v = v if isinstance(v, int) else self.h.scalar(v)
                if v:
                    n[nm] = v
            except Exception as exc:
                n[nm + '_err'] = str(exc)[:60]
        e.update(n)
        tnames = ['UNMATCHED', 'HELD_REWAIT', 'ACK_COMMIT', 'RESP_RELEASE', 'RESP_DUP_DROP', 'OP_RELEASE',
                  'TOKEN_STALE', 'HELD_STALE_FLUSH', 'ACK_FALLBACK', 'RESP_FALLBACK', 'TOKEN_TMO', 'HELD_OFF_FLUSH',
                  'TOKEN_OFF', 'REQ_BYPASS', 'OLD_EPOCH_DROP', 'GEN_EXHAUSTED', 'OP_DUP_DROP']
        for i, nm in enumerate(tnames):
            try:
                v = self.m.register_read('p1.t_Ingress.outcomes', i, pipe=1)
                v = v if isinstance(v, int) else self.h.scalar(v)
                if v:
                    p1['T_' + nm] = v
            except Exception:
                pass
        return e, p1

    def run_diag(self):
        """Non-aborting: inject ONE segmented transaction and record every capture + the E/p1 outcome counters,
        to localize where seg1 goes (E out_drop reason vs the pipe-1 padder)."""
        cseq, nsq, wsq = self.handshake(4000, 4800, 'diag_')
        s = VECS['samples'][0]
        req, native, expected = bytes.fromhex(s['request']), bytes.fromhex(s['native']), bytes.fromhex(s['expected'])
        f0, f1 = split_frames(native)
        qlen = len(req)
        for label, sent, rev in (('request', self.v.packet(24, cseq, wsq, payload=req), False),
                                 ('server_ack', self.v.packet(16, nsq, cseq + qlen, reverse=True), True),
                                 ('seg0', self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=f0), True),
                                 ('seg1', self.v.packet(24, nsq + len(f0), cseq + qlen, reverse=True, payload=f1), True)):
            got = self.m.exchange(self.relay.dev_port if rev else self.master.dev_port, sent, self.ports, timeout=3, quiet=.15)
            flat = [f for frames in got.values() for f in frames]
            e, p1 = self._ecounts()
            self.report.add('diag_' + label, 'see_extra', len(flat), ok=True,
                            out_frames=len(flat), out_lens=[len(mp.tcp_payload(f)) for f in flat],
                            out_seqs=[mp.tcp_seq(f) for f in flat], E=e, P1=p1)

    def run(self):
        self._seg1_frames = []
        if os.environ.get('SEG_DIAG'):
            self.run_diag()
            return
        self.run_gate()


def model_main():
    h = mp.load('_seg_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_seg_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False,
                      scope='m12 segmented READ 377->401 compiled-model gate (size/encoding/mapping)',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    report.record['meta']['segmented_vectors_sha256'] = hashlib.sha256(
        (HERE.parent / 'read_complete_01/vectors/segmented_vectors.json').read_bytes()).hexdigest()
    gate = None
    try:
        gate = SegmentedGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.configure()
        gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    if gate is not None:
        import pcaptk
        for name, packets in gate.captures.items():
            pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
    return 0 if report.finish(out / 'segmented_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(model_main())

"""Compiled-model robustness gate for the two-READ-target build (m12p_c24+): retransmission, corruption, the replaced
READ classes, and reset/reconnect, for the mixed (91 -> 141) and full (247 -> 271) READs. Timing disabled (T off), as
the policy gate: this is the size/mapping/admission tier; timing and J are model_control_timing's.

Workload frames are the hardware endpoint's own captures (two_read_templates.json) re-addressed to the model
connection (model_policy.PolicyGate.two_read_frames). Every expectation of a padded image is rp.construct(native),
the derivation proved byte-equal to general_read_padding.pad_read; every emitted frame is compared byte-exact (IP and
TCP checksums included, so the compiled deparser's checksum is checked) or decoded independently.

Cases (each asserts SAFETY strictly and RECORDS the disposition; a disposition is compared with the range READ of the
same build as the control where one exists):
  R  retransmission: after a padded READ response is committed and before the master ACKs it, the outstation
     retransmits the same native segment. Safety: any copy toward the master is EXACTLY the padded image at the
     image's wire start (a valid TCP retransmission), never the native, never another size. The range READ (native
     49) is the control.
  C  corruption, each separately, then the good response: (1) a corrupted block-0 measurement octet with a valid TCP
     checksum, (2) a valid DNP3 response with a bad TCP checksum, (3) a corrupted block-1 octet (tail DNP3 CRC wrong)
     with a valid TCP checksum. Safety: corruption is never laundered -- (1) must not leave the switch with a valid
     block-0 CRC; (2) any copy must still fail its TCP checksum; (3) any copy must still fail the tail DNP3 CRC (the
     shallow response path does not validate the tail: a recorded limitation). The good response afterwards must be
     delivered exactly once as the exact padded image.
  X  replaced classes: an analog and a class0 READ request (not admitted by this build) on a connection carrying
     padded READs is WITHHELD, also when retransmitted -- nothing reaches either side -- and a mixed and a full READ
     at the same client sequence afterwards still pad and map exactly (the connection state is untouched).
  Z  reset/reconnect: the master's RST|ACK acknowledging a padded image reaches the outstation with the ACK mapped
     to native, then a new connection on the same 4-tuple at a fresh ISN carries a mixed and a full READ exactly.
  B  (recorded, not asserted; run last) a bare RST (no ACK flag) after an unacknowledged padded response.
Run: python3 run_model.py <build> two_read_robust N --milestone m12
"""
import hashlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
sys.path[:0] = [str(HERE)]
import model_packets as mp  # noqa: E402
import model_policy as pol  # noqa: E402

std = mp.std


def tail_crc_ok(frame_bytes):
    """True when every link frame of a DNP3 stream deframes (all block CRCs valid)."""
    try:
        for f in mp.rp.split_frames(frame_bytes):
            std.deframe(f)
        return True
    except Exception:
        return False


class RobustGate(pol.PolicyGate):
    def _send(self, name, pkt, reverse):
        """Send one packet; return the frames that left toward the master and toward the outstation."""
        got = self.m.exchange(self.relay.dev_port if reverse else self.master.dev_port, pkt, self.ports,
                              timeout=3, quiet=.2)
        self.captures['sent'].append((0, pkt))
        flat = [f for frames in got.values() for f in frames]
        self.captures['received'].extend((0, f) for f in flat)
        to_master = [f for p, frames in got.items() if int(p) == self.master.dev_port for f in frames]
        to_out = [f for p, frames in got.items() if int(p) == self.relay.dev_port for f in frames]
        return to_master, to_out

    def _request(self, name, cls, cseq, nsq, wsq, k):
        request, native = self.two_read_frames(cls, k, k & 63)
        qlen = len(request)
        self.exchange(name + '_request', self.v.packet(24, cseq, wsq, payload=request),
                      self.v.packet(24, cseq, nsq, payload=request))
        self.exchange(name + '_server_ack', self.rs.ack_packet(seq=nsq, ack=cseq + qlen),
                      self.rs.ack_packet(seq=wsq, ack=cseq + qlen), reverse=True)
        return request, native, qlen

    # ---- R: retransmission ----------------------------------------------------------------------------------
    def case_retransmission(self, cls, isn, k):
        tag = 'R_%s' % cls
        cseq, nsq, wsq = self.handshake(isn, isn + 800, tag + '_')
        request, native, qlen = self._request(tag, cls, cseq, nsq, wsq, k)
        image = mp.rp.construct(native)
        sent = self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native)
        want = self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image)
        self.exchange(tag + '_response', sent, want, reverse=True)
        to_master, _ = self._send(tag + '_retransmission', sent, True)
        # the master has not acknowledged the image yet, so recovery needs the retransmission forwarded: at least
        # one copy, every copy the exact padded image (zero copies is a failure, never a vacuous pass)
        exact = bool(to_master) and all(self.h.same_frame(f, want, sent) for f in to_master)
        self.report.add(tag + '_retransmission_safe', '>= 1 copy, every copy == the exact padded image at the wire start',
                        'copies %d, all exact %s' % (len(to_master), exact), ok=exact,
                        disposition='replayed' if to_master else 'not forwarded', copies=len(to_master))
        self.report.record['meta'].setdefault('retransmission', {})[cls] = len(to_master)
        self.exchange(tag + '_mapped_ack', self.v.packet(16, cseq + qlen, wsq + len(image)),
                      self.v.packet(16, cseq + qlen, nsq + len(native)))
        self.close(cseq + qlen, nsq + len(native), wsq + len(image), tag + '_close')

    def case_retransmission_range_control(self, isn):
        tag = 'R_range_control'
        cseq, nsq, wsq = self.handshake(isn, isn + 800, tag + '_')
        request = self.rs.request_packet(seq=cseq, ack=wsq, app=0xc0)
        self.exchange(tag + '_request', request, self.rs.request_packet(seq=cseq, ack=nsq, app=0xc0))
        self.exchange(tag + '_server_ack', self.rs.ack_packet(seq=nsq, ack=cseq + 20),
                      self.rs.ack_packet(seq=wsq, ack=cseq + 20), reverse=True)
        native = mp.read_frame(0, list(range(23)), app=0xc0)
        sent = self.v.packet(24, nsq, cseq + 20, reverse=True, payload=native)
        self.exchange(tag + '_response', sent, self.v.packet(24, wsq, cseq + 20, reverse=True, payload=native), reverse=True)
        to_master, _ = self._send(tag + '_retransmission', sent, True)
        want = self.v.packet(24, wsq, cseq + 20, reverse=True, payload=native)
        exact = bool(to_master) and all(self.h.same_frame(f, want, sent) for f in to_master)
        self.report.add(tag + '_retransmission_safe', '>= 1 copy, every copy == the native 49 at the wire start',
                        'copies %d, all exact %s' % (len(to_master), exact), ok=exact,
                        disposition='replayed' if to_master else 'not forwarded', copies=len(to_master))
        self.report.record['meta'].setdefault('retransmission', {})['range_control'] = len(to_master)
        self.close(cseq + 20, nsq + 49, wsq + 49, tag + '_close')

    # ---- C: corruption ----------------------------------------------------------------------------------------
    def case_corruption(self, cls, kind, isn, k):
        tag = 'C_%s_%s' % (cls, kind)
        cseq, nsq, wsq = self.handshake(isn, isn + 800, tag + '_')
        request, native, qlen = self._request(tag, cls, cseq, nsq, wsq, k)
        image = mp.rp.construct(native)
        good = self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native)
        want = self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image)
        if kind == 'block0_point':
            bad_payload = bytearray(native)
            bad_payload[10 + 12] ^= 0x01                       # a measurement octet in block 0; its CRC left stale
            bad = self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=bytes(bad_payload))
        elif kind == 'tail_crc':
            bad_payload = bytearray(native)
            bad_payload[10 + 18 + 3] ^= 0x01                   # a block-1 data octet; its CRC left stale
            bad = self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=bytes(bad_payload))
        elif kind == 'tcp_checksum':
            bad = bytearray(good)
            bad[14 + 20 + 16] ^= 0x01                          # TCP checksum octet; DNP3 untouched
            bad = bytes(bad)
        else:
            raise ValueError(kind)
        to_master, _ = self._send(tag + '_corrupt', bad, True)
        if kind == 'tcp_checksum':
            laundered = [f for f in to_master if mp.wire_check.ip_tcp_checksum({'frame': f})[1]]
            what = 'no copy with a VALID TCP checksum (the corruption is not laundered)'
        elif kind == 'block0_point':
            laundered = [f for f in to_master if tail_crc_ok(mp.tcp_payload(f))]
            what = 'no copy whose DNP3 CRCs all verify (block-0 corruption is not laundered)'
        else:
            laundered = [f for f in to_master if tail_crc_ok(mp.tcp_payload(f))]
            what = 'no copy whose tail DNP3 CRC verifies (the tail corruption is not laundered)'
        self.report.add(tag + '_not_laundered', what, 'copies %d, laundered %d' % (len(to_master), len(laundered)),
                        ok=not laundered, disposition='forwarded' if to_master else 'refused', copies=len(to_master),
                        copy_lens=[len(mp.tcp_payload(f)) for f in to_master])
        self.report.record['meta'].setdefault('corruption', {})[tag] = dict(
            copies=len(to_master), lens=[len(mp.tcp_payload(f)) for f in to_master])
        # the good response afterwards: delivered exactly once as the exact padded image
        to_master, _ = self._send(tag + '_good_after', good, True)
        ok = len(to_master) == 1 and self.h.same_frame(to_master[0], want, good)
        self.report.add(tag + '_good_after_delivered_exact', 'one exact padded image', 'copies %d' % len(to_master),
                        ok=ok, copies=len(to_master))
        self.exchange(tag + '_mapped_ack', self.v.packet(16, cseq + qlen, wsq + len(image)),
                      self.v.packet(16, cseq + qlen, nsq + len(native)))
        self.close(cseq + qlen, nsq + len(native), wsq + len(image), tag + '_close')

    # ---- X: replaced classes forwarded natively ---------------------------------------------------------------
    def case_replaced_classes(self, isn):
        """The analog and class0 READs are not admitted on this build (their N admission was replaced to place the
        two READ targets; read_complete_01/STATUS.md, c23). Their disposition on an admitted connection: the request is
        withheld -- nothing reaches the outstation or returns to the master, also when the master retransmits it --
        and the connection's state is untouched, so a supported READ at the same client sequence still pads
        byte-exact. A real master's retransmissions of the withheld request are withheld too, so such a connection
        stalls until its application times out: these shapes are unsupported, never forwarded as if supported."""
        tag = 'X'
        cseq, nsq, wsq = self.handshake(isn, isn + 800, tag + '_')
        cseq, nsq, wsq = self.two_read_exchange(tag + '_mixed_before', 'mixed', cseq, nsq, wsq, 0)
        for cls in ('analog', 'class0'):
            t = pol.TEMPLATES[cls]
            request = pol.resequence(bytes.fromhex(t['request']), 0, 0xC0 | 5, dst=0x0000, src=0x0100)
            for attempt in ('request', 'request_retransmitted'):
                to_master, to_out = self._send('%s_%s_%s' % (tag, cls, attempt),
                                               self.v.packet(24, cseq, wsq, payload=request), False)
                self.report.add('%s_%s_%s_withheld' % (tag, cls, attempt), 'nothing forwarded either way',
                                'to_outstation %d, to_master %d' % (len(to_out), len(to_master)),
                                ok=not to_out and not to_master)
        cseq, nsq, wsq = self.two_read_exchange(tag + '_mixed_after', 'mixed', cseq, nsq, wsq, 1)
        cseq, nsq, wsq = self.two_read_exchange(tag + '_full_after', 'integrity', cseq, nsq, wsq, 2)
        self.close(cseq, nsq, wsq, tag + '_close')

    # ---- Z: reset and reconnect -------------------------------------------------------------------------------
    def case_reset_reconnect(self, isn):
        """The master resets after a padded response, as a Linux master does (RST|ACK acknowledging what it received,
        here the whole padded image; ss -K in the persistence_rst hardware block): the reset reaches the outstation
        with its acknowledgement mapped back to native coordinates, and a new connection then carries both READs
        byte-exact."""
        tag = 'Z'
        cseq, nsq, wsq = self.handshake(isn, isn + 800, tag + '_')
        request, native, qlen = self._request(tag, 'mixed', cseq, nsq, wsq, 3)
        image = mp.rp.construct(native)
        self.exchange(tag + '_response', self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native),
                      self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image), reverse=True)
        self.exchange(tag + '_master_RST_ACK', self.v.packet(20, cseq + qlen, wsq + len(image)),
                      self.v.packet(20, cseq + qlen, nsq + len(native)))
        cseq, nsq, wsq = self.handshake(isn + 100000, isn + 100800, tag + '_new_')
        cseq, nsq, wsq = self.two_read_exchange(tag + '_new_mixed', 'mixed', cseq, nsq, wsq, 4)
        cseq, nsq, wsq = self.two_read_exchange(tag + '_new_full', 'integrity', cseq, nsq, wsq, 5)
        self.close(cseq, nsq, wsq, tag + '_new_close')

    def characterize_bare_rst(self, isn):
        """RECORDED, NOT ASSERTED (run last: it can leave the connection state wedged). A bare RST (no ACK flag, as a
        kernel sends for a segment arriving at a closed socket) after an unacknowledged padded response: whether it
        is forwarded, and whether a following connection on the same tuple is admitted."""
        tag = 'B'
        cseq, nsq, wsq = self.handshake(isn, isn + 800, tag + '_')
        request, native, qlen = self._request(tag, 'mixed', cseq, nsq, wsq, 6)
        image = mp.rp.construct(native)
        self.exchange(tag + '_response', self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native),
                      self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image), reverse=True)
        _m, to_out = self._send(tag + '_bare_RST', self.v.packet(4, cseq + qlen, 0), False)
        _m2, syn_out = self._send(tag + '_new_SYN', self.v.packet(2, isn + 100000, mss=1460), False)
        synack_m, _o = self._send(tag + '_new_SYNACK', self.v.packet(18, isn + 100800, isn + 100001, reverse=True,
                                                                     mss=1460), True)
        observed = {'rst_to_outstation': len(to_out), 'new_syn_to_outstation': len(syn_out),
                    'new_synack_to_master': len(synack_m)}
        self.report.add(tag + '_bare_RST_characterization', 'recorded (not asserted)', observed, ok=True, **observed)
        self.report.record['meta']['bare_rst_characterization'] = observed

    def run(self):
        if not pol.TWO_READ:
            raise AssertionError('model_two_read_robust needs a two-READ-target build')
        isn = 40000
        for cls, k in (('mixed', 1), ('integrity', 2)):
            self.case_retransmission(cls, isn, k); isn += 5000
        self.case_retransmission_range_control(isn); isn += 5000
        for cls, k in (('mixed', 3), ('integrity', 4)):
            for kind in ('block0_point', 'tcp_checksum', 'tail_crc'):
                self.case_corruption(cls, kind, isn, k); isn += 5000
        self.case_replaced_classes(isn); isn += 5000
        self.case_reset_reconnect(isn); isn += 200000
        self.characterize_bare_rst(isn)


def model_main():
    h = mp.load('_robust_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = mp.load('_robust_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False,
                      scope='two-READ-target robustness: retransmission, corruption, replaced classes, reset (T off)',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = RobustGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.configure()
        gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    if gate is not None:
        import pcaptk
        for name, packets in gate.captures.items():
            pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
    return 0 if report.finish(out / 'robust_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(model_main())

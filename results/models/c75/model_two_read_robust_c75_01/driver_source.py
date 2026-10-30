"""Current two-READ robustness: retransmission, corruption, unsupported classes, reset and reconnect."""
import hashlib
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
REARM = HERE
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent.parent / 'checks'), str(Path(__file__).resolve().parent.parent / 'hardware')]
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
        mp.rp.advance_timestamp()
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
        if mp.rp.TCP_TIMESTAMPS:
            fresh = self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native)
            fresh_want = mp.rp.preserve_options(fresh, self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image))
            copies, _ = self._send(tag + '_new_timestamp_retransmission', fresh, True)
            self.add(tag + '_new_timestamp_exact_retransmission', True,
                     bool(copies) and all(self.h.same_frame(f, fresh_want, fresh) for f in copies)
                     and mp.rp.timestamp_values(fresh)[0] > mp.rp.timestamp_values(sent)[0])
        self.exchange(tag + '_mapped_ack', self.v.packet(16, cseq + qlen, wsq + len(image)),
                      self.v.packet(16, cseq + qlen, nsq + len(native)))
        self.close(cseq + qlen, nsq + len(native), wsq + len(image), tag + '_close')

    def case_retransmission_range_control(self, isn):
        if mp.rp.SEL751:
            # Both admitted relay READs pad; integrity is the independent
            # retransmission control for the mixed workload.
            return self.case_retransmission('integrity', isn, 1)
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
        qualified = []
        for frame in to_master:
            try:
                ip_ok, tcp_ok, _ = mp.wire_check.ip_tcp_checksum({'frame': frame})
                mp.rp.check_read_image(native, mp.tcp_payload(frame))
                if ip_ok and tcp_ok:
                    qualified.append(frame)
            except (AssertionError, ValueError):
                pass
        self.add(tag + '_no_receiver_qualified_corrupt_response', 0, len(qualified))
        self.report.record['meta']['corruption_scope'] = (
            'receiver-visible TCP/DNP3 validity; shallow switch admission may forward invalid tails')
        # the good response afterwards: delivered exactly once as the exact padded image
        if mp.rp.TCP_TIMESTAMPS:
            good = self.v.packet(24, nsq, cseq + qlen, reverse=True, payload=native)
            want = mp.rp.preserve_options(good, self.v.packet(24, wsq, cseq + qlen, reverse=True, payload=image))
        to_master, _ = self._send(tag + '_good_after', good, True)
        ok = len(to_master) == 1 and self.h.same_frame(to_master[0], want, good)
        self.report.add(tag + '_good_after_delivered_exact', 'one exact padded image', 'copies %d' % len(to_master),
                        ok=ok, copies=len(to_master))
        if ok:
            mp.assert_ip_tcp(to_master[0])
            mp.rp.check_read_image(native, mp.tcp_payload(to_master[0]))
            if mp.rp.TCP_TIMESTAMPS:
                self.add(tag + '_valid_retransmission_new_timestamp', True,
                         mp.rp.timestamp_values(to_master[0])[0] > mp.rp.timestamp_values(bad)[0])
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
        excluded = ('range', 'analog', 'class0') if mp.rp.SEL751 else ('analog', 'class0')
        for cls in excluded:
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
    h = mp.load('_robust_helpers', HERE / 'model_drive_composite.py')
    cp = mp.load('_robust_cp', HERE / 'cp.py')
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

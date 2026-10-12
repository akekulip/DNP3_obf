#!/usr/bin/env python3
"""Source-level parity checks for the N CRC-residue experiment."""
import copy
import importlib.util
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
ARCH = REARM.parents[1]
sys.path[:0] = [str(REARM), str(ARCH / "core" / "harness"),
                str(ARCH / "connection" / "binding" / "tests"),
                str(ARCH / "read" / "tests")]

import baseline  # noqa: E402
import cp  # noqa: E402
from interpreter import ESource, checksum_oracle, source_text  # noqa: E402
import queue_sim as qs  # noqa: E402
import read_support as rs  # noqa: E402
import vectors  # noqa: E402


SOURCE = HERE / "evidence" / "response_only_residue.p4"


def local_module(name):
    spec = importlib.util.spec_from_file_location("residue_" + name, REARM / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


make_e = local_module("make_e")
make_t = local_module("make_t")


def n_text():
    text = SOURCE.read_text()
    start = text.index("struct n_expected_work_cell_t")
    end = text.index("parser n_EgParser(")
    n = text[start:end]
    n = re.sub(r"\bn_", "", n)
    n = n.replace("const PortId_t N_ACK_RETURN=9w48;", f"const PortId_t N_ACK_RETURN=9w{cp.N_ACK_RETURN};")
    n = n.replace("const PortId_t READ_HANDOFF_PORT=9w180;", f"const PortId_t READ_HANDOFF_PORT=9w{qs.PORTS['T_IN']};")
    n = n.replace("control Egress(inout headers_t hdr,inout meta_t m,in egress_intrinsic_metadata_t eg,"
                  "in egress_intrinsic_metadata_from_parser_t p,"
                  "inout egress_intrinsic_metadata_for_deparser_t md,"
                  "inout egress_intrinsic_metadata_for_output_port_t port){apply{}}", "")
    return source_text(n)


class ExperimentN(rs.ReadPipeline):
    def run_pass(self, number, port, raw):
        src = self.src
        src.begin_pass(port)
        src.env["ig.global_tstamp"] = self.time + (number - 1) * 1000
        accepted, cursor = src.packet_parser(raw)
        note = 'parser: states=%s accepted=%s cursor=%d' % ('>'.join(src.parser_states), accepted, cursor)
        events = [note]
        if src.parse_error:
            events.append('parser error: ' + src.parse_error)
            if self.on_parser_error == 'drop':
                return events, None, 'parser error: ' + src.parse_error
        if getattr(self, "poison_noncrc_guard_residue", False):
            src.env["m.hcrc"] = 0x1234
            src.env["m.bcrc"] = 0x5678
            src.env["m.crc1"] = 0x9ABC
            src.env["m.tcrc"] = 0xDEF0
        src.apply_control('Ingress')
        events += src.events
        events.append('m.parsed=%d m.stage=%d m.kind=%d egress=%d bypass=%d drop_ctl=%d' % (
            src.env.get('m.parsed', 0), src.env.get('m.stage', 0), src.env.get('m.kind', 0),
            src.env.get('tm.ucast_egress_port', 0), src.env.get('tm.bypass_egress', 0),
            src.env.get('md.drop_ctl', 0)))
        if src.invalid_reads:
            events.append('reads of invalid headers: ' + ', '.join(sorted(src.invalid_reads)))
        if src.env.get('md.drop_ctl', 0) & 1:
            return events, None, 'drop_ctl set by deny() (m.parsed=%d, stage=%d)' % (
                src.env.get('m.parsed', 0), src.env.get('m.stage', 0))
        out = src.deparse() + raw[cursor:]
        result = (events, (src.env.get('tm.ucast_egress_port', 0), out), None)
        if result[1] and result[1][0] == self.config.return_port:
            self.returns.append(result[1][1])
        return result


class DepartingT(qs.QueueSim):
    def ingress(self, time, port, raw):
        count = len(self.emitted)
        super().ingress(time, port, raw)
        for stamp, destination, emitted in self.emitted[count:]:
            self.owner.egress(stamp, destination, emitted)


class SourcePipeline:
    def __init__(self, poison_noncrc_guard_residue=False, **timing):
        self.now, self.wire, self.trace = qs.T0, [], []
        self.temp = tempfile.TemporaryDirectory()
        source = Path(self.temp.name) / "t.p4"
        source.write_text(make_t.generate())
        self.t = DepartingT(source=source, **timing)
        self.t.owner = self
        self.n = ExperimentN(text=n_text()).start(0, 0, 0, epoch=0)
        self.n.time = self.now
        self.n.returns = []
        self.n.poison_noncrc_guard_residue = poison_noncrc_guard_residue
        self.e = ESource(make_e.generate())
        self.master = cp.rp.Endpoint("10.0.0.1", vectors.CLIENT_PORT, 9)
        self.relay = cp.rp.Endpoint("10.0.0.2", vectors.SERVER_PORT, 64)
        for table in ("ports", "connection", "read_connection"):
            rs.drop_runtime(self.n, table)
        cp.install_ingress(self.n.src, cp.n_ports_rows(9, 64)
                           + cp.n_connection_rows(self.relay, self.master)
                           + cp.n_read_rows(self.relay, self.master))
        for table, key, action, data, priority in cp.e_conn_rows(0, self.relay, self.master):
            params = self.e.controls["Ingress"].actions[action.split(".", 1)[1]][0]
            values = dict(data)
            self.e.install(table.split(".", 1)[1], tuple(v for _, v in key),
                           action.split(".", 1)[1],
                           tuple(values[name] for name, _ in params), priority=priority)

    def close(self):
        self.temp.cleanup()

    def egress(self, time, destination, raw):
        if destination == qs.PORTS["T_IN"]:
            self.t.handoff(time, raw)
            return
        result = self.e.inject(destination, raw)
        self.trace.append(("E", time, destination, raw, result))
        if result is None:
            return
        if destination == cp.N_ACK_RETURN:
            self.ingress(time + 1000, destination, checksum_oracle(result))
        else:
            self.wire.append((time, destination, result))

    def ingress(self, time, port, frame):
        self.n.time = time
        out = self.n.inject(port, frame)
        self.trace.append(("N", time, port, frame, out))
        for destination, raw in out.emitted:
            self.egress(time + 1000 * out.passes, destination, raw)
        return out

    def send(self, frame, master=True, time=None):
        self.now = self.now + 50_000 if time is None else time
        out = self.ingress(self.now, 9 if master else 64, frame)
        self.t.run(self.now + 20_000)
        return out

    def handshake(self, client_isn=100, server_isn=900):
        self.send(vectors.packet(2, client_isn, mss=1460))
        self.send(vectors.packet(18, server_isn, client_isn + 1, reverse=True, mss=1460), master=False)
        self.send(vectors.packet(16, client_isn + 1, server_isn + 1))
        assert self.n.state()["owner"] >> 16 == 5, self.n.state()
        return self

    def run(self, until):
        self.t.run(until)
        self.now = until
        return self


class ResidueParity(unittest.TestCase):
    def fresh(self, **kw):
        s = SourcePipeline(**kw)
        self.addCleanup(s.close)
        return s.handshake()

    def corrupt(self, raw, index):
        frame = bytearray(raw)
        frame[index] ^= 1
        return bytes(frame)

    def assert_no_authority_change(self, s, before_n, before_e, before_t):
        self.assertEqual({k: s.n.state()[k] for k in before_n}, before_n)
        self.assertEqual(s.e.cells, before_e)
        self.assertEqual({k: copy.deepcopy(v) for k, v in s.t.src.cells.items()
                          if k[1] != "outcomes"}, before_t)


    def test_non_crc_control_paths_ignore_arbitrary_residue_metadata(self):
        s = SourcePipeline(poison_noncrc_guard_residue=True)
        self.addCleanup(s.close)
        syn = vectors.packet(2, 100, mss=1460)
        synack = vectors.packet(18, 900, 101, reverse=True, mss=1460)
        ack = vectors.packet(16, 101, 901)
        s.send(syn)
        self.assertEqual(s.wire[-1][2], syn)
        s.send(synack, master=False)
        self.assertEqual(s.wire[-1][2], synack)
        s.send(ack)
        self.assertEqual(s.wire[-1][2], ack)
        self.assertEqual(s.n.state()["owner"] >> 16, 5)

    def test_crc_corruption_rejected_for_each_profiled_block(self):
        cases = (
            (vectors.packet(24, 101, 901, payload=vectors.native_select(0, 3)), True, (62, 72, 88)),
            (vectors.packet(24, 901, 136, reverse=True,
                            payload=vectors.native_select(0, 3)), False, (62, 72, 84)),
        )
        for raw, master, offsets in cases:
            for offset in offsets:
                with self.subTest(offset=offset):
                    s = self.fresh()
                    before_n = {k: s.n.state()[k] for k in ("owner", "client", "server", "epoch")}
                    before_e = copy.deepcopy(s.e.cells)
                    before_t = {k: copy.deepcopy(v) for k, v in s.t.src.cells.items()
                                if k[1] != "outcomes"}
                    delivered = len(s.wire)
                    s.send(self.corrupt(raw, offset), master=master)
                    self.assertEqual(len(s.wire), delivered)
                    self.assert_no_authority_change(s, before_n, before_e, before_t)

    def test_wrong_read_link_addresses_with_correct_crc_rejected(self):
        s = self.fresh()
        read = bytearray(rs.request_packet(seq=101, ack=901))
        head, user = rs.case4_padding.decode_frame(read[54:])
        wrong = bytearray(head)
        wrong[4:8] = bytes.fromhex("02000b00")
        read[54:] = rs.case4_padding.build_frame(bytes(wrong), user)
        before_n = {k: s.n.state()[k] for k in ("owner", "client", "server", "epoch")}
        before_e = copy.deepcopy(s.e.cells)
        before_t = {k: copy.deepcopy(v) for k, v in s.t.src.cells.items() if k[1] != "outcomes"}
        delivered = len(s.wire)
        s.send(bytes(read))
        self.assertEqual(len(s.wire), delivered)
        self.assert_no_authority_change(s, before_n, before_e, before_t)

    def test_read_sbo_and_old_packets_still_match_baseline_invariants(self):
        s = self.fresh()
        s.send(rs.request_packet(seq=101, ack=901))
        self.assertEqual(s.n.state()["owner"] >> 16, 14)
        s.send(rs.ack_packet(seq=901, ack=121), master=False)
        s.send(rs.response_packet(seq=901, ack=121), master=False)
        s.run(s.now + 8_000_000)
        responses = [raw for _, port, raw in s.wire if port == 9 and raw[47] == 24]
        self.assertEqual(len(responses), 1)
        self.assertEqual(int.from_bytes(responses[0][16:18], "big"), 98)
        self.assertEqual(len(responses[0]), 112)
        s.send(vectors.packet(16, 121, 959))
        self.assertEqual(s.e.cells[("", "acct")][0]["hi"], 0)

        s.send(vectors.packet(20, 121, 950))
        s.handshake(4000, 7000)
        self.assertEqual(s.n.state()["owner"] >> 16, 5)


if __name__ == "__main__":
    unittest.main()

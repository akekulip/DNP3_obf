#!/usr/bin/env python3
"""test_analyzer_pairing.py — adversarial tests for the exact-pairing CLRT analyzer (directive §3).

The v1 analyzer paired the outstation's ACK to its RESPONSE by positional adjacency. That was
correct only because the captures happened to be clean. These tests build synthetic pcaps in which
adjacency gives the WRONG answer, and assert that the exact-pairing analyzer either pairs correctly
or refuses to pair at all. A test that the old analyzer would pass is not interesting; every case
here is one it would get wrong or silently mispair.

Run:  $RESEARCH_PYTHON test_analyzer_pairing.py
"""
import json
import os
import subprocess
import sys
import tempfile

from scapy.all import Ether, IP, TCP, Raw, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
ANALYZER = os.path.join(HERE, "analyze_live_clrt.py")
MASTER, OUTSTATION = "192.168.10.1", "192.168.10.7"
MAC_M, MAC_O = "02:00:00:00:00:11", "00:30:a7:02:4c:a2"
PORT_M, PORT_O = 40001, 20000

CRC_POLY = 0xA6BC          # CRC-16/DNP, reflected


def dnp3_crc(data: bytes) -> bytes:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ CRC_POLY if crc & 1 else crc >> 1
    crc ^= 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def dnp3_frame(dst_link, src_link, app_ctrl, func, body=b""):
    """Minimal DNP3 link frame: header block + one data block, both CRC'd."""
    data = bytes([0xC0, app_ctrl, func]) + body
    hdr = bytes([0x05, 0x64, 5 + len(data), 0xC4,
                 dst_link & 0xFF, (dst_link >> 8) & 0xFF,
                 src_link & 0xFF, (src_link >> 8) & 0xFF])
    return hdr + dnp3_crc(hdr) + data + dnp3_crc(data)


def read_frame(app_seq):
    return dnp3_frame(0, 1, 0xC0 | (app_seq & 0x0F), 1, bytes([0x1E, 0x03, 0x01]))


def resp_frame(app_seq, dst_link=1, src_link=0):
    return dnp3_frame(dst_link, src_link, 0xC0 | (app_seq & 0x0F), 129, b"\x00" * 20)


class Flow:
    """Tracks sequence numbers so synthetic captures are TCP-consistent."""

    def __init__(self, seq_m=1000, seq_o=5000, sport=PORT_M):
        self.seq_m, self.seq_o, self.sport = seq_m, seq_o, sport
        self.pkts = []
        self.t = 1_000_000.0

    def _emit(self, pkt, dt):
        self.t += dt
        pkt.time = self.t
        self.pkts.append(pkt)

    def read(self, app_seq, dt=0.0):
        p = read_frame(app_seq)
        pkt = (Ether(src=MAC_M, dst=MAC_O) / IP(src=MASTER, dst=OUTSTATION) /
               TCP(sport=self.sport, dport=PORT_O, flags="PA",
                   seq=self.seq_m, ack=self.seq_o) / Raw(p))
        self._emit(pkt, dt)
        self.seq_m += len(p)
        return self

    def ack(self, dt=0.001, ack_override=None, flags="A"):
        pkt = (Ether(src=MAC_O, dst=MAC_M) / IP(src=OUTSTATION, dst=MASTER) /
               TCP(sport=PORT_O, dport=self.sport, flags=flags,
                   seq=self.seq_o, ack=ack_override if ack_override else self.seq_m))
        self._emit(pkt, dt)
        return self

    def response(self, app_seq, dt=0.002, dst_link=1, src_link=0):
        p = resp_frame(app_seq, dst_link, src_link)
        pkt = (Ether(src=MAC_O, dst=MAC_M) / IP(src=OUTSTATION, dst=MASTER) /
               TCP(sport=PORT_O, dport=self.sport, flags="PA",
                   seq=self.seq_o, ack=self.seq_m) / Raw(p))
        self._emit(pkt, dt)
        self.seq_o += len(p)
        return self


def run_analyzer(pkts):
    d = tempfile.mkdtemp()
    pc = os.path.join(d, "t.pcap")
    wrpcap(pc, pkts)
    r = subprocess.run([sys.executable, ANALYZER, "--pcap", pc,
                        "--label", "native", "--outdir", d],
                       capture_output=True, text=True)
    js = os.path.join(d, "native_summary.json")
    summary = json.load(open(js)) if os.path.exists(js) else {}
    csv = os.path.join(d, "native_transactions.csv")
    rows = []
    if os.path.exists(csv):
        lines = open(csv).read().strip().splitlines()
        if len(lines) > 1:
            hdr = lines[0].split(",")
            rows = [dict(zip(hdr, l.split(","))) for l in lines[1:]]
    return summary, rows, r


def n_paired(rows):
    """Transactions with a usable CLRT, i.e. actually paired."""
    out = 0
    for r in rows:
        v = r.get("clrt_ms", "").strip()
        if v and v not in ("", "None"):
            try:
                float(v); out += 1
            except ValueError:
                pass
    return out


TESTS = []


def test(name, why):
    def deco(fn):
        TESTS.append((name, why, fn))
        return fn
    return deco


@test("T-baseline", "one clean transaction pairs and yields ~2 ms")
def t_base():
    f = Flow().read(0).ack(0.001).response(0, 0.002)
    _, rows, _ = run_analyzer(f.pkts)
    assert n_paired(rows) == 1, "expected exactly 1 paired transaction, got %d" % n_paired(rows)
    c = float(rows[0]["clrt_ms"])
    assert 1.5 < c < 2.5, "CLRT %.3f ms outside expected ~2 ms" % c
    return "1 txn, CLRT %.3f ms" % c


@test("T-dup-ack", "a duplicated qualifying ACK must not create a second transaction")
def t_dup():
    f = Flow().read(0).ack(0.001)
    f.ack(0.0005)                       # exact duplicate, same ack number
    f.response(0, 0.002)
    _, rows, _ = run_analyzer(f.pkts)
    assert n_paired(rows) == 1, "duplicate ACK produced %d transactions" % n_paired(rows)
    return "1 txn, the duplicate did not create a second"


@test("T-unrelated-ack", "an ACK with the wrong ack number must not qualify")
def t_unrelated():
    f = Flow().read(0)
    f.ack(0.001, ack_override=999999)   # wrong ack number: adjacency would take it
    f.ack(0.001)                        # the real one
    f.response(0, 0.002)
    _, rows, _ = run_analyzer(f.pkts)
    assert n_paired(rows) == 1, "got %d transactions" % n_paired(rows)
    c = float(rows[0]["clrt_ms"])
    assert 1.5 < c < 2.5, "paired against the WRONG ack (CLRT %.3f ms)" % c
    return "wrong-ack rejected, CLRT %.3f ms" % c


@test("T-fin-ack", "a FIN+ACK must never qualify as the pure ACK")
def t_fin():
    f = Flow().read(0)
    f.ack(0.001, flags="FA")            # FIN|ACK, correct ack number
    f.ack(0.001)
    f.response(0, 0.002)
    _, rows, _ = run_analyzer(f.pkts)
    assert n_paired(rows) == 1, "got %d transactions" % n_paired(rows)
    c = float(rows[0]["clrt_ms"])
    assert 1.5 < c < 2.5, "paired against the FIN/ACK (CLRT %.3f ms)" % c
    return "FIN/ACK rejected, CLRT %.3f ms" % c


@test("T-ack-before-read", "an ACK arriving before any READ must not arm a transaction")
def t_before():
    f = Flow()
    f.ack(0.001)                        # ACK with no preceding READ
    f.read(0, 0.001).ack(0.001).response(0, 0.002)
    _, rows, _ = run_analyzer(f.pkts)
    assert n_paired(rows) == 1, "pre-READ ACK created state: %d txns" % n_paired(rows)
    return "1 txn, the pre-READ ACK armed nothing"


@test("T-stale-response", "a second RESPONSE after completion must not re-pair")
def t_stale():
    f = Flow().read(0).ack(0.001).response(0, 0.002)
    f.response(0, 0.002)                # stale duplicate response
    _, rows, _ = run_analyzer(f.pkts)
    assert n_paired(rows) == 1, "stale RESPONSE produced %d transactions" % n_paired(rows)
    return "1 txn, the stale RESPONSE did not re-pair"


@test("T-wrong-app-seq", "a RESPONSE whose app sequence differs must be flagged, not silently used")
def t_appseq():
    f = Flow().read(3).ack(0.001).response(9, 0.002)   # READ seq 3, RESPONSE seq 9
    _, rows, proc = run_analyzer(f.pkts)
    # Guard against a vacuous pass: the analyzer must have RUN, not crashed.
    assert proc.returncode == 0, "analyzer exited %d: %s" % (proc.returncode, proc.stderr[-200:])
    if not rows:
        return "rejected outright (0 rows, analyzer exit 0)"
    rd = rows[0].get("read_dnp3_al_seq", "")
    rs = rows[0].get("resp_dnp3_al_seq", "")
    assert rd and rs, "analyzer emitted a row without both app-sequence fields (rd=%r rs=%r)" % (rd, rs)
    assert rd != rs, "mismatched app seq (3 vs 9) was normalised away: both read %r" % rd
    return "paired but mismatch visible: read_seq=%s resp_seq=%s" % (rd, rs)


@test("T-wrong-link-addr", "a RESPONSE from the wrong DNP3 link address must be visible")
def t_link():
    f = Flow().read(0).ack(0.001).response(0, 0.002, dst_link=1, src_link=77)
    _, rows, proc = run_analyzer(f.pkts)
    assert proc.returncode == 0, "analyzer exited %d: %s" % (proc.returncode, proc.stderr[-200:])
    if not rows:
        return "rejected outright (0 rows, analyzer exit 0)"
    assert "resp_dnp3_src" in rows[0], "analyzer emits no resp_dnp3_src, so a wrong link address is invisible"
    src = rows[0]["resp_dnp3_src"]
    assert src == "77", "wrong link address 77 was not recorded faithfully (resp_dnp3_src=%r)" % src
    return "paired but recorded resp_dnp3_src=%s (not the expected 0)" % src


@test("T-two-streams-seq", "two NON-overlapping streams must both pair, on distinct streams")
def t_streams_seq():
    a = Flow(seq_m=1000, seq_o=5000, sport=40001)
    a.read(0).ack(0.001).response(0, 0.002)
    b = Flow(seq_m=7000, seq_o=9000, sport=40002)
    b.t = a.t + 0.01
    b.read(0).ack(0.001).response(0, 0.002)
    pk = sorted(a.pkts + b.pkts, key=lambda p: p.time)
    _, rows, _ = run_analyzer(pk)
    assert n_paired(rows) == 2, "expected 2 paired transactions, got %d" % n_paired(rows)
    streams = {r.get("tcp_stream") for r in rows}
    assert len(streams) == 2, "both landed on one stream: %s" % streams
    return "2 txns on distinct streams %s" % sorted(streams)


@test("T-two-streams-interleaved",
      "with two streams IN FLIGHT AT ONCE the analyzer must never mispair; rejecting is acceptable")
def t_streams_inter():
    # KNOWN LIMITATION, asserted rather than hidden: when two transactions overlap in time on
    # different streams, this analyzer pairs only one and rejects the other with an explicit
    # validation_failure. That is the SAFE direction. The property under test is therefore
    # "never emits a wrong CLRT", not "pairs both". The live campaign is single-stream, so this
    # limitation does not affect it. Do not relax this into a pass-by-default.
    a = Flow(seq_m=1000, seq_o=5000, sport=40001)
    b = Flow(seq_m=7000, seq_o=9000, sport=40002)
    b.t += 0.0003
    a.read(0); b.read(0); a.ack(0.001); b.ack(0.001)
    b.response(0, 0.002); a.response(0, 0.002)   # B answers first: adjacency would cross-pair
    pk = sorted(a.pkts + b.pkts, key=lambda p: p.time)
    _, rows, _ = run_analyzer(pk)
    assert len(rows) == 2, "expected a row per READ (2), got %d" % len(rows)
    # every row that DID pair must carry a correct ~2 ms CLRT and matching stream on all three frames
    for r in rows:
        if r.get("clrt_ms", "").strip():
            c = float(r["clrt_ms"])
            assert 1.5 < c < 2.5, "MISPAIRED across streams: CLRT %.3f ms" % c
    # and every row that did NOT pair must say why
    unpaired = [r for r in rows if not r.get("clrt_ms", "").strip()]
    for r in unpaired:
        assert r.get("validation_failure", "").strip(), "silently dropped a transaction with no reason"
    return "%d paired correctly, %d rejected with an explicit reason (no mispairing)" % (
        n_paired(rows), len(unpaired))


def main():
    if not os.path.exists(ANALYZER):
        sys.exit("analyzer not found: %s" % ANALYZER)
    print("Adversarial pairing tests for %s\n" % os.path.basename(ANALYZER))
    npass = nfail = 0
    for name, why, fn in TESTS:
        try:
            detail = fn()
            print("  PASS  %-18s %s" % (name, detail))
            npass += 1
        except AssertionError as e:
            print("  FAIL  %-18s %s" % (name, e))
            print("        (%s)" % why)
            nfail += 1
        except Exception as e:
            print("  ERROR %-18s %s: %s" % (name, type(e).__name__, e))
            nfail += 1
    print("\n%d passed, %d failed" % (npass, nfail))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())

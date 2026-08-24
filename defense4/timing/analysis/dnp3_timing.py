"""DNP3 timing extraction from master-facing captures.

One place where the wire is turned into transactions. Everything downstream — CSVs,
statistics, figures, tests — reads from here, so there is a single definition of "a
transaction" and of CLRT.

Definitions
-----------
T_req   the master's DNP3 application request (function 1 READ, 3 SELECT, 4 OPERATE)
T_ack   the relay's first ACK-bearing packet after that request (TCP ACK flag set)
T_resp  the relay's DNP3 application response (function 0x81)
CLRT    T_resp - T_ack, in milliseconds — Formby's command-to-link response time
A       T_ack  - T_req, in milliseconds — master-visible ACK delay
R       T_resp - T_req, in milliseconds — master-visible echo delay

Timestamps are carried as integer nanoseconds end to end (see pcap_reader) and converted
to milliseconds only at the last step, so no interval is degraded by float64 epoch
arithmetic and the result does not depend on the installed scapy version.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from typing import Optional

from pcap_reader import decode_tcp, iter_frames

MASTER = "192.168.10.1"
RELAY = "192.168.10.7"
DNP3_PORT = 20000

FUNC_READ, FUNC_SELECT, FUNC_OPERATE = 1, 3, 4
FUNC_RESPONSE = 0x81
REQUEST_FUNCS = (FUNC_READ, FUNC_SELECT, FUNC_OPERATE)
FUNC_NAME = {FUNC_READ: "READ", FUNC_SELECT: "SELECT", FUNC_OPERATE: "OPERATE"}

TCP_SYN, TCP_ACK = 0x02, 0x10

NS_PER_MS = 1_000_000


class TimingDataError(Exception):
    pass


@dataclass
class Packet:
    t_ns: int
    from_master: bool
    payload: bytes
    flags: int

    @property
    def dnp3_func(self) -> Optional[int]:
        """DNP3 application function code, or None if this is not a DNP3 application frame.

        A DNP3 link frame starts with the 0x0564 start octets; byte 12 is the application
        function code once the 10-byte link header and the transport octet are passed.
        """
        p = self.payload
        if len(p) >= 13 and p[0] == 0x05 and p[1] == 0x64:
            return p[12]
        return None


@dataclass
class Transaction:
    txn: int
    req_func: int
    t_req_ns: int
    t_ack_ns: Optional[int]
    t_resp_ns: Optional[int]
    req_len: int
    cold: int

    def _ms(self, a, b):
        return None if (a is None or b is None) else (b - a) / NS_PER_MS

    @property
    def clrt_ms(self):
        return self._ms(self.t_ack_ns, self.t_resp_ns)

    @property
    def ack_ms(self):
        return self._ms(self.t_req_ns, self.t_ack_ns)

    @property
    def resp_ms(self):
        return self._ms(self.t_req_ns, self.t_resp_ns)


def read_packets(pcap_path):
    """Return the master<->relay TCP packets of a capture, in capture order."""
    out = []
    last_ns = None
    for t_ns, frame in iter_frames(pcap_path):
        if last_ns is not None and t_ns < last_ns:
            raise TimingDataError(
                "non-monotonic capture timestamp in %s (%d < %d)" % (pcap_path, t_ns, last_ns))
        last_ns = t_ns
        d = decode_tcp(frame)
        if d is None:
            continue
        if d["src"] not in (MASTER, RELAY) or d["dst"] not in (MASTER, RELAY):
            continue
        out.append(Packet(t_ns=t_ns, from_master=(d["src"] == MASTER),
                          payload=d["payload"], flags=d["flags"]))
    return out


def extract_transactions(pcap_path):
    """Pair every DNP3 request in a capture with the relay's ACK and its response.

    A request whose ACK or response is missing is still returned, with the missing field
    set to None, so nothing is dropped without being counted. Callers decide what to
    exclude and report the exclusions.
    """
    pkts = read_packets(pcap_path)
    txns = []
    connection_is_new = True
    n = 0
    for i, pk in enumerate(pkts):
        if pk.from_master and (pk.flags & TCP_SYN):
            connection_is_new = True
        if not pk.from_master:
            continue
        func = pk.dnp3_func
        if func not in REQUEST_FUNCS:
            continue
        t_ack = t_resp = None
        for nxt in pkts[i + 1:]:
            if nxt.from_master:
                if nxt.dnp3_func in REQUEST_FUNCS:
                    break                     # the next request begins; this one is over
                continue
            if (nxt.flags & TCP_ACK) and t_ack is None:
                t_ack = nxt.t_ns
            if nxt.dnp3_func == FUNC_RESPONSE and t_resp is None:
                t_resp = nxt.t_ns
                break
        n += 1
        txns.append(Transaction(txn=n, req_func=func, t_req_ns=pk.t_ns, t_ack_ns=t_ack,
                                t_resp_ns=t_resp, req_len=len(pk.payload),
                                cold=1 if connection_is_new else 0))
        connection_is_new = False
    return txns


TXN_CSV_COLUMNS = ["class", "mode", "txn", "req_func", "t_req", "t_ack", "t_resp",
                   "clrt_ms", "req_len", "cold"]


def write_txn_csv(txns, path, cls, mode):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(TXN_CSV_COLUMNS)
        for t in txns:
            clrt = t.clrt_ms
            w.writerow([cls, mode, t.txn, t.req_func, "%.9f" % (t.t_req_ns / 1e9),
                        "" if t.t_ack_ns is None else "%.9f" % (t.t_ack_ns / 1e9),
                        "" if t.t_resp_ns is None else "%.9f" % (t.t_resp_ns / 1e9),
                        "" if clrt is None else "%.3f" % clrt,
                        t.req_len, t.cold])


def read_txn_rows(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def read_txn_csv(path, req_func=None, drop_cold=True):
    """CLRT values (ms) from a transaction CSV.

    drop_cold removes the first transaction of each TCP connection: the relay's first
    response after a connect is dominated by session setup inside the device and is not a
    steady-state measurement.
    """
    out = []
    for r in read_txn_rows(path):
        if req_func is not None and int(r["req_func"]) != req_func:
            continue
        if drop_cold and r["cold"].strip() not in ("0", ""):
            continue
        if not r["clrt_ms"].strip():
            continue
        out.append(float(r["clrt_ms"]))
    return out


SBO_CSV_COLUMNS = ["Jpolicy", "txn", "A_ms", "R_ms", "echo_ack_ms"]


def extract_operate_timing(pcap_path):
    """OPERATE transactions only: (A, R, echo-ACK) in ms, all master-visible."""
    rows = []
    for t in extract_transactions(pcap_path):
        if t.req_func != FUNC_OPERATE:
            continue
        if t.t_ack_ns is None or t.t_resp_ns is None:
            continue
        rows.append((t.ack_ms, t.resp_ms, t.clrt_ms))
    return rows


def write_sbo_csv(rows, path, label):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(SBO_CSV_COLUMNS)
        for k, (a, r, d) in enumerate(rows):
            w.writerow([label, k, "%.3f" % a, "%.3f" % r, "%.3f" % d])


def read_sbo_csv(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    return {"A": [float(r["A_ms"]) for r in rows],
            "R": [float(r["R_ms"]) for r in rows],
            "echo": [float(r["echo_ack_ms"]) for r in rows]}

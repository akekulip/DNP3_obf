"""Does this DNP3 outstation acknowledge SEPARATELY from its response, or piggyback?

The Case A / Case B distinction (research/.../CASE_A_TERMINOLOGY.md) is a property of the
device's TCP stack, not of DNP3:

  Case A (SEPARATE ACK)  READ -> pure TCP ACK (tcp.len == 0) -> RESPONSE.
                         The ACK->RESPONSE interval is the CLRT, and it is the leak the
                         Defense 3 work conceals.
  Case B (COMBINED ACK)  READ -> RESPONSE, whose TCP header carries the acknowledgement.
                         No pure ACK, so no CLRT to observe.

This script decides which, for ONE device, from a wire capture of real Class 0 integrity
polls. It is READ-ONLY: it sends nothing but Class 0 reads (group 60 variation 1,
qualifier 0x06) and issues no control command of any kind.

Method (the parsing is the proven logic of defense3/harness/block.py, which produced the
D-sweep campaign rows):
  - dumpcap is started FIRST and verified to have started; a block with no capture is
    invalid rather than silently empty;
  - rows are bound to THIS connection's 4-tuple, so another session or an idle-socket
    keepalive cannot be counted;
  - per transaction: t_read (our 18-byte READ), t_ack (first pure ACK from the relay
    before any response) and t_resp (first response segment);
  - a transaction is SEPARATE if a pure ACK arrived strictly before the response,
    COMBINED if the response arrived with no pure ACK before it.

The verdict is reported per transaction and aggregated, with the disagreement count
visible, because a stack can legitimately do both (delayed-ACK behaviour depends on how
fast the application answers).

Usage (on the master host, on the relay's subnet):
    python3 probe_ack_mode.py --relay 192.168.10.8 --dest 100 --n 20
    python3 probe_ack_mode.py --self-test        # frame builder vs known-good frames
"""
import argparse
import binascii
import json
import os
import re
import socket
import subprocess
import sys
import time

# ---- CRC-16/DNP, IEEE 1815 (reflected 0x3D65, init 0, final xor 0xFFFF) --------------
def dnp3_crc16(data):
    crc = 0x0000
    for b in bytearray(data):
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def _blk(data):
    """A DNP3 block: the data followed by its little-endian CRC."""
    return data + dnp3_crc16(data).to_bytes(2, "little")


def class0_read(dest, src, app_seq):
    """One Class 0 integrity poll: group 60 var 1, qualifier 0x06 (all points).

    18 bytes on the wire, the same length as the SEL-751 frames the campaign used, so a
    parser keyed on the READ length behaves identically across devices.
    """
    link = _blk(bytes([0x05, 0x64, 0x0B, 0xC4]) +
                int(dest).to_bytes(2, "little") + int(src).to_bytes(2, "little"))
    transport = bytes([0xC0])                      # FIR+FIN, sequence 0
    app = bytes([0xC0 | (app_seq & 0x0F),          # FIR+FIN + application sequence
                 0x01,                             # function 1 = READ
                 0x3C, 0x01, 0x06])                # group 60 var 1, qualifier 06
    return link + _blk(transport + app)


# The 16 frames defense3/harness/block.py sends to the SEL-751 (outstation 0, master 1).
# The builder above must reproduce them EXACTLY or it is not building a valid frame.
KNOWN_GOOD_SEL751 = [
    "05640bc4000001002aecc0c0013c0106ff50", "05640bc4000001002aecc0c1013c0106f973",
    "05640bc4000001002aecc0c2013c0106f316", "05640bc4000001002aecc0c3013c0106f535",
    "05640bc4000001002aecc0c4013c0106e7dc", "05640bc4000001002aecc0c5013c0106e1ff",
    "05640bc4000001002aecc0c6013c0106eb9a", "05640bc4000001002aecc0c7013c0106edb9",
    "05640bc4000001002aecc0c8013c0106b605", "05640bc4000001002aecc0c9013c0106b026",
    "05640bc4000001002aecc0ca013c0106ba43", "05640bc4000001002aecc0cb013c0106bc60",
    "05640bc4000001002aecc0cc013c0106ae89", "05640bc4000001002aecc0cd013c0106a8aa",
    "05640bc4000001002aecc0ce013c0106a2cf", "05640bc4000001002aecc0cf013c0106a4ec",
]


def self_test():
    ok = True
    for i, expect in enumerate(KNOWN_GOOD_SEL751):
        got = binascii.hexlify(class0_read(0, 1, i)).decode()
        if got != expect:
            print("MISMATCH seq %d: built %s want %s" % (i, got, expect))
            ok = False
    print("frame builder vs 16 known-good SEL-751 frames: %s"
          % ("PASS (byte-identical)" if ok else "FAIL"))
    if ok:
        print("example, outstation 100: %s"
              % binascii.hexlify(class0_read(100, 1, 0)).decode())
    return 0 if ok else 1


def run(a):
    res = {"relay": a.relay, "dest": a.dest, "src": a.src, "n_requested": a.n,
           "attempted": 0, "sent": 0, "responded": 0, "errors": [], "capture_ok": False}
    pc = os.path.expanduser("~/ackmode_%s.pcap" % a.relay.replace(".", "_"))
    if os.path.exists(pc):
        os.remove(pc)

    dc = subprocess.Popen(["dumpcap", "-i", a.iface, "-f", "host %s" % a.relay,
                           "-w", pc, "-q"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(40):
        time.sleep(0.1)
        if dc.poll() is not None:
            err = (dc.stderr.read() or b"").decode(errors="replace")[:300]
            res["errors"].append("dumpcap exited early: %s" % err)
            break
        if os.path.exists(pc):
            res["capture_ok"] = True
            break
    if not res["capture_ok"]:
        res["errors"].append("dumpcap did not start on %s" % a.iface)
        print("ACKMODE " + json.dumps(res))
        return 2
    time.sleep(1.0)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        if a.master:
            s.bind((a.master, 0))
        s.connect((a.relay, a.port))
        res["local_port"] = s.getsockname()[1]
        time.sleep(0.6)
        for i in range(a.n):
            res["attempted"] += 1
            try:
                frame = class0_read(a.dest, a.src, i)
                if a.split_read:
                    # Deliver the SAME 18 bytes as two TCP segments. RFC 1122 §4.2.3.2
                    # requires a receiver to acknowledge at least every second segment, so
                    # a stack that would otherwise wait for its delayed-ACK timer (and
                    # therefore piggyback on the response) is obliged to ACK at once.
                    # The DNP3 bytes are unchanged: this is a segmentation change only.
                    cut = a.split_at
                    s.sendall(frame[:cut])
                    time.sleep(a.split_gap)
                    s.sendall(frame[cut:])
                else:
                    s.sendall(frame)
                res["sent"] += 1
                s.settimeout(a.timeout)
                got = s.recv(4096)
                if got:
                    res["responded"] += 1
                    res.setdefault("first_response_hex",
                                   binascii.hexlify(got[:24]).decode())
                else:
                    res["errors"].append("poll %d: peer closed" % i)
                    break
            except socket.timeout:
                res["errors"].append("poll %d: no response within %.1fs"
                                     % (i, a.timeout))
            except Exception as e:                              # noqa: BLE001
                res["errors"].append("poll %d: %r" % (i, e))
                break
            time.sleep(a.gap)
    except Exception as e:                                      # noqa: BLE001
        res["errors"].append("setup: %r" % (e,))
    finally:
        try:
            s.close()
        except Exception:                                       # noqa: BLE001
            pass

    time.sleep(1.0)
    dc.terminate()
    try:
        dc.wait(timeout=5)
    except Exception:                                           # noqa: BLE001
        dc.kill()

    rows = parse(pc, a, res.get("local_port"))
    res["rows"] = rows
    sep = [r for r in rows if r["mode"] == "SEPARATE"]
    comb = [r for r in rows if r["mode"] == "COMBINED"]
    res["n_separate"], res["n_combined"] = len(sep), len(comb)
    if rows:
        res["verdict"] = ("SEPARATE_ACK (Case A)" if len(sep) == len(rows) else
                          "COMBINED_ACK (Case B)" if len(comb) == len(rows) else
                          "MIXED — %d separate / %d combined" % (len(sep), len(comb)))
    else:
        res["verdict"] = "NO TRANSACTIONS OBSERVED"
    if sep:
        cl = sorted(r["clrt_ms"] for r in sep if r["clrt_ms"] is not None)
        if cl:
            res["clrt_ms"] = {"n": len(cl), "min": round(cl[0], 3),
                              "median": round(cl[len(cl) // 2], 3),
                              "max": round(cl[-1], 3)}
    rr = sorted(r["read_to_resp_ms"] for r in rows if r["read_to_resp_ms"] is not None)
    if rr:
        res["read_to_resp_ms"] = {"n": len(rr), "min": round(rr[0], 3),
                                  "median": round(rr[len(rr) // 2], 3),
                                  "max": round(rr[-1], 3)}
    res["pcap"] = pc
    print("ACKMODE " + json.dumps(res))
    return 0


def parse(pc, a, local_port):
    """Per-transaction rows, bound to our 4-tuple (defense3/harness/block.py logic)."""
    txt = subprocess.run(["tcpdump", "-r", pc, "-nn", "-tt", "-S"],
                         capture_output=True, text=True).stdout.splitlines()
    rx = re.compile(r"^(\d+\.\d+) IP (\S+?)\.(\d+) > (\S+?)\.(\d+): Flags \[([^\]]*)\],"
                    r".*?length (\d+)")
    ev = []
    for ln in txt:
        m = rx.match(ln)
        if not m:
            continue
        t, sip, sp, dip, dp, fl, n = m.groups()
        sp, dp, n = int(sp), int(dp), int(n)
        from_relay = (sip == a.relay and sp == a.port)
        from_master = (dip == a.relay and dp == a.port)
        if local_port is not None:
            if from_master and sp != local_port:
                continue
            if from_relay and dp != local_port:
                continue
        if not (from_relay or from_master):
            continue
        ev.append({"t": float(t), "from_relay": from_relay, "flags": fl, "len": n})

    # A transaction opens on the first master DATA segment after the previous one has
    # been answered. A further master segment while a transaction is still unanswered is
    # a CONTINUATION of the same request (this is what --split-read produces), not a new
    # transaction — so the same parser serves both the one-segment and two-segment cases.
    rows, cur = [], None
    for e in ev:
        if (not e["from_relay"]) and e["len"] > 0:
            if cur is None or cur["t_resp"] is not None:
                if cur:
                    rows.append(cur)
                cur = {"t_read": e["t"], "t_read_last": e["t"], "read_bytes": e["len"],
                       "t_ack": None, "t_resp": None, "resp_len": None, "read_segs": 1}
            else:
                cur["t_read_last"] = e["t"]
                cur["read_bytes"] += e["len"]
                cur["read_segs"] += 1
        elif cur and e["from_relay"] and e["len"] == 0 and e["flags"] in (".", "P."):
            if cur["t_ack"] is None and cur["t_resp"] is None:
                cur["t_ack"] = e["t"]
        elif cur and e["from_relay"] and e["len"] > 0:
            if cur["t_resp"] is None:
                cur["t_resp"] = e["t"]
                cur["resp_len"] = e["len"]
    if cur:
        rows.append(cur)

    out = []
    for r in rows:
        if r["t_resp"] is None:
            r["mode"] = "NO_RESPONSE"
        elif r["t_ack"] is not None and r["t_ack"] < r["t_resp"]:
            r["mode"] = "SEPARATE"
        else:
            r["mode"] = "COMBINED"
        # timings are measured from the LAST byte of the request, which is the instant the
        # outstation actually has a complete frame to act on (identical to t_read when the
        # request is a single segment)
        r["read_to_ack_ms"] = (None if r["t_ack"] is None
                               else round((r["t_ack"] - r["t_read_last"]) * 1e3, 3))
        r["clrt_ms"] = (None if (r["t_ack"] is None or r["t_resp"] is None)
                        else round((r["t_resp"] - r["t_ack"]) * 1e3, 3))
        r["read_to_resp_ms"] = (None if r["t_resp"] is None
                                else round((r["t_resp"] - r["t_read_last"]) * 1e3, 3))
        for k in ("t_read", "t_read_last", "t_ack", "t_resp"):
            r.pop(k)
        out.append(r)
    return out


def scan(a):
    """Find the outstation's link address: send one Class 0 read per candidate on a
    single connection and report which candidates answer.

    Read-only and gentle: one 18-byte read per candidate. 0xFFFC is the IEEE 1815
    self-address, which a device that supports it answers regardless of its configured
    address, revealing that address in the response's SOURCE field.
    """
    cands = ([int(x, 0) for x in a.scan.split(",")] if a.scan != "auto" else
             [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 32, 50, 100, 101, 102,
              200, 254, 255, 1000, 1024, 0xFFFC])
    found = []
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(6)
    try:
        if a.master:
            s.bind((a.master, 0))
        s.connect((a.relay, a.port))
    except Exception as e:                                      # noqa: BLE001
        print("SCAN connect failed: %r" % (e,))
        return 2
    for c in cands:
        try:
            s.sendall(class0_read(c, a.src, 0))
            s.settimeout(a.scan_wait)
            got = s.recv(4096)
        except socket.timeout:
            got = b""
        except Exception as e:                                  # noqa: BLE001
            print("SCAN dest=%d: connection error %r — reconnecting" % (c, e))
            try:
                s.close()
            except Exception:                                   # noqa: BLE001
                pass
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(6)
            try:
                if a.master:
                    s.bind((a.master, 0))
                s.connect((a.relay, a.port))
            except Exception:                                   # noqa: BLE001
                break
            continue
        if got:
            src_addr = None
            if len(got) >= 8 and got[0] == 0x05 and got[1] == 0x64:
                src_addr = int.from_bytes(got[6:8], "little")   # link SOURCE = the device
            found.append({"dest_tried": c, "resp_src_addr": src_addr,
                          "hex": binascii.hexlify(got[:20]).decode()})
            print("SCAN dest=%-6d ANSWERED  device link address = %s  %s"
                  % (c, src_addr, binascii.hexlify(got[:20]).decode()))
    try:
        s.close()
    except Exception:                                           # noqa: BLE001
        pass
    print("SCAN " + json.dumps({"relay": a.relay, "src": a.src,
                                "candidates": len(cands), "found": found}))
    return 0 if found else 1


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--relay", help="outstation IP")
    p.add_argument("--master", default="192.168.10.1", help="source IP to bind")
    p.add_argument("--dest", type=int, default=0, help="outstation DNP3 link address")
    p.add_argument("--src", type=int, default=1, help="master DNP3 link address")
    p.add_argument("--port", type=int, default=20000)
    p.add_argument("--n", type=int, default=20, help="Class 0 polls")
    p.add_argument("--gap", type=float, default=0.5, help="seconds between polls")
    p.add_argument("--timeout", type=float, default=4.0)
    p.add_argument("--iface", default="enp59s0f0np0")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--scan", nargs="?", const="auto", default=None,
                   help="discover the outstation link address: 'auto' for the built-in "
                        "candidate list (incl. the 0xFFFC self-address), or a "
                        "comma-separated list")
    p.add_argument("--scan-wait", type=float, default=0.8,
                   help="seconds to wait for an answer per candidate")
    p.add_argument("--split-read", action="store_true",
                   help="send each READ as TWO TCP segments (same bytes) to test whether "
                        "a combined-ACK device can be forced into separate-ACK behaviour")
    p.add_argument("--split-at", type=int, default=9,
                   help="byte offset of the segment boundary (default 9 of 18)")
    p.add_argument("--split-gap", type=float, default=0.002,
                   help="seconds between the two segments")
    a = p.parse_args()
    if a.self_test:
        return self_test()
    if not a.relay:
        p.error("--relay is required (or use --self-test)")
    if a.scan:
        return scan(a)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
